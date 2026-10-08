// static/js/main.js

const { createApp, ref, onMounted, nextTick } = Vue;
//是 Vue 的全局构建版：index.html 里 <script> 引 CDN，Vue 挂在 window 上，没有 npm、没有构建步骤、没有模块打包。优点是零工程配置，缺点是无法拆组件、无法 tree-shaking。这是 CDN 全局模式，不是 Vite 工程化

// Mock 假数据（模拟一个经典的缓冲区溢出漏洞及修复）
const mockVulnerableCode = `#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    // CWE-119: 缓冲区溢出，直接使用 strcpy 没有检查边界
    strcpy(buffer, input); 
    printf("Buffer contains: %s\\n", buffer);
}

int main() {
    char *large_input = "This_is_a_very_long_string_that_will_overflow";
    vulnerable_function(large_input);
    return 0;
}`;

const mockRepairedCode = `#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    // 【修复】使用 strncpy 限制拷贝长度，并确保最后一位是安全结束符
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0'; 
    printf("Buffer contains: %s\\n", buffer);
}

int main() {
    char *large_input = "This_is_a_very_long_string_that_will_overflow";
    vulnerable_function(large_input);
    return 0;
}`;

// Monaco Editor 全局实例
let originalEditorInstance = null;
let diffEditorInstance = null;
let diffOriginalModel = null;    // 新增：Diff 左侧模型（只建一次）
let diffModifiedModel = null;    // 新增：Diff 右侧模型（只建一次）
let iterationStatusTimer = null;

const app = createApp({
    setup() {
        const isRepairing = ref(false);
        const showSteps = ref(false);
        const showDiff = ref(false);
        const currentStep = ref(0);
        const openPanels = ref(['iterations']);
        const summary = ref({}); // ★ 第 5 周新增：保存结构化语义摘要
                // ★ 第 6 周新增：迭代修复过程数据
        const iterations = ref([]);
        const totalRounds = ref(1);
        const finalStatus = ref('');   // success / scan_failed / compile_failed
        const activeIteration = ref(1);
        const activePhase = ref('准备生成修复方案');
        const activeStatus = ref('正在准备第 1 轮错误驱动修复…');
        const iterationProgress = ref(0);

        const workflowPhases = [
            { step: 2, name: '生成修复方案', status: '大模型正在结合扫描结果与错误记忆生成代码…' },
            { step: 3, name: 'GCC 编译', status: '正在检查语法、类型和编译错误…' },
            { step: 3, name: 'Cppcheck 复扫', status: '正在确认高危漏洞是否已经消除…' },
            { step: 3, name: '功能差分', status: '正在确认修复没有改变原有业务行为…' }
        ];

        const updateIterationStatus = (phaseIndex, round = activeIteration.value) => {
            const phase = workflowPhases[phaseIndex % workflowPhases.length];
            activeIteration.value = round;
            activePhase.value = phase.name;
            activeStatus.value = phase.status;
            currentStep.value = phase.step;
            iterationProgress.value = Math.round(((phaseIndex % workflowPhases.length) / workflowPhases.length) * 100);
        };

        const startIterationStatus = () => {
            let phaseIndex = 0;
            let round = 1;
            updateIterationStatus(phaseIndex, round);
            iterationStatusTimer = setInterval(() => {
                phaseIndex += 1;
                if (phaseIndex % workflowPhases.length === 0) {
                    round += 1;
                }
                updateIterationStatus(phaseIndex, Math.min(round, 3));
            }, 1800);
        };

        const stopIterationStatus = () => {
            if (iterationStatusTimer) {
                clearInterval(iterationStatusTimer);
                iterationStatusTimer = null;
            }
        };

        const layoutDiffEditor = () => {
            nextTick(() => {
                requestAnimationFrame(() => {
                    if (!diffEditorInstance) return;
                    const editorElement = document.getElementById('diffEditor');
                    if (editorElement && editorElement.clientWidth && editorElement.clientHeight) {
                        diffEditorInstance.layout({
                            width: editorElement.clientWidth,
                            height: editorElement.clientHeight
                        });
                    }
                });
            });
        };

        const handlePanelChange = () => {
            layoutDiffEditor();
            setTimeout(layoutDiffEditor, 300);
        };

        // 触发文件上传框
        const triggerUpload = () => {
            document.getElementById('fileInput').click();
        };

        // 处理文件读取
        const handleFileUpload = (event) => {
            const file = event.target.files[0];
            if (file) {
                // 新增检查 1：扩展名白名单（拦住选错文件）
                if (!/\.(c|h)$/i.test(file.name)) {
                    ElementPlus.ElMessage.warning('请上传 .c 源码文件（当前选中的是：' + file.name + '）');
                    event.target.value = '';
                    return;
                }

                const reader = new FileReader();
                reader.onload = (e) => {
                    const content = e.target.result;

                    // 新增检查 2：空文件
                    if (!content.trim()) {
                        ElementPlus.ElMessage.warning('文件内容为空！');
                        event.target.value = '';
                        return;
                    }

                    // 新增检查 3：二进制嗅探（借鉴 Git 的经典启发式：文本里不该出现 NUL 字节）
                    if (content.includes('\0')) {
                        ElementPlus.ElMessage.warning('检测到二进制内容，这不是文本形式的 C 源码');
                        event.target.value = '';
                        return;
                    }

                    if (originalEditorInstance) {
                        originalEditorInstance.setValue(content);
                    }
                };
                reader.readAsText(file);
            }
        };

        // 初始化 Monaco Editor
        const initMonaco = () => {
            require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.36.1/min/vs' } });
            require(['vs/editor/editor.main'], function () {
                
                // 1. 初始化左侧原始代码编辑器
                originalEditorInstance = monaco.editor.create(document.getElementById('originalEditor'), {
                    value: mockVulnerableCode,
                    language: 'c',
                    theme: 'vs-light',
                    automaticLayout: true,
                    minimap: { enabled: false }
                });

                // 2. 初始化右侧 Diff 代码对比编辑器
                diffEditorInstance = monaco.editor.createDiffEditor(document.getElementById('diffEditor'), {
                    enableSplitViewResizing: false,
                    renderSideBySide: true, // 并排对比
                    theme: 'vs-light',
                    automaticLayout: true,
                    readOnly: true
                });
                // 模型只在这里创建一次；以后每次修复只更新内容，不再新建
                diffOriginalModel = monaco.editor.createModel('', 'c');
                diffModifiedModel = monaco.editor.createModel('', 'c');
                diffEditorInstance.setModel({ original: diffOriginalModel, modified: diffModifiedModel });
            });
        };

        // 模拟智能修复工作流
        const startRepair = async () => {
            // 获取当前左侧编辑器中的代码
            const currentCode = originalEditorInstance.getValue();
            if (!currentCode.trim()) {
                ElementPlus.ElMessage.warning('请输入或上传 C 代码！');
                return;
            }

            // 重置 UI 状态
            isRepairing.value = true;
            showSteps.value = true;
            showDiff.value = false;
            currentStep.value = 0;
            summary.value = {}; // 重置摘要状态
            // ★ 第 6 周新增：重置迭代数据
            iterations.value = [];
            totalRounds.value = 1;
            finalStatus.value = '';
            activeIteration.value = 1;
            activePhase.value = '准备生成修复方案';
            activeStatus.value = '正在准备第 1 轮错误驱动修复…';
            iterationProgress.value = 0;
            stopIterationStatus();

            // ====== 真实的智能修复工作流 ======
            try {
                // 1. UI 表现：模拟快速跳过前置步骤，进入大模型修复状态
                currentStep.value = 1;
                setTimeout(() => { currentStep.value = 2; }, 500);
                startIterationStatus();

                // 2. 发起真实网络请求，调用后端大模型接口
                const response = await fetch('/api/repair', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: currentCode }),
                });

                const data = await response.json();

                if (response.ok && data.status === 'success') {
                    // 新增：打印工具链提取到的结构化数据
                    console.log("【第3周成果】安全扫描提取的CWE漏洞：", data.scan_results);
                    console.log("【第4周成果】RAG检索到的修复案例：", data.rag_cases);
                    console.log("【第3周成果】GCC编译验证状态：", data.compile_result);
                    console.log("【第5周成果】结构化语义摘要：", data.summary);
                                        // ★ 第 6 周新增：保存迭代修复日志
                    console.log("【第6周成果】迭代修复日志：", data.iterations);
                    iterations.value = data.iterations || [];
                    totalRounds.value = data.total_rounds || 1;
                    finalStatus.value = data.final_status || 'success';
                    stopIterationStatus();
                    const lastIteration = iterations.value[iterations.value.length - 1];
                    if (lastIteration) {
                        activeIteration.value = lastIteration.round;
                        activePhase.value = lastIteration.stage;
                        activeStatus.value = lastIteration.log;
                        iterationProgress.value = 100;
                    }

                    // ★ 第 5 周新增：保存结构化摘要供模板渲染
                    summary.value = data.summary || {};

                    if (data.rag_cases && data.rag_cases.length > 0) {
                        ElementPlus.ElMessage.success(
                            `已检索 ${data.rag_cases.length} 个同类漏洞修复案例（${data.rag_cases.map(item => item.cwe).join('、')}）`
                        );
                    } else {
                        ElementPlus.ElMessage.info('知识库暂无匹配案例，模型将依据扫描结果完成修复。');
                    }
                    
                    // ★ 第 6 周改造：按最终状态给三态反馈
                    if (finalStatus.value === 'success' && totalRounds.value > 1) {
                        ElementPlus.ElMessage.success(
                            `修复成功！工具链反馈驱动，共迭代 ${totalRounds.value} 轮后通过编译与安全扫描`
                        );
                    } else if (finalStatus.value === 'scan_failed') {
                        ElementPlus.ElNotification({
                            title: '安全扫描未完全通过',
                            message: `已迭代 ${totalRounds.value} 轮，返回编译通过的最优版本，但重扫仍存在高危漏洞，详见下方迭代日志。`,
                            type: 'warning',
                            duration: 0
                        });
                    } else if (finalStatus.value === 'compile_failed') {
                        ElementPlus.ElNotification({
                            title: 'GCC 编译警告',
                            message: `已迭代 ${totalRounds.value} 轮仍未编译通过，返回最后一轮结果，报错详见控制台。`,
                            type: 'warning',
                            duration: 0
                        });
                        console.error("GCC编译错误日志：", data.compile_result.error_msg);
                    }

                    currentStep.value = 3; // 进入第四个主步骤：GCC 验证

                    setTimeout(() => {
                        currentStep.value = 5; // 超过最后一步索引，使第五步也显示为完成态
                        isRepairing.value = false;
                        if (finalStatus.value === 'success' && totalRounds.value === 1) {
                            ElementPlus.ElMessage.success('模型修复完成！（1 轮通过编译与安全扫描）');
                        }

                        diffOriginalModel.setValue(currentCode);
                        diffModifiedModel.setValue(data.repaired_code);
                        showDiff.value = true;

                        // 保留强制刷新布局代码
                        //Diff 容器初始 showDiff=false（隐藏/零尺寸）→ 等到展示时容器突然有了尺寸 → automaticLayout 的 ResizeObserver 触发时机偶尔滞后一拍 → 编辑器以 0 高度渲染或错位。解法就是在容器可见后手动调 layout() 强制重算，并用 requestAnimationFrame 等浏览器完成一轮布局后再量尺寸、再补一帧（双保险）。
                        layoutDiffEditor();
                        setTimeout(layoutDiffEditor, 300);
                    }, 500); // 稍微延迟展示，让用户看清“GCC验证”那一步
                } else {
                     const msg = typeof data.detail === 'string'
                        ? data.detail
                        : (data.detail?.[0]?.msg || JSON.stringify(data.detail));
                    throw new Error(msg);
                }
            } catch (error) {
                stopIterationStatus();
                isRepairing.value = false;
                ElementPlus.ElMessage.error('修复失败: ' + error.message);
            }
        };

        onMounted(() => {
            initMonaco();
        });

        return {
            isRepairing, showSteps, showDiff, currentStep, summary,
            iterations, totalRounds, finalStatus,   // ★ 第 6 周新增
            activeIteration, activePhase, activeStatus, iterationProgress, openPanels,
            handlePanelChange,
            triggerUpload, handleFileUpload, startRepair
        };
    }
});

app.use(ElementPlus);
app.mount('#app');