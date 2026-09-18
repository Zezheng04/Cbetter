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

const app = createApp({
    setup() {
        const isRepairing = ref(false);
        const showSteps = ref(false);
        const showDiff = ref(false);
        const currentStep = ref(0);

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
            require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.36.1/min/vs' } });
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

// ====== 真实的智能修复工作流 ======
            try {
                // 1. UI 表现：模拟快速跳过前置步骤，进入大模型修复状态
                currentStep.value = 1;
                setTimeout(() => { currentStep.value = 2; }, 500);
                setTimeout(() => { currentStep.value = 3; }, 1000);

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
                    console.log("【第3周成果】GCC编译验证状态：", data.compile_result);
                    
                    // 如果大模型生成的代码编译失败，给用户一个提示框
                    if (!data.compile_result.success) {
                         ElementPlus.ElNotification({
                            title: 'GCC 编译警告',
                            message: '模型修复的代码存在编译错误，详见控制台。',
                            type: 'warning',
                            duration: 0 // 不自动关闭
                         });
                         console.error("GCC编译错误日志：", data.compile_result.error_msg);
                    }

                    currentStep.value = 4; // 进入验证阶段

                    setTimeout(() => {
                        currentStep.value = 5; // 最终完成
                        isRepairing.value = false;
                        ElementPlus.ElMessage.success('模型修复完成！');

                        diffOriginalModel.setValue(currentCode);
                        diffModifiedModel.setValue(data.repaired_code);
                        showDiff.value = true;

                        // 保留强制刷新布局代码
                        //Diff 容器初始 showDiff=false（隐藏/零尺寸）→ 等到展示时容器突然有了尺寸 → automaticLayout 的 ResizeObserver 触发时机偶尔滞后一拍 → 编辑器以 0 高度渲染或错位。解法就是在容器可见后手动调 layout() 强制重算，并用 requestAnimationFrame 等浏览器完成一轮布局后再量尺寸、再补一帧（双保险）。
                        nextTick(() => {
                            requestAnimationFrame(() => {
                                if (diffEditorInstance) {
                                    const editorElement = document.getElementById('diffEditor');
                                    const layoutEditor = () => {
                                        diffEditorInstance.layout({
                                            width: editorElement.clientWidth,
                                            height: editorElement.clientHeight
                                        });
                                    };

                                    layoutEditor();
                                    requestAnimationFrame(layoutEditor);
                                }
                            });
                        });
                    }, 500); // 稍微延迟展示，让用户看清“GCC验证”那一步
                } else {
                     const msg = typeof data.detail === 'string'
                        ? data.detail
                        : (data.detail?.[0]?.msg || JSON.stringify(data.detail));
                    throw new Error(msg);
                }
            } catch (error) {
                isRepairing.value = false;
                ElementPlus.ElMessage.error('修复失败: ' + error.message);
            }
        };

        onMounted(() => {
            initMonaco();
        });

        return {
            isRepairing, showSteps, showDiff, currentStep,
            triggerUpload, handleFileUpload, startRepair
        };
    }
});

app.use(ElementPlus);
app.mount('#app');