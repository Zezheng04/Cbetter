// static/js/main.js

const { createApp, ref, onMounted, nextTick } = Vue;

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
                const reader = new FileReader();
                reader.onload = (e) => {
                    if (originalEditorInstance) {
                        originalEditorInstance.setValue(e.target.result);
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
                    body: JSON.stringify({ code: currentCode })
                });

                const data = await response.json();

                if (response.ok && data.status === 'success') {
                    currentStep.value = 4; // 进入验证阶段

                    setTimeout(() => {
                        currentStep.value = 5; // 最终完成
                        isRepairing.value = false;
                        ElementPlus.ElMessage.success('模型修复完成！');

                        const originalModel = monaco.editor.createModel(currentCode, 'c');
                        // 🌟 注意这里：使用大模型真实返回的 data.repaired_code 替换了之前的假数据
                        const modifiedModel = monaco.editor.createModel(data.repaired_code, 'c');

                        diffEditorInstance.setModel({
                            original: originalModel,
                            modified: modifiedModel
                        });
                        showDiff.value = true;

                        // 🌟 完全保留你自己写好的、完美的强制刷新布局代码
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
                    throw new Error(data.detail || "请求失败");
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