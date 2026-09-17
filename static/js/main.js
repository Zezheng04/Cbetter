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
        const startRepair = () => {
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

            // Mock 状态机流转 (通过定时器模拟后端处理时长)
            const stepsTiming = [
                { step: 1, time: 1000 }, // 静态扫描中...
                { step: 2, time: 2500 }, // 语义分析中...
                { step: 3, time: 4500 }, // LLM修复中...
                { step: 4, time: 6000 }, // GCC验证中...
                { step: 5, time: 7000 }  // 完成
            ];

            stepsTiming.forEach(s => {
                setTimeout(() => {
                    currentStep.value = s.step;
                    
if (s.step === 5) { // 最终完成
                        isRepairing.value = false;
                        ElementPlus.ElMessage.success('智能修复与验证完成！');

                        const originalModel = monaco.editor.createModel(currentCode, 'c');
                        const modifiedModel = monaco.editor.createModel(mockRepairedCode, 'c');

                        diffEditorInstance.setModel({
                            original: originalModel,
                            modified: modifiedModel
                        });
                        showDiff.value = true;

                        // 等待显示状态和 flex 布局完成后，强制 Monaco 重新计算尺寸
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
                    }
                }, s.time);
            });
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