基于大语言模型的 C 代码漏洞自动修复系统
上传 C 代码 → Cppcheck 静态扫描提取 CWE → 知识库检索同类修复案例（RAG）→ 本地大模型生成修复 → GCC 编译验证，前端 Diff 对比展示。

系统架构
前端(Monaco Editor) → FastAPI(main.py) → 扫描(tools.py, Cppcheck)→ 检索(rag.py, CWE硬过滤+BM25) → LLM(vLLM, Qwen2.5-Coder-7B-Instruct, 端口8001)→ 编译验证(GCC) → 前端 Diff

快速开始
~/start_vllm.sh启动大模型

依赖
Python 3.10+；fastapi / openai / rank_bm25 / tree-sitter / tree-sitter-c外部工具：Cppcheck 2.21.0、GCC（含 -Wall -Wextra）

静态扫描环境
Cppcheck 2.21.0
命令：cppcheck --enable=warning --std=c11
--template='{line}|{cwe}|{severity}|{id}|{message}'
error 级默认开启，--enable=warning 追加 warning 级；style/performance/portability 判定为噪声，不参与修复与指标统计
知识库（第 4 周）
数据源：Juliet C/C++ Test Suite v1.3（NIST SARD #112，sha256 校验通过）
构建：python scripts/build_kb_from_juliet.py（CWE 子类目录→父类归并；函数级 bad↔goodB2G 配对；辅助函数展开；去重；每族≤20）
规模：148 条（手写 8 + Juliet 140），家族分布：{CWE-119: 20, CWE-125: 20, ...}
字段：id/cwe/title/vulnerable_code/fixed_code/guidance
预留 root_cause/fix_strategy/negative_example + source
辅助产物：data/cppcheck_id_to_cwe.json（本机 errorlist 导出的 296 条 id→CWE 映射）
回归测试
python tests/test_scan.py（4 类已知漏洞检出 + 干净代码零告警；每次改动扫描逻辑后必跑）

周志
W1 前端交互 | W2 后端+LLM 联调 | W3 工具链集成 | W4 RAG 检索 + 知识库 ← 当前