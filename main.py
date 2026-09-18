# main.py
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from openai import AsyncOpenAI
import uvicorn
import re

# 导入工具模块
from tools import scan_c_code, compile_c_code
app = FastAPI(title="基于大语言模型的C代码漏洞自动修复系统")

# 配置本地的大模型客户端 (指向4用 vLLM 启动的 8001 端口)
#" OpenAI SDK 不关心对面是不是 OpenAI，它只负责按 OpenAI 协议格式发 HTTP 请求。vLLM 启动时暴露了一个协议兼容层（/v1/chat/completions、/v1/models），所以 SDK 能直接指过去。api_key 随便填是因为 OpenAI SDK 客户端要求非空字符串，而 vLLM 默认不校验 key（除非启动时加 --api-key）。"
client = AsyncOpenAI(
    base_url="http://localhost:8001/v1",
    api_key="sk-no-key-needed" # 本地调用不需要真实的 API Key
)

# 定义前端传过来的数据结构
#这 2 行是前后端契约。Pydantic 在运行时强制执行它：body 缺失或 code 不是字符串 → 自动返回 422（detail 是错误对象数组）
# 定义前端传过来的数据结构
class RepairRequest(BaseModel):
    code: str

# ===== 新增：定义后端返回给前端的数据结构 =====
class ScanResult(BaseModel): 
    #BaseModel 是什么： Pydantic 提供的基类。一个类只要继承它，类体内写的每一行 字段名: 类型 就不再是摆设，而是被 Pydantic 解析成带运行时校能力的数据字段。它会在背后干三件事：
    # 校验——实例化时检查每个字段的类型对不对；
    # 生成 JSON Schema——FastAPI 拿它去画 /docs 里的文档；
    # 序列化/反序列化——JSON 字符串 ↔ Python 对象自动互转。
    line: int
    error_type: str
    message: str

class CompileResult(BaseModel):
    success: bool
    error_msg: str = ""

class RepairResponse(BaseModel):
    status: str
    repaired_code: str
    scan_results: list[ScanResult]
    compile_result: CompileResult


#mount 把整个 static 目录挂到 /static 前缀下；访问 / 时 307 重定向过去。
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

# 核心：真实的漏洞修复接口
@app.post("/api/repair", response_model=RepairResponse)
async def repair_code(req: RepairRequest):
    try:
                # 步骤 A：静态扫描 (获取 CWE 编号，本周先提取，下周利用它去 RAG 检索)
        vulns = await scan_c_code(req.code)
        print("Detected Vulnerabilities:", vulns) # 打印在后端控制台方便调试

        system_prompt = """你是一个顶级的 C 语言安全专家。
请修复用户提供的 C 代码中的安全漏洞。
要求：
1. 确保修复后的代码没有缓冲区溢出、指针越界等内存安全问题。
2. 保持原有的业务逻辑不变。
3. 你的回答中必须且只能包含完整的修复后的 C 代码，请将其放在 ```c 和 ``` 之间，不要解释。"""

        # 步骤B：调用本地大模型修复
        response = await client.chat.completions.create(
            model="Qwen/Qwen2.5-Coder-7B-Instruct",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": req.code}
            ],
            temperature=0.1, # temperature 越低采样越接近贪心解码，输出越确定——代码修复要的是可复现，不是创意
            max_tokens=2048  #是生成长度上限：超出就截断，截断的代码没有闭合围栏 

            #截断会导致正则提取失败或提出残缺代码 → GCC 报一堆不相干的错。目前代码短所以没触发，需要知道 response.choices[0].finish_reason 这个字段的存在（"stop"=自然结束，"length"=被截断）
        )
        
        raw_output = response.choices[0].message.content
        
        # 步骤C 提取代码 (模型习惯在外面包一层 markdown 标签，我们需要去掉它)
        fixed_code = raw_output
        code_match = re.search(r"```[cC]?\n(.*?)```", raw_output, re.DOTALL)
        #这里可能会导致问题，后边需要注意（.*?）捕获组，？表示非贪婪，如果正文出现反引号会提前截断

        if code_match:
            fixed_code = code_match.group(1).strip()

                # 步骤 C：编译器验证 (验证 LLM 修复的代码是否会报语法错误)
        compile_result = await compile_c_code(fixed_code)
        print("Compile Result:", compile_result) # 打印在后端控制台

        # 步骤 D：将所有结构化信息返回给前端
        return {
            "status": "success", 
            "repaired_code": fixed_code,
            "scan_results": vulns,               # 新增：漏洞扫描结果
            "compile_result": compile_result     # 新增：编译结果
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)