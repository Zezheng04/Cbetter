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
client = AsyncOpenAI(
    base_url="http://localhost:8001/v1",
    api_key="sk-no-key-needed" # 本地调用不需要真实的 API Key
)

# 定义前端传过来的数据结构
class RepairRequest(BaseModel):
    code: str

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

# 核心：真实的漏洞修复接口
@app.post("/api/repair")
async def repair_code(req: RepairRequest):
    try:
                # 步骤 A：静态扫描 (获取 CWE 编号，本周先提取，下周利用它去 RAG 检索)
        vulns = scan_c_code(req.code)
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
            temperature=0.1, # 修复代码需要严谨，温度调低
            max_tokens=2048
        )
        
        raw_output = response.choices[0].message.content
        
        # 3. 提取代码 (模型习惯在外面包一层 markdown 标签，我们需要去掉它)
        fixed_code = raw_output
        code_match = re.search(r"```[cC]?\n(.*?)```", raw_output, re.DOTALL)
        if code_match:
            fixed_code = code_match.group(1).strip()

                # 步骤 C：编译器验证 (验证 LLM 修复的代码是否会报语法错误)
        compile_result = compile_c_code(fixed_code)
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