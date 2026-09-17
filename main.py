# main.py
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from openai import AsyncOpenAI
import uvicorn
import re

app = FastAPI(title="基于大语言模型的C代码漏洞自动修复系统")

# 配置本地的大模型客户端 (指向刚才用 vLLM 启动的 8001 端口)
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
        # 1. 构建 Prompt (第 4 周我们还会在这里加入 RAG 检索)
        system_prompt = """你是一个顶级的 C 语言安全专家。
请修复用户提供的 C 代码中的安全漏洞。
要求：
1. 确保修复后的代码没有缓冲区溢出、指针越界等内存安全问题。
2. 保持原有的业务逻辑不变。
3. 你的回答中必须且只能包含完整的修复后的 C 代码，请将其放在 ```c 和 ``` 之间，不要解释。"""

        # 2. 调用本地大模型
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
            
        return {"status": "success", "repaired_code": fixed_code}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)