# main.py 目前主要功能是启动一个 Web 服务器，提供静态前端页面，并预留了一个模拟的大模型修复接口。
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles #用于处理静态文件（如 HTML、CSS、JS、图片等）
from fastapi.responses import RedirectResponse #导入 RedirectResponse 类，用于实现页面的 HTTP 重定向。
import uvicorn #Uvicorn 是一个高性能的 ASGI 服务器，用于运行 FastAPI 应用。

app = FastAPI(title="基于大语言模型的C代码漏洞自动修复系统")

# 将 static 目录挂载为静态文件服务
app.mount("/static", StaticFiles(directory="static"), name="static") #将项目左侧目录树中的 static 文件夹挂载到 Web 根路径的 /static 下。这意味着浏览器可以通过 http://localhost:8000/static/... 直接访问 static 目录里的前端文件

# 访问根目录时，自动跳转到前端 index.html
@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

# 提供一个 Mock 接口（预留给第2周使用）
@app.post("/api/mock_repair")
async def mock_repair(data: dict):
    return {"status": "success", "message": "这是预留给大模型修复的后端接口"}

if __name__ == "__main__":
    # 在 0.0.0.0 运行，确保你在本地通过 VS Code 端口转发可以访问
    uvicorn.run(app, host="0.0.0.0", port=8000) #表示监听所有可用的网络接口（允许外部访问），port=8000 表示监听 8000 端口