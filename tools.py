# tools.py
import asyncio
import tempfile
import os

async def scan_c_code(code: str) -> list:#scan_c_code 和 compile_c_code 都必须加上 async 关键字，变成协程函数.可以改同步为异步
    """
    使用 Cppcheck 扫描 C 代码，提取 CWE 编号和报错行号
    """
    # 1. 将代码写入临时文件
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
        #—默认 delete=True 时，with 块结束文件关闭的瞬间就被删了，后面的 subprocess 就读不到文件了。所以必须关掉自动删除，最后在 finally 里手动删。
        #suffix=".c"？——cppcheck 靠扩展名判断语言。没有 .c 后缀，它可能按 C++ 规则解析，结果会变。
        f.write(code.encode('utf-8'))
        temp_filename = f.name
        
    vulnerabilities = []
    try:
        # 2. 调用 cppcheck。
        # 使用 --template 自定义输出格式，方便我们用 Python 结构化解析
        # 输出格式： 行号|CWE编号|错误信息
        cmd = [
            'cppcheck', 
            '--enable=warning,style,performance,portability', # 扫描级别
            '--inconclusive', #--inconclusive：把“分析器不确定但可能有问题的”也报出来。代价是误报变多
            '--template={line}|{cwe}|{message}',#关键点：默认输出是人类可读的句子，要用正则硬抠；自定义 template 让 cppcheck 直接输出准结构化的 行号|CWE|信息，Python 只需 split。
            temp_filename
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,                                    # 把 cmd 列表拆成一个一个参数传入
            stdout=asyncio.subprocess.PIPE,          # 等价于原来的 capture_output=True
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate() # 异步等待进程结束，同时读两个管道防死锁

        # communicate() 返回的是 bytes，必须解码，后面的 split('\n') 才能工作
        output = stderr.decode('utf-8')
        
        # 3. 解析输出并结构化为 JSON (Dict) 列表
        for line in output.split('\n'):
            parts = line.split('|')
            if len(parts) == 3:
                line_num, cwe_id, msg = parts
                if cwe_id != '0': # 过滤掉没有特定 CWE 的普通警告
                    vulnerabilities.append({
                        "line": int(line_num) if line_num.isdigit() else 0,
                        "error_type": f"CWE-{cwe_id}",
                        "message": msg.strip()
                    })
    except Exception as e:
        print(f"扫描工具执行异常: {e}")
    finally:
        # 4. 清理临时文件
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
            
    return vulnerabilities


async def compile_c_code(code: str) -> dict:
    """
    使用 GCC 编译 C 代码，捕获编译报错
    只查“合法的 C 代码”。丢掉了一个信号——代码里调用了根本不存在的函数（如 foo() 从未定义）时，-c 下能通过（链接才查这个），完整编译会报 undefined reference
    """
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
        f.write(code.encode('utf-8'))
        temp_filename = f.name
        
    output_filename = temp_filename + ".o"
    process = None          # 新增：预先声明，防止 create_subprocess_exec 本身异常时超时分支报 NameError
    try:
        # 调用 GCC 编译，只编译不运行 (-c 或者编译为可执行文件)
        process = await asyncio.create_subprocess_exec(
            'gcc', '-c', temp_filename, '-o', output_filename, '-Wall', '-Wextra',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        # create_subprocess_exec 不支持 timeout 参数，用 wait_for 包装实现超时
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)

        if process.returncode == 0:
            return {"success": True, "error_msg": ""}
        else:
            return {"success": False, "error_msg": stderr.decode('utf-8').strip()}

    except asyncio.TimeoutError:
        # 超时后 gcc 还活着，必须手动杀掉并回收，否则堆积僵尸进程
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        return {"success": False, "error_msg": "GCC Compile Timeout."}
    except Exception as e:
        return {"success": False, "error_msg": str(e)}
    finally:
        # 清理临时文件
        if os.path.exists(temp_filename): os.remove(temp_filename)
        if os.path.exists(output_filename): os.remove(output_filename)