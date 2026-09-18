# tools.py
import subprocess
import tempfile
import os

def scan_c_code(code: str) -> list:
    """
    使用 Cppcheck 扫描 C 代码，提取 CWE 编号和报错行号
    """
    # 1. 将代码写入临时文件
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
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
            '--inconclusive', 
            '--template={line}|{cwe}|{message}',
            temp_filename
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        # cppcheck 的输出通常在 stderr 中
        output = result.stderr
        
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


def compile_c_code(code: str) -> dict:
    """
    使用 GCC 编译 C 代码，捕获编译报错
    """
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
        f.write(code.encode('utf-8'))
        temp_filename = f.name
        
    output_filename = temp_filename + ".out"
    
    try:
        # 调用 GCC 编译，只编译不运行 (-c 或者编译为可执行文件)
        # 这里尝试编译为可执行文件来检查所有链接和语法错误
        result = subprocess.run(
            ['gcc', temp_filename, '-o', output_filename],
            capture_output=True,
            text=True,
            timeout=5 # 设置超时，防止死锁
        )
        
        if result.returncode == 0:
            return {"success": True, "error_msg": ""}
        else:
            # 提取编译器的标准错误输出
            return {"success": False, "error_msg": result.stderr.strip()}
            
    except subprocess.TimeoutExpired:
        return {"success": False, "error_msg": "GCC Compile Timeout."}
    except Exception as e:
        return {"success": False, "error_msg": str(e)}
    finally:
        # 清理临时文件
        if os.path.exists(temp_filename): os.remove(temp_filename)
        if os.path.exists(output_filename): os.remove(output_filename)