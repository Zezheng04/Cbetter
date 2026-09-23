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
            '--enable=warning', # 扫描级别
            '--std=c11',          # 固定解析标准，不同机器/版本结果一致
            '--template={line}|{cwe}|{severity}|{id}|{message}',#关键点：默认输出是人类可读的句子，要用正则硬抠；自定义 template 让 cppcheck 直接输出准结构化的 行号|CWE|信息，Python 只需 split。
            temp_filename
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,                                    # 把 cmd 列表拆成一个一个参数传入
            stdout=asyncio.subprocess.PIPE,          # 等价于原来的 capture_output=True
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        except asyncio.TimeoutError:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            print("扫描超时，已终止")
            return []   # finally 仍会执行，临时文件照常清理

        # communicate() 返回的是 bytes，必须解码，后面的 split('\n') 才能工作
        output = (stdout + b"\n" + stderr).decode('utf-8', errors='replace')
        
        # 3. 解析输出并结构化为 JSON (Dict) 列表
        seen = set()
        for line in output.split('\n'):
            parts = line.split('|', 4)          # maxsplit 保住 message 里可能出现的 |
            if len(parts) != 5:                 # 进度行/日志行长度不对，自然过滤
                continue
            line_num, cwe_id, severity, check_id, msg = parts
            if not cwe_id.strip().isdigit() or int(cwe_id) == 0:
                continue                        # 无 CWE 的检查输出空串或 0，全部跳过
            key = (line_num, cwe_id, check_id, msg.strip())
            if key in seen:                     # 同一位置常被两个检查各报一次，去重
                continue
            seen.add(key)
            vulnerabilities.append({
                "line": int(line_num) if line_num.isdigit() else 0,
                "error_type": f"CWE-{int(cwe_id)}",
                "severity": severity,
                "cppcheck_id": check_id,
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
        if os.path.exists(output_filename): os.remove(output_filename)# ===== 第 4 周新增：Tree-sitter 锚点切片 =====
try:
    import tree_sitter_c as _tsc
    from tree_sitter import Language as _TSLang, Parser as _TSParser

    _C_LANG = _TSLang(_tsc.language())

    def _make_parser():
        try:
            return _TSParser(_C_LANG)      # tree-sitter >= 0.24
        except TypeError:
            p = _TSParser()                 # 0.22 / 0.23
            try:
                p.language = _C_LANG
            except Exception:
                p.set_language(_C_LANG)     # <= 0.21
            return p

    _PARSER = _make_parser()
    _TS_OK = True
except Exception as _e:
    _TS_OK = False
    print(f"[tools] tree-sitter 不可用，检索退化为全文匹配: {_e}")


def _iter_functions(node):
    if node.type == "function_definition":
        yield node
    for child in node.children:
        yield from _iter_functions(child)


def _function_name(node):
    decl = node.child_by_field_name("declarator")
    if decl is None:
        return ""
    stack = [decl]
    while stack:
        n = stack.pop()
        if n.type == "identifier":
            return n.text.decode("utf-8", errors="replace")
        stack.extend(n.children)
    return ""


def extract_function_at(code: str, line: int):
    """返回包含 line 行（1-based）的整个函数源码；找不到返回 None"""
    if not _TS_OK or line <= 0:
        return None
    try:
        tree = _PARSER.parse(code.encode("utf-8"))
        target = line - 1
        for fn in _iter_functions(tree.root_node):
            # start_point[0] 是 0 起始的行号，用下标兼容新旧版本的 Point 类型
            if fn.start_point[0] <= target <= fn.end_point[0]:
                return fn.text.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[tools] 切片失败: {e}")
    return None