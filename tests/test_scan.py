# tests/test_scan.py —— 扫描器已知答案回归
# 用法：任意目录下 python tests/test_scan.py 均可
import asyncio
import sys
from pathlib import Path

# 运行子目录里的脚本时，Python 的模块搜索路径是脚本所在目录（tests/），
# 不含项目根，`from tools import ...` 会失败——手动把项目根加进去
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import scan_c_code

# 用 __file__ 锚定夹具路径，和启动目录解耦（与 gen_cwe_map.py 同一招）
SMOKE_PATH = Path(__file__).with_name("smoke.c")


async def main():
    code = SMOKE_PATH.read_text(encoding="utf-8")
    findings = await scan_c_code(code)
    for f in findings:
        print(f)

    types = {f["error_type"] for f in findings}
    for expect in ["CWE-476", "CWE-369", "CWE-788", "CWE-415"]:
        assert expect in types, f"{expect} 未检出！"
    print("smoke 扫描 OK:", sorted(types))

    # 反向：干净代码必须 0 告警（噪声过滤生效的证据）
    clean = await scan_c_code("int add(int a, int b) {\n    return a + b;\n}\n")
    assert clean == [], f"干净代码出了 {len(clean)} 条告警：{clean}"
    print("干净代码 0 告警 OK")


if __name__ == "__main__":
    asyncio.run(main())