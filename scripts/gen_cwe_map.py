# scripts/gen_cwe_map.py
"""从本机 cppcheck 的 errorlist 生成 {检查id: CWE} 全量映射，存成 JSON。"""
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

# 用脚本自身位置锚定项目根：无论从哪个目录启动，输出都落在 <项目根>/data/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = PROJECT_ROOT / "data" / "cppcheck_id_to_cwe.json"

# 注意：不加 text=True，让 stdout 保持 bytes。
# errorlist 的 XML 带 encoding 声明，ET.fromstring 收到 str 会报
# "Unicode strings with encoding declaration are not supported"
out = subprocess.run(["cppcheck", "--errorlist"],
                     capture_output=True, check=True).stdout
root = ET.fromstring(out)

mapping = {}
for e in root.iter("error"):
    cwe = e.get("cwe")
    if cwe:
        mapping[e.get("id")] = f"CWE-{cwe}"

OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with OUT_PATH.open("w", encoding="utf-8") as f:
    json.dump(mapping, f, ensure_ascii=False, indent=2)

print(f"共 {len(mapping)} 条带 CWE 的检查项，已写入 {OUT_PATH}")