# scripts/build_kb_from_juliet.py
"""从 Juliet C 测试集构建知识库：<漏洞函数, 修复函数, CWE> 数据对。
结构自适应：兼容 bad/good 分文件与单文件两种布局，sXX 子目录可有可无。
用法：python scripts/build_kb_from_juliet.py
产出：data/juliet_cases.json（rag.py 自动加载）"""
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

PROJECT_ROOT = Path(__file__).resolve().parent.parent
JULIET_TESTCASES = Path.home() / "juliet" / "testcases"   # ★ 指向含 CWE###_ 目录的那一层
OUT_PATH = PROJECT_ROOT / "data" / "juliet_cases.json"

CANON = {
    "CWE121": "CWE-119", "CWE122": "CWE-119", "CWE124": "CWE-119",
    "CWE129": "CWE-119", "CWE785": "CWE-119", "CWE787": "CWE-119", "CWE788": "CWE-119",
    "CWE126": "CWE-125", "CWE127": "CWE-125", "CWE786": "CWE-125",
    "CWE476": "CWE-476", "CWE369": "CWE-369",
    "CWE415": "CWE-415", "CWE416": "CWE-416", "CWE401": "CWE-401",
}

FAMILY_GUIDANCE = {
    "CWE-119": "修复前检查缓冲区大小与索引边界，改用带长度限制的安全 API 并补终止符。",
    "CWE-125": "读取数组前同时校验指针有效性与索引上界。",
    "CWE-476": "解引用前对可能为空的指针做 NULL 检查。",
    "CWE-369": "除法或取模前校验除数不为零。",
    "CWE-415": "确保每块内存只释放一次，释放后将指针置空。",
    "CWE-416": "释放后不再使用指针，必要时重新分配。",
    "CWE-401": "所有分配路径都要有对应释放，失败分支同样要清理。",
}

MAX_ENTRY_LINES = 60    # 入口函数行数上限
MAX_TOTAL_LINES = 120   # 拼上辅助函数后的总量上限
PER_FAMILY_CAP = 20     # 每个 CWE 家族最多入库条数

_LANG = Language(tsc.language())
try:
    PARSER = Parser(_LANG)
except TypeError:
    PARSER = Parser()
    PARSER.language = _LANG


def iter_functions(node):
    if node.type == "function_definition":
        yield node
    for child in node.children:
        yield from iter_functions(child)


def func_name(node):
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


def parse_file(path: Path):
    code = path.read_text(encoding="utf-8", errors="replace")
    tree = PARSER.parse(code.encode("utf-8"))
    return [(func_name(f), f.text.decode("utf-8", errors="replace"))
            for f in iter_functions(tree.root_node)]


def expand_with_helpers(entry_name: str, entry_text: str, fns) -> str:
    """沿调用关系把同文件被引用的辅助函数拼进来（最多两层），few-shot 例子才完整。"""
    parts, seen = [entry_text], {entry_name}
    frontier = [entry_text]
    for _ in range(2):
        nxt = []
        for text in frontier:
            for name, src in fns:
                if name and name not in seen and re.search(rf"\b{re.escape(name)}\b", text):
                    parts.append(src)
                    seen.add(name)
                    nxt.append(src)
        frontier = nxt
    return "\n\n".join(parts)


def is_bad_entry(n: str) -> bool:
    return n == "bad" or n.endswith("_bad")


def bad_stem(n: str) -> str:
    return n[: -len("_bad")] if n.endswith("_bad") else n


def pick_good(fns, stem: str):
    """优先 goodB2G（坏数据+安全处理=真正的修复语义），其次官方 ..._good 包装。
    排除 goodG2B（喂好数据走坏流程，不是修复）。"""
    for n, s in fns:
        if n.endswith("goodB2G"):
            return n, s
    for n, s in fns:
        if n == f"{stem}_good" or n == "good":
            return n, s
    return None, None


def find_good(fns, stem: str, registry):
    """先在当前文件找 good；找不到再到 registry 找同名包装函数所在的其他文件"""
    g_name, g_src = pick_good(fns, stem)
    if g_src is not None:
        return g_name, g_src, fns
    other = registry.get(f"{stem}_good")
    if other is not None:
        g_name, g_src = pick_good(other, stem)
        if g_src is not None:
            return g_name, g_src, other
    return None, None, None


def main():
    if not JULIET_TESTCASES.exists():
        sys.exit(f"路径不存在: {JULIET_TESTCASES}")

    # 阶段A：解析白名单家族下全部 .c（rglob 兼容任意层级），登记函数名索引
    parsed, registry = [], {}
    for cwe_dir in sorted(p for p in JULIET_TESTCASES.iterdir() if p.is_dir()):
        m = re.match(r"CWE(\d+)_", cwe_dir.name)
        if not m:
            continue
        canon = CANON.get(f"CWE{m.group(1)}")
        if canon is None:
            continue
        for path in sorted(cwe_dir.rglob("*.c")):
            try:
                fns = parse_file(path)
            except Exception:
                continue
            parsed.append((canon, path, fns))
            for n, _ in fns:
                registry.setdefault(n, fns)

    # 阶段B：按函数名配对 bad ↔ good
    out, family_count = [], Counter()
    skipped, dup, seen_keys = Counter(), 0, set()

    for canon, path, fns in parsed:
        for bad_name, bad_src in fns:
            if not is_bad_entry(bad_name):
                continue
            stem = bad_stem(bad_name)
            g_name, g_src, g_fns = find_good(fns, stem, registry)
            if g_src is None:
                skipped["无good对应"] += 1
                continue
            if len(bad_src.splitlines()) > MAX_ENTRY_LINES:
                skipped["超长"] += 1
                continue

            bad_code = expand_with_helpers(bad_name, bad_src, fns)
            good_code = expand_with_helpers(g_name, g_src, g_fns)
            if (bad_code == good_code
                    or len(bad_code.splitlines()) > MAX_TOTAL_LINES
                    or len(good_code.splitlines()) > MAX_TOTAL_LINES):
                skipped["内容不合格"] += 1
                continue

            norm = re.sub(r"\s+", " ", bad_src)
            key = hashlib.sha1(f"{canon}|{norm}".encode()).hexdigest()
            if key in seen_keys:
                dup += 1
                continue
            if family_count[canon] >= PER_FAMILY_CAP:
                skipped["家族满额"] += 1
                continue
            seen_keys.add(key)
            family_count[canon] += 1

            out.append({
                "id": "juliet-" + key[:8],
                "cwe": canon,
                "title": f"{path.stem}（{canon}）",
                "vulnerable_code": bad_code,
                "fixed_code": good_code,
                "guidance": FAMILY_GUIDANCE.get(canon, ""),
                "root_cause": "",        # 预留，12 月填
                "fix_strategy": "",
                "negative_example": "",
                "source": str(path.relative_to(JULIET_TESTCASES)),
            })

    OUT_PATH.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"入库 {len(out)} 条 → {OUT_PATH}")
    print("各家族数量:", dict(family_count))
    print("去重丢弃:", dup, " 跳过原因:", dict(skipped))
    if not out:
        print("提示：白名单家族解析到 0 对——把上面①②诊断输出贴出来，布局和函数名一对就清楚了")


if __name__ == "__main__":
    main()