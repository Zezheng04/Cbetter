# rag.py —— 第 4 周升级版：CWE 父子归并 + 两级检索（硬过滤 + BM25）+ 锚点切片查询
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rank_bm25 import BM25Okapi

try:  # tools.py 的切片函数还没加时也能跑，退化为全文匹配
    from tools import extract_function_at
except Exception:
    extract_function_at = None

DATA_DIR = Path(__file__).with_name("data")
KB_FILES = [DATA_DIR / "cwe_repair_cases.json", DATA_DIR / "juliet_cases.json"]

# 子类/细分号 → 知识库父类。入库侧(_load_cases)和查询侧(_normalise_cwe)都走它，
# 保证 Juliet 目录、cppcheck 输出、知识库三方说同一种语言
CWE_TO_PARENT = {
    "CWE-121": "CWE-119", "CWE-122": "CWE-119", "CWE-124": "CWE-119",
    "CWE-129": "CWE-119", "CWE-785": "CWE-119", "CWE-787": "CWE-119",
    "CWE-788": "CWE-119",
    "CWE-126": "CWE-125", "CWE-127": "CWE-125", "CWE-786": "CWE-125",
}

# 无 CWE 命中时的 BM25 兜底最低分：太小召回垃圾案例，太大召回为空。
# 先拍一个值，第 8 周消融时再调
MIN_FALLBACK_SCORE = 2.0

DANGEROUS_APIS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "memmove",
    "scanf", "malloc", "calloc", "realloc", "free", "strncpy",
]
_TOKEN_RE = re.compile(r"[A-Za-z_]\w*")
REQUIRED_FIELDS = {"id", "cwe", "title", "vulnerable_code", "fixed_code", "guidance"}

# 反引号常量化：提示词里需要 markdown 代码围栏，但源码里写裸三反引号
# 会在文档/渲染层面引发嵌套围栏问题，统一用常量插值
FENCE = "```"
FENCE_C = "```c"

_CASE_CACHE: list[dict[str, Any]] | None = None
_BM25 = None
_BM25_CASES: list[dict[str, Any]] = []


def canonical_cwe(value: str) -> str:
    """CWE-788 → CWE-119 一类父子归并；已是父类则原样返回"""
    v = value.strip().upper()
    return CWE_TO_PARENT.get(v, v)


def _normalise_cwe(value: str) -> str:
    """任意写法（'cwe 788' / 'CWE-788' / 788）→ 归一化 + 父类归并"""
    s = str(value).upper()
    m = re.search(r"CWE[-_ ]?(\d+)", s)
    if not m:
        return s.strip()
    return canonical_cwe(f"CWE-{m.group(1)}")


def _load_cases() -> list[dict[str, Any]]:
    global _CASE_CACHE
    if _CASE_CACHE is not None:
        return _CASE_CACHE
    cases: list[dict[str, Any]] = []
    for path in KB_FILES:
        if not path.exists():
            print(f"[rag] 知识库文件不存在，跳过: {path.name}")
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        for case in raw:
            if not isinstance(case, dict) or not REQUIRED_FIELDS.issubset(case):
                raise RuntimeError(f"案例缺少必填字段: {path.name}")
            case = dict(case)
            case["cwe"] = _normalise_cwe(case["cwe"])
            for field in ("root_cause", "fix_strategy", "negative_example"):
                case.setdefault(field, "")   # 预留字段，12 月论文窗口再填
            cases.append(case)
    if not cases:
        raise RuntimeError("知识库为空：data/ 下没有任何案例文件")
    seen, unique = set(), []
    for c in cases:
        if c["id"] not in seen:
            seen.add(c["id"])
            unique.append(c)
    _CASE_CACHE = unique
    print(f"[rag] 知识库加载完成: {len(unique)} 条")
    return unique


def _case_tokens(case: dict[str, Any]) -> list[str]:
    text = case["title"] + " " + case["guidance"] + " " + case["vulnerable_code"]
    return _TOKEN_RE.findall(text.lower())


def _get_bm25():
    global _BM25, _BM25_CASES
    if _BM25 is None:
        _BM25_CASES = _load_cases()
        _BM25 = BM25Okapi([_case_tokens(c) for c in _BM25_CASES])
    return _BM25


def _query_text(code: str, vulnerabilities: list[dict[str, Any]]) -> str:
    """锚点切片：用报错行号定位所在函数，检索时只看这一块，避免长文件全文匹配"""
    lines = sorted({v.get("line", 0) for v in vulnerabilities if v.get("line")})
    if extract_function_at is not None:
        for ln in lines:
            fn = extract_function_at(code, ln)
            if fn:
                return fn
    return code


def _query_tokens(code: str, vulnerabilities: list[dict[str, Any]]) -> list[str]:
    text = _query_text(code, vulnerabilities)
    tokens = _TOKEN_RE.findall(text.lower())
    tokens += [a for a in DANGEROUS_APIS if re.search(rf"\b{a}\s*\(", text)]
    return tokens


def retrieve_cases(
    vulnerabilities: list[dict[str, Any]],
    *,
    query_code: str = "",
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """第一级：CWE 硬过滤；第二级：BM25 在过滤后的候选中排序"""
    if top_k <= 0:
        return []
    _load_cases()
    bm25 = _get_bm25()
    cwes = {_normalise_cwe(v.get("error_type", "")) for v in vulnerabilities if v.get("error_type")}
    matching = [c for c in _BM25_CASES if c["cwe"] in cwes]

    if matching:
        q = _query_tokens(query_code, vulnerabilities)
        scores = bm25.get_scores(q)
        ranked = sorted(zip(scores, _BM25_CASES), key=lambda x: x[0], reverse=True)
        return [c for s, c in ranked if c["cwe"] in cwes and s > 0][:top_k]

    # 无 CWE（或扫描器没检出）：全库 BM25 兜底，分数不达标宁可不给案例
    if not query_code.strip():
        return []
    q = _query_tokens(query_code, vulnerabilities)
    scores = bm25.get_scores(q)
    ranked = sorted(zip(scores, _BM25_CASES), key=lambda x: x[0], reverse=True)
    return [c for s, c in ranked if s >= MIN_FALLBACK_SCORE][:top_k]


def build_repair_prompt(
    code: str,
    vulnerabilities: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> str:
    """Build the user prompt with bounded, labelled few-shot repair examples."""
    cwe_list = ", ".join(
        sorted({_normalise_cwe(str(v.get("error_type", ""))) for v in vulnerabilities if v.get("error_type")})
    ) or "未识别到具体 CWE"

    examples = []
    for index, case in enumerate(cases, start=1):
        examples.append(
            f"""### 历史修复案例 {index}（{case['cwe']}：{case['title']}）
漏洞代码：
{FENCE_C}
{case['vulnerable_code']}
{FENCE}
修复代码：
{FENCE_C}
{case['fixed_code']}
{FENCE}
修复要点：{case['guidance']}"""
        )

    examples_text = "\n\n".join(examples) or "暂无匹配案例，请依据扫描结果和 C 语言安全最佳实践修复。"
    return f"""检测到的漏洞类型：{cwe_list}

以下是本地知识库检索到的同类修复案例。请将其作为参考，不要机械复制其中的变量名或业务逻辑：
{examples_text}

请修复下面的用户代码，保持原有业务逻辑，优先采用边界检查、长度限制和安全的 API。
你的回答必须且只能包含完整的修复后 C 代码，并放在 {FENCE_C} 和 {FENCE} 之间，不要输出解释。

用户代码：
{FENCE_C}
{code}
{FENCE}"""