# semantics.py —— 第 5 周：结构化语义提取模块
"""
两步走工作流的第一步：证据 + 代码 → 结构化摘要
两路客观证据：
  (a) Tree-sitter AST：函数签名、入参类型、返回值约束、核心控制流
  (b) 扫描器报告：CWE 编号、报警行号、报警行 ±10 行上下文、危险函数调用名
摘要四字段：io_spec / business_logic / memory_risk / repair_constraint
"""
from __future__ import annotations

import json
import re
from typing import Any

from openai import AsyncOpenAI

# 复用 tools.py 已有的 Tree-sitter 能力
try:
    from tools import _TS_OK, _PARSER, _iter_functions
    _TS_AVAILABLE = _TS_OK
except Exception:
    _TS_AVAILABLE = False
    _PARSER = None
    _iter_functions = None

DANGEROUS_APIS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "memmove",
    "scanf", "malloc", "calloc", "realloc", "free", "strncpy",
]

FENCE = "```"
FENCE_C = "```c"

SUMMARY_SYSTEM_PROMPT = """你是一个 C 代码静态分析专家。
你的任务是基于给定的客观证据（AST 结构信息 + 扫描器报告），提炼代码的结构化语义摘要。
摘要用于指导后续修复，必须严格基于证据，不要臆造。
请严格按以下 JSON 格式输出（不要 markdown 代码块，不要任何解释，只输出 JSON 对象）：
{
  "io_spec": "输入参数与返回值的类型、约束、合法范围",
  "business_logic": "函数核心业务逻辑（一句话说明数据如何流动、做了什么）",
  "memory_risk": "潜在内存风险边界（哪些指针、哪些数组、哪些 API 调用是危险点）",
  "repair_constraint": "修复时不可改变的行为约束（如返回值含义、外部接口、业务流程必须保留）"
}"""

SUMMARY_USER_TEMPLATE = f"""# 代码上下文
{FENCE_C}
{{code}}
{FENCE}

# 客观证据（A）：AST 结构信息
{{ast_info}}

# 客观证据（B）：扫描器报告
- CWE 列表：{{cwe_list}}
- 报警位置：
{{alarms}}
- 报警行 ±10 行上下文：
{{context_snippets}}
- 危险 API 调用：{{dangerous_apis}}

请基于以上客观证据，输出结构化语义摘要 JSON。"""


def extract_ast_info(code: str, target_lines: list[int]) -> dict[str, Any]:
    """提取目标函数的 AST 信息：函数签名、入参、返回值、核心控制流"""
    info = {
        "available": False,
        "function_signature": "",
        "params": [],
        "return_type": "",
        "control_flow": [],
        "function_text": "",
    }
    if not _TS_AVAILABLE or not target_lines:
        return info
    try:
        tree = _PARSER.parse(code.encode("utf-8"))
        target = next((ln - 1 for ln in target_lines if ln > 0), None)
        if target is None:
            return info
        target_fn = None
        for fn in _iter_functions(tree.root_node):
            if fn.start_point[0] <= target <= fn.end_point[0]:
                target_fn = fn
                break
        if target_fn is None:
            return info
        info["available"] = True
        info["function_text"] = target_fn.text.decode("utf-8", errors="replace")
        first_line = info["function_text"].split("\n", 1)[0].strip()
        info["function_signature"] = first_line
        # 入参解析
        m = re.search(r"\(([^)]*)\)", first_line)
        if m:
            params_str = m.group(1).strip()
            if params_str and params_str.lower() != "void":
                info["params"] = [p.strip() for p in params_str.split(",") if p.strip()]
        # 返回类型
        m2 = re.match(r"([\w\s\*]+?)\s+\**\w+\s*\(", first_line)
        if m2:
            info["return_type"] = m2.group(1).strip()
        # 核心控制流
        control_keywords = ["if", "for", "while", "switch", "return", "do"]
        for line in info["function_text"].split("\n"):
            stripped = line.strip()
            for kw in control_keywords:
                if re.match(rf"\b{kw}\b", stripped):
                    info["control_flow"].append(stripped)
                    break
    except Exception as e:
        print(f"[semantics] AST 提取异常: {e}")
    return info


def get_context_around_line(code: str, line: int, radius: int = 10) -> str:
    """返回 code 中第 line 行 ± radius 行的代码片段（带行号，>>> 标记报警行）"""
    if line <= 0:
        return ""
    lines = code.split("\n")
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    snippet = []
    for i in range(start, end):
        marker = ">>>" if (i + 1) == line else "   "
        snippet.append(f"{marker} {i+1:4d} | {lines[i]}")
    return "\n".join(snippet)


def extract_dangerous_apis(code: str) -> list[str]:
    """从代码中提取被调用的危险 API 列表（去重）"""
    found, seen = [], set()
    for api in DANGEROUS_APIS:
        if re.search(rf"\b{api}\s*\(", code) and api not in seen:
            found.append(api)
            seen.add(api)
    return found


def _format_alarms(vulns: list[dict[str, Any]]) -> str:
    if not vulns:
        return "  （扫描器未报告漏洞）"
    lines = []
    for v in vulns:
        ln = v.get("line", 0)
        cwe = v.get("error_type", "?")
        msg = v.get("message", "")
        sev = v.get("severity", "")
        lines.append(f"  - 行 {ln} | {cwe} | {sev} | {msg}")
    return "\n".join(lines)


async def generate_summary(
    client: AsyncOpenAI,
    code: str,
    vulnerabilities: list[dict[str, Any]],
    model: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
) -> dict[str, Any]:
    """第一步：证据 + 代码 → 结构化摘要（四字段 JSON）

    失败不阻塞主流程：返回带 _meta 的兜底摘要。
    """
    target_lines = sorted({v.get("line", 0) for v in vulnerabilities if v.get("line", 0) > 0})
    if not target_lines:
        total_lines = len(code.split("\n"))
        target_lines = [max(1, total_lines // 2)]

    # 证据 A：AST
    ast_info = extract_ast_info(code, target_lines)
    if ast_info["available"]:
        cf_text = "\n".join(f"    {c}" for c in ast_info["control_flow"][:15]) or "    （无明显控制流）"
        ast_text = (
            f"- 函数签名：{ast_info['function_signature']}\n"
            f"- 返回类型：{ast_info['return_type'] or '(未识别)'}\n"
            f"- 入参：{', '.join(ast_info['params']) or 'void'}\n"
            f"- 核心控制流：\n{cf_text}"
        )
    else:
        ast_text = "（Tree-sitter 不可用或定位失败，退化为全文）"

    # 证据 B：扫描器报告
    cwe_list = ", ".join(sorted({v.get("error_type", "?") for v in vulnerabilities})) or "（无）"
    alarms = _format_alarms(vulnerabilities)
    context_snippets = []
    for ln in target_lines[:3]:
        snippet = get_context_around_line(code, ln, radius=10)
        if snippet:
            context_snippets.append(f"--- 报警行 {ln} 上下文 ---\n{snippet}")
    context_text = "\n\n".join(context_snippets) or "（无报警位置）"
    dangerous = extract_dangerous_apis(code)
    dangerous_text = ", ".join(dangerous) if dangerous else "（未发现）"

    user_prompt = SUMMARY_USER_TEMPLATE.format(
        code=code,
        ast_info=ast_text,
        cwe_list=cwe_list,
        alarms=alarms,
        context_snippets=context_text,
        dangerous_apis=dangerous_text,
    )

    summary: dict[str, Any] = {}
    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
            max_tokens=1024,
        )
        raw = response.choices[0].message.content.strip()
        # 兜底清洗：去 markdown 围栏
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                summary = json.loads(m.group(0))
            except Exception:
                summary = {"io_spec": raw, "business_logic": "", "memory_risk": "", "repair_constraint": ""}
        else:
            summary = {"io_spec": raw, "business_logic": "", "memory_risk": "", "repair_constraint": ""}
    except Exception as e:
        print(f"[semantics] 摘要生成失败: {e}")
        summary = {
            "io_spec": "(摘要生成失败)",
            "business_logic": "",
            "memory_risk": "",
            "repair_constraint": "",
        }

    # 保证四个核心字段都存在
    for k in ("io_spec", "business_logic", "memory_risk", "repair_constraint"):
        summary.setdefault(k, "")

    # 附带证据元信息
    summary["_meta"] = {
        "ast_available": ast_info["available"],
        "function_signature": ast_info["function_signature"],
        "params": ast_info["params"],
        "return_type": ast_info["return_type"],
        "control_flow_count": len(ast_info["control_flow"]),
        "dangerous_apis": dangerous,
        "alarms": [
            {
                "line": v.get("line", 0),
                "cwe": v.get("error_type", ""),
                "severity": v.get("severity", ""),
                "message": v.get("message", ""),
            }
            for v in vulnerabilities
        ],
    }
    return summary