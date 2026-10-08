# feedback.py —— 第 6 周：闭环工具反馈迭代修复引擎
"""
工作流：修复 → GCC 编译 → Cppcheck 重扫 → 失败拦截 → 反馈 Prompt → 重试（上限 3 轮）

对应规划的三个关键设计：
1. 错误记忆（Reflexion 工程化）：报错归一化 + Hash 签名比对，
   同一错误连续出现 2 次 → 下一轮 Prompt 强制插入负面提示（固定模板轮换）
2. 反馈 Prompt 三段式（Self-Debug 风格）：归一化报错 + 一句话自述失败原因 + 定向修改指令
   （绝不把 stderr 原文整坨贴回）
3. 防死循环：同一签名连续 3 次（负面提示也救不回）提前止损；
   全部失败时返回"编译成功过的最优轮"，而不是最后一轮
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from openai import AsyncOpenAI

from tools import compile_c_code, scan_c_code
from rag import build_repair_prompt

FENCE = "```"
FENCE_C = "```c"

MAX_ROUNDS = 3                        # 迭代轮数上限（含首轮），即规划"限制最大重试次数（如3次）"
HIGH_RISK_SEVERITIES = {"error"}      # cppcheck 什么级别算"高危"。注意：第 8 周算 SPR 的口径必须与此一致；
                                      # 想更严格可改为 {"error", "warning"}
NEGATIVE_HINT_THRESHOLD = 2           # 同一错误连续出现 2 次 → 触发负面提示

# 负面提示固定模板（轮换使用）。规划明确收窄：开题只承诺"退化策略存在"，
# 模板轮换已满足，不做动态干预 Prompt 生成，防止过度工程
NEGATIVE_HINTS = [
    "【负面提示】严禁再次沿用上一轮的修复思路，它已被工具链证明无效。"
    "请彻底更换策略：优先使用显式边界检查配合长度受控的安全 API（如 strncpy/snprintf），"
    "杜绝任何依赖原指针运算的写法。",
    "【负面提示】同一错误再次出现。禁止使用与之前相同的指针/内存分配方案，"
    "改用栈上缓冲、防御性拷贝，或重新设计该函数的数据流向。",
    "【负面提示】该错误已连续多轮未解决。请放弃增量修补，"
    "严格对照报错位置重写问题函数，确保每一处内存读写都有显式边界校验。",
]

SYSTEM_PROMPT = """你是一个顶级的 C 语言安全专家。
你必须遵守用户提示中的输出格式，生成可编译、可维护且安全的 C 代码。
要求：
1. 确保修复后的代码没有缓冲区溢出、指针越界等内存安全问题。
2. 保持原有的业务逻辑不变。
3. 不要臆造不存在的库函数或业务接口。"""

# ==================== 1. 报错归一化与签名 ====================

_TMP_PATH_RE = re.compile(r"/tmp/[^\s:]+\.c")       # gcc 报错里的临时文件路径，每轮都随机
_LINE_NO_RE = re.compile(r"file\.c:\d+(?::\d+)?")   # 行号:列号，模型每轮改代码必然漂移


def normalize_gcc_errors(stderr: str) -> list[str]:
    """GCC stderr → 归一化 error 行列表。

    两个必须去掉的东西（否则 Hash 每轮都对不上，错误记忆形同虚设）：
    - 临时文件路径：/tmp/tmpXXXX.c 每轮随机生成
    - 行号/列号：模型每轮都改代码，同一逻辑错误的行号必然漂移
    """
    lines = []
    for raw in stderr.split("\n"):
        line = _TMP_PATH_RE.sub("file.c", raw).strip()
        if "error:" in line:                         # 只留诊断主行，丢弃 note: 等噪声
            lines.append(_LINE_NO_RE.sub("file.c:L", line))
    if not lines and stderr.strip():
        # 超时/内部异常这类没有 "error:" 关键字的报错，降级保留全文（去了路径）
        lines = [_TMP_PATH_RE.sub("file.c", l).strip() for l in stderr.split("\n") if l.strip()]
    return sorted(set(lines))                        # 排序去重：gcc 偶尔把同一错误报两次


def scan_signature(rescan_vulns: list[dict]) -> list[str]:
    """高危扫描告警签名：CWE + 检查器 id。刻意不含行号——同上，行号必然漂移"""
    return sorted({
        f"{v.get('error_type')}|{v.get('cppcheck_id')}"
        for v in rescan_vulns if v.get("severity") in HIGH_RISK_SEVERITIES
    })


def error_signature(compile_result: dict, rescan_vulns: list[dict]) -> str:
    """编译错误 + 高危扫描告警 → 统一 MD5 签名，供错误记忆跨轮比对"""
    parts = [f"GCC|{l}" for l in normalize_gcc_errors(compile_result.get("error_msg", ""))]
    parts += [f"SCAN|{s}" for s in scan_signature(rescan_vulns)]
    if not parts:
        return ""
    return hashlib.md5("\n".join(parts).encode("utf-8")).hexdigest()

# ==================== 2. 错误记忆（Reflexion 工程化：一个计数器 + 三条模板） ====================

class ErrorMemory:
    """跨轮记住失败签名；同一错误连续命中阈值次 → 发放负面提示（模板轮换）"""

    def __init__(self, threshold: int = NEGATIVE_HINT_THRESHOLD):
        self.threshold = threshold
        self._last_sig: str | None = None
        self._consecutive = 0
        self._trigger_count = 0

    def record(self, sig: str) -> str:
        """登记本轮失败签名；命中阈值返回一条负面提示，否则返回空串"""
        if sig and sig == self._last_sig:
            self._consecutive += 1
        else:
            self._last_sig = sig
            self._consecutive = 1 if sig else 0
        if sig and self._consecutive >= self.threshold:
            hint = NEGATIVE_HINTS[min(self._trigger_count, len(NEGATIVE_HINTS) - 1)]
            self._trigger_count += 1
            return hint
        return ""

    @property
    def hopeless(self) -> bool:
        """同一错误连吃 threshold+1 轮：负面提示也救不回来，该止损了"""
        return self._consecutive >= self.threshold + 1

# ==================== 3. 输出解析 ====================

_CODE_BLOCK_RE = re.compile(r"```[cC]?\n(.*?)```", re.DOTALL)   # 与第 2 周同一提取策略，集中到此处
_FAILURE_REASON_RE = re.compile(r"失败原因[:：]\s*(.+)")


def extract_code_block(raw: str) -> str:
    m = _CODE_BLOCK_RE.search(raw)
    return m.group(1).strip() if m else raw.strip()


def extract_failure_reason(raw: str) -> str:
    """反馈轮要求模型先自述失败原因，这里把它抠出来写进迭代日志"""
    m = _FAILURE_REASON_RE.search(raw)
    return m.group(1).strip()[:200] if m else ""

# ==================== 4. 反馈 Prompt（三段式：失败证据 → 自述原因 → 定向指令） ====================

def build_feedback_prompt(
    original_code: str,
    failed_code: str,
    compile_result: dict,
    rescan_vulns: list[dict],
    summary: dict | None,
    cases: list[dict],
    *,
    truncated: bool = False,
    negative_hint: str = "",
) -> str:
    # ---- 第一段：失败证据（归一化后，不贴 stderr 原文） ----
    gcc_errors = normalize_gcc_errors(compile_result.get("error_msg", ""))
    high_risk = [v for v in rescan_vulns if v.get("severity") in HIGH_RISK_SEVERITIES]

    failure_lines = []
    if truncated:
        failure_lines.append("- 上一轮输出超过长度上限被截断，代码不完整。请精简输出，只给代码。")
    if gcc_errors:
        shown = "\n".join(f"  {l}" for l in gcc_errors[:10])
        failure_lines.append(f"- GCC 编译报错（已归一化，忽略行号）：\n{shown}")
    if high_risk:
        shown = "\n".join(
            f"  - 行 {v.get('line')} | {v.get('error_type')} | {v.get('message')}"
            for v in high_risk[:10]
        )
        failure_lines.append(f"- 安全扫描仍报告高危漏洞：\n{shown}")
    failure_text = "\n".join(failure_lines) or "- 未知失败原因"

    # ---- 第 5 周的摘要硬约束在反馈轮继续生效 ----
    constraint_block = ""
    if summary and any(summary.get(k) for k in ("io_spec", "business_logic", "memory_risk", "repair_constraint")):
        constraint_block = f"""
# 不可修改的硬性约束（违反即视为修复失败）
- 输入输出规范：{summary.get('io_spec', '（未提供）')}
- 核心业务逻辑：{summary.get('business_logic', '（未提供）')}
- 潜在内存风险边界：{summary.get('memory_risk', '（未提供）')}
- 修复约束：{summary.get('repair_constraint', '（未提供）')}
"""

    # ---- 案例精简为"修复要点"，不重复贴完整 bad/good 代码 ----
    guidance = "\n".join(f"- {c['cwe']}：{c['guidance']}" for c in cases[:3]) or "（无）"

    negative_block = f"\n{negative_hint}\n" if negative_hint else ""

    return f"""你上一轮的修复尝试未通过工具链验证，需要重新修复。

# 第一段：失败证据
{failure_text}

# 第二段：你上一轮生成的失败代码（报错位置以此为准）
{FENCE_C}
{failed_code}
{FENCE}

# 原始用户代码（业务逻辑与外部接口的唯一依据）
{FENCE_C}
{original_code}
{FENCE}
{constraint_block}
# 历史案例修复要点（精简版）
{guidance}
{negative_block}
# 第三段：定向修改指令
1. 先用一句话自述上一轮失败的原因，以"失败原因："开头。
2. 只修复失败证据指出的问题，不要大范围重写无关代码。
3. 函数名、变量名、结构体名和外部接口签名必须与原始用户代码完全一致，只能在函数内部修改实现。
4. 你的回答必须且只能包含：一行失败原因分析 + 完整的修复后 C 代码（放在 {FENCE_C} 和 {FENCE} 之间）。"""

# ==================== 5. 迭代引擎（状态机主体） ====================

async def _call_llm(client: AsyncOpenAI, model: str, user_prompt: str,
                    temperature: float, max_tokens: int = 2048) -> tuple[str, str]:
    resp = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return resp.choices[0].message.content or "", resp.choices[0].finish_reason or ""


async def iterative_repair(
    client: AsyncOpenAI,
    code: str,
    vulns: list[dict],
    retrieved_cases: list[dict],
    summary: dict | None,
    *,
    model: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
    max_rounds: int = MAX_ROUNDS,
    on_event: Callable[[str], None] | None = None,  # ★ 第 7 周接 WebSocket 时传入推送函数即可，无需重构
) -> dict[str, Any]:
    """
    状态机：修复 → 编译 → 重扫 → (失败)反馈 → 修复 ... 直到成功 / 轮数用尽 / 死循环止损

    返回:
        repaired_code  最终代码（成功轮；否则编译成功过的最优轮；再否则最后一轮）
        compile_result 最终代码对应的编译结果
        rescan_vulns   最终代码的重扫结果（第 8 周评估 SPR 可直接用）
        final_status   success | scan_failed（有编译通过版本但扫描未全过）| compile_failed
        total_rounds   实际执行的轮数
        iterations     每轮日志（前端时间线直接渲染）
    """
    memory = ErrorMemory()
    iterations: list[dict] = []
    best: tuple | None = None       # 编译成功过的最优轮
    prev: tuple | None = None       # 上一轮 (code, compile, rescan, truncated)
    pending_hint = ""
    final_status = ""
    result_code, result_compile, result_scan = "", {"success": False, "error_msg": ""}, []

    def log(msg: str):
        print(f"[ITER] {msg}")
        if on_event:
            on_event(msg)

    for round_no in range(1, max_rounds + 1):
        # ---------- 生成本轮代码 ----------
        if round_no == 1:
            user_prompt = build_repair_prompt(code, vulns, retrieved_cases, summary=summary)
            stage = "初始修复"
        else:
            failed_code, prev_compile, prev_scan, prev_trunc = prev
            user_prompt = build_feedback_prompt(
                code, failed_code, prev_compile, prev_scan, summary, retrieved_cases,
                truncated=prev_trunc, negative_hint=pending_hint,
            )
            stage = "反馈修复" + ("（含负面提示）" if pending_hint else "")
            pending_hint = ""

        # 首轮 0.1 求稳；反馈轮 0.3，配合负面提示鼓励跳出上一轮思路（不想要可改回 0.1）
        raw, finish_reason = await _call_llm(
            client, model, user_prompt, 0.1 if round_no == 1 else 0.3
        )
        truncated = finish_reason == "length"   # 截断的代码必挂 GCC，要作为一类失败证据反馈
        current_code = extract_code_block(raw)
        failure_reason = extract_failure_reason(raw) if round_no > 1 else ""

        # ---------- 工具链验证：GCC 编译 → Cppcheck 重扫 ----------
        compile_result = await compile_c_code(current_code)
        # 编译都失败了，重扫结果不可信，直接置空（此时签名只由 GCC 错误构成）
        rescan_vulns = [] if not compile_result["success"] else await scan_c_code(current_code)
        high_risk = [v for v in rescan_vulns if v.get("severity") in HIGH_RISK_SEVERITIES]

        # ---------- 轮次日志 ----------
        if not compile_result["success"]:
            log_msg = f"第 {round_no} 轮（{stage}）：GCC 编译失败 → 拦截报错日志" + ("（输出被截断）" if truncated else "")
        elif high_risk:
            log_msg = f"第 {round_no} 轮（{stage}）：编译通过，但 Cppcheck 重扫仍有 {len(high_risk)} 个高危漏洞 → 拦截"
        else:
            log_msg = f"第 {round_no} 轮（{stage}）：编译通过，重扫无高危漏洞 ✓"
        log(log_msg)

        sig = error_signature(compile_result, rescan_vulns)
        iterations.append({
            "round": round_no,
            "stage": stage,
            "log": log_msg,
            "compile_success": compile_result["success"],
            "high_risk_count": len(high_risk),
            "failure_reason": failure_reason,
            "error_signature": sig[:12],
        })

        # ---------- 成功即退出 ----------
        if compile_result["success"] and not high_risk:
            final_status = "success"
            result_code, result_compile, result_scan = current_code, compile_result, rescan_vulns
            break

        # 编译通过但扫描没全过：留作兜底最优轮（第 2 轮编译过、第 3 轮反而挂了时，别把能跑的丢了）
        if compile_result["success"] and best is None:
            best = (current_code, compile_result, rescan_vulns)

        # ---------- 错误记忆 ----------
        pending_hint = memory.record(sig)
        if pending_hint:
            log(f"错误记忆：同一错误连续 {memory.threshold} 轮出现，下一轮注入负面提示")

        prev = (current_code, compile_result, rescan_vulns, truncated)

        # ---------- 防死循环：负面提示也救不回来就止损 ----------
        if memory.hopeless:
            log("死循环保护：同一错误连续 3 轮未解决，提前终止迭代")
            break

        if round_no < max_rounds:
            log(f"失败信息已拼接为反馈 Prompt，触发第 {round_no + 1} 轮迭代重试")

    # ---------- 收尾：全部失败时选"最优残局" ----------
    if not final_status:
        if best is not None:
            result_code, result_compile, result_scan = best
            final_status = "scan_failed"       # 至少有能编译的版本
        else:
            result_code = prev[0] if prev else ""
            result_compile = prev[1] if prev else {"success": False, "error_msg": ""}
            result_scan = prev[2] if prev else []
            final_status = "compile_failed"    # 一轮都没编译通过，只能交最后一轮

    return {
        "repaired_code": result_code,
        "compile_result": result_compile,
        "rescan_vulns": result_scan,
        "final_status": final_status,
        "total_rounds": len(iterations),
        "iterations": iterations,
    }