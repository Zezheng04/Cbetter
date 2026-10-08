# tests/run_all.py —— 一站式测试入口（以后每周只维护这一个文件）
# 用法: python tests/run_all.py   （依赖 cppcheck、gcc）
# 内容: 第3周扫描回归(原test_scan.py已并入) + 第6周feedback纯函数 + Fake-LLM端到端三场景
import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import scan_c_code
from feedback import (normalize_gcc_errors, error_signature, ErrorMemory,
                      extract_code_block, extract_failure_reason, iterative_repair)

SMOKE_PATH = Path(__file__).with_name("smoke.c")   # 夹具，别删
FENCE = "```"


# ===== Fake LLM：按剧本出牌，create() 一次弹一条；rec.calls 记录每次请求 =====
class _FakeCompletions:
    def __init__(self, script):
        self.script = list(script)   # [(raw_output, finish_reason), ...]
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self.script:
            # 明确报错而不是裸 IndexError：一眼看出"状态机实际调用了几次 LLM、剧本只备了几次"
            raise AssertionError(
                f"剧本耗尽：LLM 被第 {len(self.calls)} 次调用，超出剧本预期——"
                f"状态机行为与测试场景不符（多半是轮次路径和预期不同）"
            )
        content, finish = self.script.pop(0)
        msg = SimpleNamespace(content=content)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason=finish)])


def make_fake_client(script):
    completions = _FakeCompletions(script)
    return SimpleNamespace(chat=SimpleNamespace(completions=completions)), completions


# ===== 剧本素材 =====
# 缺分号：gcc 必挂
BROKEN_SEMI = FENCE + "c\nint add(int a, int b) {\n    int s = a + b\n    return s;\n}\n" + FENCE
FIXED_ADD   = FENCE + "c\nint add(int a, int b) {\n    int s = a + b;\n    return s;\n}\n" + FENCE
BROKEN_SRC  = "int add(int a, int b) {\n    int s = a + b\n    return s;\n}\n"
# 场景 B 剧本：smoke.c 的逐字复刻（同样 include、同样函数体）。
# smoke 测试已在你机器上证明这段代码必触发 error 级告警，排除一切环境差异
RISK_C = ('#include <stdlib.h>\n'
          '#include <string.h>\n\n'
          'int null_deref(int *p) {\n'
          '    if (p == NULL) {\n'
          '        return *p;\n'
          '    }\n'
          '    return 0;\n'
          '}\n\n'
          'void oob_write(void) {\n'
          '    char buf[16];\n'
          '    memcpy(buf, "0123456789ABCDEFGHIJKLMN", 25);\n'
          '}\n')

SAFE_C = ('#include <stdlib.h>\n'
          '#include <string.h>\n\n'
          'int null_deref(int *p) {\n'
          '    if (p == NULL) {\n'
          '        return 0;\n'
          '    }\n'
          '    return *p;\n'
          '}\n\n'
          'void oob_write(void) {\n'
          '    char buf[32];\n'
          '    memcpy(buf, "0123456789ABCDEF", 17);\n'
          '}\n')

VULN_C  = FENCE + "c\n" + RISK_C + FENCE     # 第 1 轮 LLM 输出（有漏洞，必被拦截）
FIXED_C = FENCE + "c\n" + SAFE_C + FENCE     # 第 2 轮 LLM 输出（干净，必通过）

FAKE_VULNS = [
    {"line": 6,  "error_type": "CWE-476", "severity": "error",
     "cppcheck_id": "nullPointer", "message": "Null pointer dereference: p"},
    {"line": 13, "error_type": "CWE-788", "severity": "error",
     "cppcheck_id": "bufferAccessOutOfBounds", "message": "Size of buf is 16 bytes, writing 25"},
]

# ===== 第 3 周：扫描器已知答案回归（原 test_scan.py 全部并入） =====
async def test_scan_smoke():
    findings = await scan_c_code(SMOKE_PATH.read_text(encoding="utf-8"))
    types = {f["error_type"] for f in findings}
    print("    检出:", sorted(types))
    for expect in ["CWE-476", "CWE-369", "CWE-788", "CWE-415"]:
        assert expect in types, f"{expect} 未检出！"


async def test_scan_clean():
    clean = await scan_c_code("int add(int a, int b) {\n    return a + b;\n}\n")
    assert clean == [], f"干净代码出了 {len(clean)} 条告警：{clean}"


# ===== 第 6 周：纯函数 =====
def test_normalize_gcc():
    a = "/tmp/tmpabc123.c:12:5: error: 'x' undeclared (first use in this function)"
    b = "/tmp/tmpxyz789.c:99:1: error: 'x' undeclared (first use in this function)"
    assert normalize_gcc_errors(a) == normalize_gcc_errors(b), "临时路径/行号漂移应被视为同一错误"


def test_error_signature():
    s1 = error_signature({"success": False, "error_msg": "/tmp/t1.c:3:5: error: expected ';'"}, [])
    s2 = error_signature({"success": False, "error_msg": "/tmp/t2.c:40:1: error: expected ';'"}, [])
    assert s1 and s1 == s2, "同一逻辑错误的签名必须一致且非空"


def test_error_memory():
    m = ErrorMemory(threshold=2)
    assert m.record("sig-a") == ""                     # 第 1 次：不触发
    hint = m.record("sig-a")                           # 第 2 次：触发负面提示
    assert hint and "负面提示" in hint
    assert m.record("sig-b") == ""                     # 换新错误：计数重置
    m.record("sig-b")
    assert not m.hopeless
    m.record("sig-b")
    assert m.hopeless, "连续 threshold+1 次应触发死循环止损"


def test_extract_helpers():
    raw = "失败原因：上一轮忘记给 buffer 预留结束符。\n" + FENCE + "c\nint main(){return 0;}\n" + FENCE
    assert extract_failure_reason(raw).startswith("上一轮")
    assert extract_code_block(raw) == "int main(){return 0;}"


# ===== 第 6 周：端到端（Fake LLM 出牌，真实跑 gcc + cppcheck） =====
async def test_iter_compile_fail_then_success():
    """A：第 1 轮 GCC 失败 → 反馈 Prompt → 第 2 轮成功"""
    client, rec = make_fake_client([(BROKEN_SEMI, "stop"), (FIXED_ADD, "stop")])
    r = await iterative_repair(client, BROKEN_SRC, [], [], None)
    assert r["final_status"] == "success", f"最终状态: {r['final_status']}"
    assert r["total_rounds"] == 2, f"应 2 轮完成，实际 {r['total_rounds']} 轮"
    assert r["compile_result"]["success"] is True
    assert len(rec.calls) == 2
    p2 = rec.calls[1]["messages"][1]["content"]        # 第 2 轮的 user prompt
    assert "error:" in p2, "反馈 Prompt 应包含归一化报错"
    assert "/tmp/" not in p2, "反馈 Prompt 不应泄漏临时路径"


async def test_iter_scan_risk_then_success():
    """B：第 1 轮编译通过但重扫高危 → 扫描通道拦截 → 第 2 轮成功"""
    # ---- 前置自检 1：剧本里的"漏洞代码"必须真的触发 error 级告警 ----
    # 若这步就挂，说明是扫描器/环境问题，与引擎无关——把打印结果发我即可定位
    pre = await scan_c_code(RISK_C)
    print("    前置扫描（应为 error 级）:",
          [(v["error_type"], v["severity"], v["cppcheck_id"]) for v in pre])
    assert any(v["severity"] == "error" for v in pre), \
        f"扫描器未对剧本漏洞代码报 error 级告警，实际返回: {pre}"

    # ---- 前置自检 2：剧本里的"修复代码"必须扫描干净 ----
    post = await scan_c_code(SAFE_C)
    assert not any(v["severity"] == "error" for v in post), \
        f"修复版代码不应有 error 级告警，实际: {post}"

    client, rec = make_fake_client([(VULN_C, "stop"), (FIXED_C, "stop")])
    r = await iterative_repair(client, RISK_C, FAKE_VULNS, [], None)
    assert r["final_status"] == "success", f"最终状态: {r['final_status']}"
    assert r["total_rounds"] == 2, f"应 2 轮完成，实际 {r['total_rounds']} 轮"
    assert r["iterations"][0]["compile_success"] is True, "第 1 轮应编译通过"
    assert r["iterations"][0]["high_risk_count"] >= 1, (
        "前置扫描已确认该代码必触发 error 级告警，但引擎却认为重扫干净——"
        "问题不在测试也不在扫描器，在 feedback.py 的重扫逻辑。检查：\n"
        '    rescan_vulns = [] if not compile_result["success"] else await scan_c_code(current_code)\n'
        "① not 是否还在（丢了会导致编译成功时不扫描——A/C 测不出来，只有 B 能暴露）；\n"
        "② 扫描的是 current_code（本轮新代码），不是 code（用户原始代码）。"
    )
    assert r["iterations"][1]["high_risk_count"] == 0, "第 2 轮重扫应干净"
async def test_iter_hopeless_early_stop():
    """C：同一错误连吃 3 轮 → 第 3 轮负面提示 + 死循环止损（上限 5 只跑 3）"""
    client, rec = make_fake_client([(BROKEN_SEMI, "stop")] * 3)
    r = await iterative_repair(client, BROKEN_SRC, [], [], None, max_rounds=5)
    assert r["final_status"] == "compile_failed"
    assert r["total_rounds"] == 3, f"应在第 3 轮止损，实际跑了 {r['total_rounds']} 轮"
    assert len(rec.calls) == 3, "止损后不应再发起第 4 次请求"
    assert "负面提示" in rec.calls[2]["messages"][1]["content"], "第 3 轮应含负面提示"
    assert "负面提示" not in rec.calls[1]["messages"][1]["content"], "第 2 轮不应提前出现"


# ===== 注册表：以后每周的测试加在这里，不再新建文件 =====
TESTS = [
    ("第3周·扫描器smoke回归",              test_scan_smoke),
    ("第3周·干净代码零告警",                test_scan_clean),
    ("第6周·报错归一化",                    test_normalize_gcc),
    ("第6周·错误签名稳定性",                test_error_signature),
    ("第6周·错误记忆与止损",                test_error_memory),
    ("第6周·输出解析",                      test_extract_helpers),
    ("第6周·端到端A：编译失败→反馈→成功",   test_iter_compile_fail_then_success),
    ("第6周·端到端B：重扫高危→拦截→成功",   test_iter_scan_risk_then_success),
    ("第6周·端到端C：负面提示+死循环止损",  test_iter_hopeless_early_stop),
]


def main():
    failures = []
    for name, fn in TESTS:
        print(f"[RUN ] {name}")
        try:
            out = fn()
            if asyncio.iscoroutine(out):   # 兼容同步/异步测试
                asyncio.run(out)
            print(f"[PASS] {name}\n")
        except AssertionError as e:
            failures.append((name, str(e)))
            print(f"[FAIL] {name}: {e}\n")
        except Exception as e:
            failures.append((name, repr(e)))
            print(f"[ERROR] {name}: {e!r}\n")
    print("=" * 60)
    print(f"结果：通过 {len(TESTS) - len(failures)} / {len(TESTS)}")
    for name, err in failures:
        print(f"  ✗ {name}: {err}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()