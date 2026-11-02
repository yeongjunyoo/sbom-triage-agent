"""조치 검사기 회귀 시험. 표본은 2026-11-02 headscale 실제 출력 형식이다."""
import pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from remediate import alert_ids, go_mod_state, new_failures, parse_go_test, side_effects

REAL = """FAIL: headscale_test.go:29: Suite.TestConfigFileLoading
--- FAIL: TestConstraints (0.05s)
    --- FAIL: TestConstraints/no-oidc-duplicate-id-postgres (0.00s)
FAIL
FAIL\tgithub.com/juanfont/headscale/hscontrol/db\t19.462s
ok  \tgithub.com/juanfont/headscale/hscontrol/util\t2.035s
FAIL
"""


def run(out, code=1):
    return {"exit": code, **parse_go_test(out)}


def test_lone_fail_line_does_not_swallow_the_package():
    r = parse_go_test(REAL)
    assert r["failed_packages"] == ["github.com/juanfont/headscale/hscontrol/db"]
    assert r["failed_tests"] == ["TestConstraints", "TestConstraints/no-oidc-duplicate-id-postgres"]
    assert r["ok_packages"] == 1


def test_new_failure_inside_an_already_failing_package_is_caught():
    base = run("--- FAIL: TestOld (0.1s)\nFAIL\nFAIL\tgithub.com/a/db\t1s\n")
    now = run("--- FAIL: TestOld (0.1s)\n--- FAIL: TestNew (0.1s)\nFAIL\nFAIL\tgithub.com/a/db\t1s\n")
    assert new_failures(base, now) == ["TestNew"]


def test_build_failure_of_an_already_failing_package_is_caught():
    base = run("--- FAIL: TestOld (0.1s)\nFAIL\nFAIL\tgithub.com/a/db\t1s\n")
    now = run("FAIL\tgithub.com/a/db [build failed]\nFAIL\n")
    assert new_failures(base, now) == ["github.com/a/db [build failed]"]


def test_nonzero_exit_with_nothing_parsed_is_not_a_pass():
    base = run("ok  \tgithub.com/a/b\t1s\n", 0)
    now = {"exit": -9, **parse_go_test("시간 초과")}
    got = new_failures(base, now)
    assert any("읽지 못한" in x for x in got) and any("통과 패키지 감소" in x for x in got)


def test_same_failures_are_not_new():
    assert new_failures(run(REAL), run(REAL)) == []


def test_side_effects_report_language_and_indirect_bumps():
    before = "module m\n\ngo 1.23.1\n\nrequire (\n\tgolang.org/x/net v0.32.0\n\tgolang.org/x/text v0.21.0 // indirect\n)\n"
    after = "module m\n\ngo 1.26.0\n\nrequire (\n\tgolang.org/x/net v0.60.0\n\tgolang.org/x/text v0.42.0 // indirect\n)\n"
    assert go_mod_state(before)[0] == "1.23.1"
    e = side_effects(before, after, {"golang.org/x/net"})
    assert e["go_directive"] == ["1.23.1", "1.26.0"]
    assert e["also_changed"] == {"golang.org/x/text": ["v0.21.0", "v0.42.0"]}


def test_a_failed_rescan_is_an_error_not_zero_alerts():
    try:
        alert_ids("")
    except ValueError:
        return
    raise AssertionError("빈 재스캔 출력을 경보 0건으로 읽었다")
