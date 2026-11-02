import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "eval"))

from pipeline import close_hold  # noqa: E402
from remediate import side_effects  # noqa: E402


def test_none_holds_every_category():
    assert close_hold(["code_not_reachable", "code_not_present"], "none") == ["code_not_reachable", "code_not_present"]


def test_proof_holds_only_interpretive_categories():
    assert close_hold(["code_not_reachable", "requires_configuration"], "proof") == ["requires_configuration"]
    assert close_hold(["code_not_reachable", "code_not_present"], "proof") == []


def test_all_holds_nothing():
    assert close_hold(["requires_configuration"], "all") == []


def test_side_effects_splits_direct_and_indirect():
    before = "go 1.23\nrequire (\n\ta.io/x v1.0.0\n\tb.io/y v1.0.0\n\tc.io/z v1.0.0 // indirect\n)\n"
    after = "go 1.26\nrequire (\n\ta.io/x v1.1.0\n\tb.io/y v1.2.0\n\tc.io/z v1.3.0 // indirect\n)\n"
    fx = side_effects(before, after, {"a.io/x"})
    assert sorted(fx["also_changed"]) == ["b.io/y", "c.io/z"]
    assert fx["also_changed_indirect"] == ["c.io/z"]
    assert fx["go_directive"] == ["1.23", "1.26"]
