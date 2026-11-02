"""근거 검사의 범위 해석. 2026-11-02 headscale 에서 쉼표 든 글롭을 쪼개 틀린 실패를 낸 것의 회귀 시험."""
import pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "eval"))
from verify import _scope_globs, _split_scope


def test_comma_inside_braces_is_one_glob():
    assert _split_scope("**/*.{go,mod}") == ["**/*.{go,mod}"]
    assert _scope_globs("**/*.{go,mod}") == (["**/*.{go,mod}"], ".")


def test_comma_list_still_splits():
    assert _split_scope("go.mod, go.sum") == ["go.mod", "go.sum"]
    assert _scope_globs("go.mod, go.sum")[0] == ["go.mod", "go.sum"]


def test_brace_glob_next_to_a_plain_item():
    assert _split_scope("src/**/*.{ts,tsx}, package.json") == ["src/**/*.{ts,tsx}", "package.json"]
