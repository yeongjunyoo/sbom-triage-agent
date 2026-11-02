"""닫은 판단의 재판단 조건."""
import pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from recheck import basis_of, changed


def make(tmp_path):
    (tmp_path / "go.mod").write_text("module m\n\nrequire golang.org/x/net v0.32.0\n", encoding="utf-8")
    (tmp_path / "a.go").write_text('package a\n\nimport "golang.org/x/net/http2"\n', encoding="utf-8")
    objs = [{"evidence": [{"path": "a.go", "line": 3, "quote": "x"}]}]
    return basis_of(tmp_path, objs, {"version": "v0.32.0", "modified": "2026-10-01T00:00:00Z", "kev": False})


def test_no_change_means_no_recheck(tmp_path):
    assert changed(tmp_path, make(tmp_path)) == []


def test_changed_lockfile_or_evidence_file_triggers_recheck(tmp_path):
    b = make(tmp_path)
    (tmp_path / "go.mod").write_text("module m\n\nrequire golang.org/x/net v0.60.0\n", encoding="utf-8")
    assert any("go.mod" in w for w in changed(tmp_path, b))
    (tmp_path / "a.go").unlink()
    assert any("a.go" in w for w in changed(tmp_path, b))


def test_newer_advisory_and_new_kev_trigger_recheck(tmp_path):
    b = make(tmp_path)
    assert any("권고문" in w for w in changed(tmp_path, b, advisory_modified="2026-11-02T00:00:00Z"))
    assert changed(tmp_path, b, advisory_modified="2026-09-01T00:00:00Z") == []
    assert any("KEV" in w for w in changed(tmp_path, b, kev_now=True))
