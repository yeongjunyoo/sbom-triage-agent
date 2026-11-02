"""같은 권고가 다른 번호로 와도 한 건으로 친다."""
import json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
import pipeline


def test_ghsa_and_go_ids_merge(tmp_path):
    scan = {"results": [{"packages": [{"package": {"name": "github.com/go-viper/mapstructure/v2", "version": "2.2.1", "ecosystem": "Go"}, "groups": [], "vulnerabilities": [
        {"id": "GHSA-fv92-fjc5-jj9h", "aliases": [], "summary": "a", "affected": []},
        {"id": "GO-2025-3787", "aliases": ["GHSA-fv92-fjc5-jj9h"], "summary": "b", "affected": []},
        {"id": "GHSA-other", "aliases": ["CVE-2026-1"], "summary": "c", "affected": []},
    ]}]}]}
    (tmp_path / "scan.json").write_text(json.dumps(scan), encoding="utf-8")
    found = pipeline.step_scan(tmp_path / "bom.json", tmp_path)
    assert len(found) == 2
    assert set(found[0]["ids"]) == {"GHSA-fv92-fjc5-jj9h", "GO-2025-3787"}
    assert json.loads((tmp_path / "scan_counts.json").read_text())["raw_alerts"] == 3
