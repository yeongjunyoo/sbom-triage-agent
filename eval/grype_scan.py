"""두 번째 스캐너(grype)로 같은 SBOM 을 스캔해 합집합의 포착률을 잰다. 집계만 출력한다.

    python3 eval/grype_scan.py

스캐너가 놓친 실제 위험은 에이전트에게 입력되지 않는다. 입력 누락을 줄일 수 있는지 보려는 측정이다.
결과: results/scanner_grype/<폴더>.json, results/scanner_grype/summary.json, results/scanner_union/summary.json
"""
from __future__ import annotations

import json, pathlib, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
GRYPE = ROOT / "tools" / "grype"
OUT = ROOT / "results" / "scanner_grype"
OUT.mkdir(parents=True, exist_ok=True)
SBOM = ROOT / "results" / "sbom"


def scan(name: str) -> tuple[str, set[str]]:
    f = OUT / f"{name}.json"
    if not f.exists() or f.stat().st_size < 10:
        r = subprocess.run([str(GRYPE), f"sbom:{SBOM / (name + '.cdx.json')}", "-o", "json", "-q"], capture_output=True, text=True, timeout=900)
        f.write_text(r.stdout or "{}", encoding="utf-8")
    ids = set()
    try:
        d = json.loads(f.read_text(encoding="utf-8"))
    except ValueError:
        return name, ids
    for m in d.get("matches", []):
        ids.add(m["vulnerability"]["id"])
        ids.update(x["id"] for x in m.get("relatedVulnerabilities", []))
    return name, ids


def stats(preds: dict, gt: dict, keep: list[str]) -> dict:
    expl = {t for t in keep if gt[t]["ground_truth"] == "exploitable"}
    flagged = {t for t in keep if preds.get(t)}
    tp, fp, fn = len(flagged & expl), len(flagged - expl), len(expl - flagged)
    p, r = tp / (tp + fp) if tp + fp else 0, tp / (tp + fn) if tp + fn else 0
    return {"n": len(keep), "flagged": len(flagged), "tp": tp, "fp": fp, "fn": fn, "precision": round(100 * p, 1), "recall": round(100 * r, 1), "f1": round(200 * p * r / (p + r), 1) if p + r else 0}


def main() -> int:
    tasks = vex_run.tasks()
    gt = vex_score.truth()
    names = sorted({vex_run.repo_dir(t).name for t in tasks if (SBOM / (vex_run.repo_dir(t).name + ".cdx.json")).exists()})
    print("SBOM", len(names), flush=True)
    with ThreadPoolExecutor(3) as ex:
        found = dict(ex.map(scan, names))
    preds = {t["task_id"]: t["cve_id"] in found.get(vex_run.repo_dir(t).name, set()) for t in tasks}
    osv = json.loads((ROOT / "results/scanner_osv/summary.json").read_text(encoding="utf-8"))["preds"]
    union = {k: bool(preds.get(k) or osv.get(k)) for k in preds}
    split = json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))
    res = {}
    for name, p in (("osv", osv), ("grype", preds), ("union", union)):
        res[name] = {s: stats(p, gt, sorted(split[s])) for s in ("dev", "test")} | {"all": stats(p, gt, sorted(split["dev"]) + sorted(split["test"]))}
        print(name, res[name], flush=True)
    (OUT / "summary.json").write_text(json.dumps({"preds": preds, "stats": res}, ensure_ascii=False), encoding="utf-8")
    (ROOT / "results" / "scanner_union").mkdir(exist_ok=True)
    (ROOT / "results" / "scanner_union" / "summary.json").write_text(json.dumps({"preds": union}, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
