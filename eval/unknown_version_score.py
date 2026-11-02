"""버전을 못 읽은 구성요소도 입력으로 올리면 스캐너 누락이 줄어드는지 잰다. 봉인 세트는 집계만 낸다.

    python3 eval/unknown_version_score.py

스캐너는 버전을 모르는 구성요소를 건너뛴다(Maven, Gradle 에서 흔하다). 이름이 권고문의 패키지와 같고 버전이 비어 있으면 「버전 확인 필요」 로 올린다.
결과: results/scanner_unknown/summary.json(path_score.py 입력), 개발 세트 누락 건의 원인은 표준 출력에 건별로 적는다.
"""
from __future__ import annotations

import json, pathlib, sys
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "agent"))
import vex_run, vex_score
from grype_scan import stats
from where_used import components, osv_affected, purl_name

SBOM = ROOT / "results" / "sbom"


def main() -> int:
    tasks = vex_run.tasks()
    gt = vex_score.truth()
    split = json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))
    osv = json.loads((ROOT / "results/scanner_osv/summary.json").read_text(encoding="utf-8"))["preds"]
    cves = sorted({t["cve_id"] for t in tasks})
    with ThreadPoolExecutor(6) as ex:
        affected = dict(zip(cves, ex.map(osv_affected, cves)))
    preds, why = {}, {}
    for t in tasks:
        names = {x["name"] for x in affected[t["cve_id"]]}
        f = SBOM / (vex_run.repo_dir(t).name + ".cdx.json")
        comps = components(f) if f.exists() else []
        match = [(purl_name(c), str(c.get("version") or "")) for c in comps if purl_name(c) in names]
        unknown = [m for m in match if m[1] in ("", "UNKNOWN")]
        preds[t["task_id"]] = bool(osv.get(t["task_id"]) or unknown)
        why[t["task_id"]] = {"sbom_components": len(comps), "name_match": len(match), "unknown_version": len(unknown), "osv_packages": len(names)}
    dev = sorted(split["dev"])
    print("개발 세트에서 스캐너가 놓친 실제 위험의 원인")
    for t in dev:
        if gt[t]["ground_truth"] == "exploitable" and not osv.get(t):
            print(" ", t[:56], why[t], "새 입력" if preds[t] else "여전히 누락")
    res = {name: {s: stats(p, gt, sorted(split[s])) for s in ("dev", "test")} for name, p in (("osv", osv), ("osv+버전 미상", preds))}
    print(json.dumps(res, ensure_ascii=False))
    out = ROOT / "results" / "scanner_unknown"
    out.mkdir(exist_ok=True)
    (out / "summary.json").write_text(json.dumps({"preds": preds, "stats": res}, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
