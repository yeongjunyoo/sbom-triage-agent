"""호출 그래프(govulncheck) 판정을 에이전트 판단과 대조한다. Go 과제만. 봉인 세트는 집계만 낸다.

    python3 eval/govulncheck_score.py

닫기 조건에 「호출 그래프가 called 라고 하지 않음」 을 더했을 때 무엇이 바뀌는지 본다.
"""
from __future__ import annotations

import collections, itertools, json, pathlib, statistics, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from final_score import agree, single
from grype_scan import stats as scan_stats
from guard import evidence_guard
from verify import parse_obj
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROOF = {"code_not_present", "code_not_reachable", "false_positive"}
RUN = {0: "triage_v1", 1: "triage_v1", 2: "triage_v1", 3: "confirm_v1", 4: "confirm_v1"}


def main() -> int:
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    split = json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))
    gv = json.loads((ROOT / "results/govulncheck/summary.json").read_text(encoding="utf-8"))
    res = {"n_go": len(gv), "levels": dict(collections.Counter(gv.values()))}
    for s in ("dev", "test"):
        keep = [t for t in sorted(split[s]) if t in gv]
        res[s] = {"n": len(keep), "risk": sum(gt[t]["ground_truth"] == "exploitable" for t in keep), "levels": dict(collections.Counter(gv[t] for t in keep)),
                  "called_as_positive": scan_stats({t: gv[t] == "called" for t in keep}, gt, keep)}
        rounds = (0, 1) if s == "dev" else (0, 1, 2, 3, 4)
        objs = {}
        for r in rounds:
            objs[r] = {}
            for t in keep:
                f = ROOT / "results" / RUN[r] / f"{t}__r{r}.json"
                objs[r][t] = parse_obj(json.loads(f.read_text(encoding="utf-8")).get("final_text")) if f.exists() else None
        base = {r: {t: single(objs[r][t], vex_run.repo_dir(tasks[t]), True) for t in keep} for r in rounds}

        def one(r, t, veto):
            d = base[r][t]
            if d != "CLOSE":
                return d
            o = objs[r][t]
            if evidence_guard(o, vex_run.repo_dir(tasks[t]), tasks[t]["cve_id"]) or o.get("category") not in PROOF:
                return "REVIEW"
            if veto and gv[t] == "called":
                return "REVIEW"
            return "CLOSE"

        rows = {"기본값": [], "기본값 + 호출 그래프 대조": []}
        for a, b in itertools.combinations(rounds, 2):
            for name, veto in (("기본값", False), ("기본값 + 호출 그래프 대조", True)):
                decs = {t: agree([one(a, t, veto), one(b, t, veto)]) for t in keep}
                cl = [t for t, d in decs.items() if d == "CLOSE"]
                rows[name].append({"close": len(cl), "close_err": sum(gt[t]["ground_truth"] == "exploitable" for t in cl), "called_closed": sum(gv[t] == "called" for t in cl)})
        res[s]["rules"] = {k: {m: round(statistics.mean(x[m] for x in v), 2) for m in ("close", "close_err", "called_closed")} for k, v in rows.items()}
    (ROOT / "results" / "govulncheck_score.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
