"""좁힌 닫기 규칙을 새 회차로 확인한다. 봉인 세트는 집계만 낸다.

    python3 eval/policy_confirm.py            # 닫힌 건의 범주 분포와 규칙별 표

「없음 증명 범주만 닫기」 는 봉인 전 개발 세트에서 비교해 둔 대안(eval/policy_dev.py 의 P1)이고, 봉인 결과를 본 뒤 집계했다.
회차 r0~r2 는 사전 등록 평가의 것이고, confirm_v1 의 r3, r4 는 이 규칙을 정한 뒤 새로 돌린 확인 회차다.
"""
from __future__ import annotations

import collections, itertools, json, pathlib, statistics, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from final_score import agree, single, stats, wilson
from guard import evidence_guard
from verify import parse_obj
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
ABSENCE = {"code_not_present", "code_not_reachable", "false_positive"}
RUN = {0: "triage_v1", 1: "triage_v1", 2: "triage_v1", 3: "confirm_v1", 4: "confirm_v1"}


def load(t, r):
    f = ROOT / "results" / RUN[r] / f"{t}__r{r}.json"
    return parse_obj(json.loads(f.read_text(encoding="utf-8")).get("final_text")) if f.exists() else None


def main() -> int:
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    keep = sorted(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))["test"])
    rounds = [r for r in RUN if (ROOT / "results" / RUN[r] / f"{keep[0]}__r{r}.json").exists()]
    objs = {r: {t: load(t, r) for t in keep} for r in rounds}
    base = {r: {t: single(objs[r][t], vex_run.repo_dir(tasks[t]), True) for t in keep} for r in rounds}
    guarded = {r: {t: bool(base[r][t] == "CLOSE" and evidence_guard(objs[r][t], vex_run.repo_dir(tasks[t]), tasks[t]["cve_id"])) for t in keep} for r in rounds}

    def decide(r, t, narrow):
        d = base[r][t]
        if d != "CLOSE":
            return d
        if guarded[r][t] or (narrow and objs[r][t].get("category") not in ABSENCE):
            return "REVIEW"
        return "CLOSE"

    res = {"rounds": rounds, "closing_categories_by_round": {r: dict(collections.Counter(objs[r][t].get("category") for t in keep if base[r][t] == "CLOSE")) for r in rounds}}
    print(res["closing_categories_by_round"])
    for name, narrow in (("글 근거 차단까지", False), ("없음 증명 범주만 닫기", True)):
        rows = []
        for a, b in itertools.combinations(rounds, 2):
            s = stats({t: agree([decide(r, t, narrow) for r in (a, b)]) for t in keep}, gt)
            rows.append({"pair": [a, b], **{k: s[k] for k in ("close", "close_err", "review", "open", "open_tp", "expl_in_review")}, "ci": wilson(s["close_err"], s["close"])})
        keys = ("close", "close_err", "review", "open", "open_tp", "expl_in_review")
        mean = {k: round(statistics.mean(x[k] for x in rows), 1) for k in keys}
        fresh = [x for x in rows if set(x["pair"]) & {3, 4}]
        res[name] = {"mean": mean, "pairs": rows, "fresh_pairs_mean": {k: round(statistics.mean(x[k] for x in fresh), 1) for k in keys} if fresh else None}
        print(name, mean, "| 새 회차가 든 쌍", res[name]["fresh_pairs_mean"])
        for x in rows:
            print("   ", x["pair"], "닫음", x["close"], "오류", x["close_err"], "검토", x["review"], "조치", x["open"], "CI", x["ci"])
    (ROOT / "results" / "policy_confirm.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
