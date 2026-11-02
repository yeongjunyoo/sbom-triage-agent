"""글 근거 차단(agent/guard.py)을 더하면 닫기가 얼마나 줄어드는지 잰다. 봉인 세트는 집계만 낸다.

    python3 eval/guard_effect.py

규칙은 심은 글 시험(개발 세트)에서 정했다. 봉인 세트 결과로 고르지 않았고, 사전 등록한 대표값을 바꾸지 않는다.
"""
from __future__ import annotations

import itertools, json, pathlib, statistics, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from final_score import agree, load_obj, single, stats
from guard import evidence_guard
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]


def guarded(o, repo, cve):
    d = single(o, repo, True)
    return "REVIEW" if d == "CLOSE" and evidence_guard(o, repo, cve) else d


def run(split: str, rounds: tuple[int, ...]) -> dict:
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    keep = sorted(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))[split])
    objs = {r: {t: load_obj("triage_v1", t, r)[0] for t in keep} for r in rounds}
    base, guard = [], []
    for a, b in itertools.combinations(rounds, 2):
        base.append(stats({t: agree([single(objs[r][t], vex_run.repo_dir(tasks[t]), True) for r in (a, b)]) for t in keep}, gt))
        guard.append(stats({t: agree([guarded(objs[r][t], vex_run.repo_dir(tasks[t]), tasks[t]["cve_id"]) for r in (a, b)]) for t in keep}, gt))
    keys = ("close", "close_err", "review", "open", "expl_in_review")
    return {"가드 없음": {k: round(statistics.mean(x[k] for x in base), 1) for k in keys}, "가드 있음": {k: round(statistics.mean(x[k] for x in guard), 1) for k in keys}}


def main() -> int:
    res = {"개발 26건": run("dev", (0, 1)), "봉인 49건": run("test", (0, 1, 2))}
    (ROOT / "results" / "guard_effect.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
