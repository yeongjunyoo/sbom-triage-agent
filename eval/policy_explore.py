"""닫을 수 있는 범주를 좁히면 어떻게 되는지 잰다. 봉인 세트는 집계만 낸다.

    python3 eval/policy_explore.py

동기: 심지 않은 대조군에서 rancher(완화 조치)와 llama_index(의존성 없음)가 6쌍 모두 잘못 닫혔다. 두 회차 일치는 같은 해석을 반복하는 오류를 못 막는다.
이 규칙은 개발 세트에서 나왔고 봉인 결과를 본 뒤의 탐색이다. 사전 등록 대표값을 바꾸지 않는다. 다음 봉인 데이터에서 다시 확인해야 한다.
"""
from __future__ import annotations

import itertools, json, pathlib, statistics, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from final_score import agree, load_obj, single, stats
from guard import evidence_guard
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
ABSENCE = {"code_not_present", "code_not_reachable", "false_positive"}
INTERPRET = {"mitigating_control_protected", "requires_dependency", "runtime_protected", "perimeter_protected", "compiler_protected"}
POLICIES = {
    "현재(글 근거 차단까지)": lambda c: True,
    "완화와 의존성 범주는 사람 검토": lambda c: c not in {"mitigating_control_protected", "requires_dependency"},
    "해석 범주 전부 사람 검토": lambda c: c not in INTERPRET,
    "없음 증명 범주만 닫기": lambda c: c in ABSENCE,
}


def decide(o, repo, cve, allow, cache={}):
    key = id(o)
    d = cache.setdefault(key, single(o, repo, True) if key not in cache else None)
    if d != "CLOSE":
        return d
    if evidence_guard(o, repo, cve) or not allow(o.get("category")):
        return "REVIEW"
    return "CLOSE"


def run(split, rounds):
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    keep = sorted(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))[split])
    objs = {r: {t: load_obj("triage_v1", t, r)[0] for t in keep} for r in rounds}
    out = {}
    for name, allow in POLICIES.items():
        rows = []
        for a, b in itertools.combinations(rounds, 2):
            decs = {t: agree([decide(objs[r][t], vex_run.repo_dir(tasks[t]), tasks[t]["cve_id"], allow) for r in (a, b)]) for t in keep}
            rows.append(stats(decs, gt))
        keys = ("close", "close_err", "close_err_pct", "review", "open", "open_tp", "expl_in_review", "not_exploitable_auto_closed_pct")
        out[name] = {k: round(statistics.mean(x[k] for x in rows), 1) for k in keys} | {"pairs": [(x["close"], x["close_err"]) for x in rows]}
    return out


def main() -> int:
    res = {"개발 26건": run("dev", (0, 1)), "봉인 49건": run("test", (0, 1, 2))}
    (ROOT / "results" / "policy_explore.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    for s, rows in res.items():
        print(s)
        for n, r in rows.items():
            print(f"  {n:24} 닫음 {r['close']} 오류 {r['close_err']} ({r['close_err_pct']}%) 검토 {r['review']} 조치 {r['open']} 검토 속 위험 {r['expl_in_review']} 쌍 {r['pairs']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
