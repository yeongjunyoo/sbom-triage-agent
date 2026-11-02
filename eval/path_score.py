"""실제 파이프라인 경로의 점수. 에이전트는 스캐너가 올린 경보만 받는다. 스캐너가 놓친 건은 입력되지 않는다.

    python3 eval/path_score.py [--scanner results/scanner_osv/summary.json]

벤치마크 표(final_score.py)는 49건 전부를 에이전트가 판단한 값이라 「스캐너가 놓친 위험」 을 에이전트가 줄인 것처럼 보인다. 이 파일은 그 착시를 뺀다.
- 스캐너가 안 올린 건: 사람 목록에 오지 않는다(스캐너 단독과 같다).
- 스캐너가 올린 건: 에이전트 규칙대로 닫음, 사람 검토, 조치 대상.
F1 은 두 가지로 낸다. 조치 대상만 양성, 조치 대상과 사람 검토를 양성. 봉인 세트는 집계만 낸다.
"""
from __future__ import annotations

import argparse, itertools, json, pathlib, statistics, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from final_score import agree, single, wilson
from guard import evidence_guard
from verify import parse_obj
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROOF = {"code_not_present", "code_not_reachable", "false_positive"}
RUN = {0: "triage_v1", 1: "triage_v1", 2: "triage_v1", 3: "confirm_v1", 4: "confirm_v1"}


def f1(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return round(100 * 2 * p * r / (p + r), 1) if p + r else 0.0, round(100 * p, 1), round(100 * r, 1)


def measure(decs: dict, gt: dict) -> dict:
    expl = {t for t in decs if gt[t]["ground_truth"] == "exploitable"}
    op = {t for t, d in decs.items() if d == "OPEN"}
    rv = {t for t, d in decs.items() if d == "REVIEW"}
    cl = {t for t, d in decs.items() if d == "CLOSE"}
    drop = {t for t, d in decs.items() if d == "DROP"}
    a = f1(len(op & expl), len(op - expl), len(expl - op))
    b = f1(len((op | rv) & expl), len((op | rv) - expl), len(expl - op - rv))
    return {"people": len(op | rv), "open": len(op), "review": len(rv), "close": len(cl), "close_err": len(cl & expl), "scanner_drop": len(drop), "scanner_drop_err": len(drop & expl),
            "missed": len((cl | drop) & expl), "risk_seen": len((op | rv) & expl), "f1_open": a[0], "p_open": a[1], "r_open": a[2], "f1_people": b[0], "p_people": b[1], "r_people": b[2]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", default="results/scanner_osv/summary.json")
    ap.add_argument("--split", default="test")
    ap.add_argument("--out", default="results/path_score.json")
    a = ap.parse_args()
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    keep = sorted(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))[a.split])
    flagged = json.loads((ROOT / a.scanner).read_text(encoding="utf-8"))["preds"]
    rounds = [r for r in RUN if (ROOT / "results" / RUN[r] / f"{keep[0]}__r{r}.json").exists()]

    def load(t, r):
        f = ROOT / "results" / RUN[r] / f"{t}__r{r}.json"
        return parse_obj(json.loads(f.read_text(encoding="utf-8")).get("final_text")) if f.exists() else None

    objs = {r: {t: load(t, r) for t in keep} for r in rounds}
    base = {r: {t: single(objs[r][t], vex_run.repo_dir(tasks[t]), True) for t in keep} for r in rounds}
    guarded = {r: {t: bool(base[r][t] == "CLOSE" and evidence_guard(objs[r][t], vex_run.repo_dir(tasks[t]), tasks[t]["cve_id"])) for t in keep} for r in rounds}

    cg_file = ROOT / "results" / "govulncheck" / "summary.json"
    called = {k for k, v in json.loads(cg_file.read_text(encoding="utf-8")).items() if v == "called"} if cg_file.exists() else set()

    def one(r, t, level):
        d = base[r][t]
        if d == "CLOSE" and level >= 3 and t in called:
            return "REVIEW"
        if d == "CLOSE" and level >= 1 and guarded[r][t]:
            return "REVIEW"
        if d == "CLOSE" and level >= 2 and objs[r][t].get("category") not in PROOF:
            return "REVIEW"
        return d

    scanner = measure({t: ("OPEN" if flagged.get(t) else "DROP") for t in keep}, gt)
    res = {"split": a.split, "n": len(keep), "exploitable": sum(gt[t]["ground_truth"] == "exploitable" for t in keep), "rounds": rounds, "scanner": scanner}
    print("스캐너 단독", scanner)
    for name, level, rs in (("먼저 고정한 설정(근거 검사 + 두 회차, 3쌍)", 0, [r for r in rounds if r < 3]), ("글 근거 차단까지(10쌍)", 1, rounds), ("범주 제한까지(10쌍)", 2, rounds), ("현재 기본값(10쌍)", 3, rounds)):
        for scope, gate in (("실제 경로(스캐너가 올린 건만)", True), ("49건 전부 판단", False)):
            rows = []
            for x, y in itertools.combinations(rs, 2):
                decs = {}
                for t in keep:
                    if gate and not flagged.get(t):
                        decs[t] = "DROP"
                    else:
                        decs[t] = agree([one(x, t, level), one(y, t, level)])
                rows.append(measure(decs, gt))
            mean = {k: round(statistics.mean(r[k] for r in rows), 1) for k in rows[0]}
            mean["pairs"] = [(r["close"], r["close_err"], wilson(r["close_err"], r["close"])[1]) for r in rows]
            mean["err_rate_pct"] = round(statistics.mean(r["close_err"] / r["close"] * 100 if r["close"] else 0 for r in rows), 1)
            res.setdefault(name, {})[scope] = mean
            print(name, "|", scope, "| 사람", mean["people"], "(조치", mean["open"], "검토", mean["review"], ") 닫음", mean["close"], "오류", mean["close_err"], "스캐너 누락", mean["scanner_drop_err"], "놓침", mean["missed"], "F1 조치", mean["f1_open"], "F1 사람", mean["f1_people"], "재현율 사람", mean["r_people"], "정밀도 사람", mean["p_people"])
    # 언어별: 현재 기본값, 실제 경로
    res["by_language"] = {}
    for lang in sorted({tasks[t]["language"] for t in keep}):
        sub_keep = [t for t in keep if tasks[t]["language"] == lang]
        rows = []
        for x, y in itertools.combinations(rounds, 2):
            decs = {t: ("DROP" if not flagged.get(t) else agree([one(x, t, 3), one(y, t, 3)])) for t in sub_keep}
            rows.append(measure(decs, gt))
        res["by_language"][lang] = {"n": len(sub_keep), "risk": sum(gt[t]["ground_truth"] == "exploitable" for t in sub_keep), "scanner_flagged": sum(bool(flagged.get(t)) for t in sub_keep), **{k: round(statistics.mean(r[k] for r in rows), 1) for k in ("people", "close", "close_err", "missed", "f1_open")}}
        print(lang, res["by_language"][lang])
    (ROOT / a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
