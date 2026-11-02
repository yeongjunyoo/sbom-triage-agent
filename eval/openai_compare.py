"""같은 개발 세트, 같은 프롬프트, 같은 도구에서 모델만 바꾼 비교. 개발 세트라 건별로 볼 수 있다.

    python3 eval/openai_compare.py --run triage_openai --out results/openai_compare.json

대조는 Sonnet 5.5 의 r0, r1 쌍이다. 값은 한 쌍이라 차이를 일반화하지 않는다.
"""
from __future__ import annotations

import argparse, json, pathlib, statistics, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from final_score import agree, single
from guard import evidence_guard
from path_score import PROOF, measure
from verify import parse_obj
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]


def evaluate(run, keep, tasks, gt, flagged, called):
    objs = {r: {t: _load(run, t, r) for t in keep} for r in (0, 1)}
    metas = {r: {t: _meta(run, t, r) for t in keep} for r in (0, 1)}
    base = {r: {t: single(objs[r][t], vex_run.repo_dir(tasks[t]), True) for t in keep} for r in (0, 1)}

    def one(r, t):
        d = base[r][t]
        if d != "CLOSE":
            return d
        if t in called or evidence_guard(objs[r][t], vex_run.repo_dir(tasks[t]), tasks[t]["cve_id"]) or objs[r][t].get("category") not in PROOF:
            return "REVIEW"
        return d

    decs_all = {t: agree([one(0, t), one(1, t)]) for t in keep}
    decs_path = {t: ("DROP" if not flagged.get(t) else decs_all[t]) for t in keep}
    # 근거 검사 없는 한 번 판단: 범주 그대로
    single_rows = []
    for r in (0, 1):
        raw = {}
        for t in keep:
            cat = objs[r][t].get("category") if isinstance(objs[r][t], dict) else None
            raw[t] = "OPEN" if cat == "vulnerable" else ("REVIEW" if cat in (None, "uncertain") else "CLOSE")
        single_rows.append(measure(raw, gt))
    all_meta = [metas[r][t] for r in (0, 1) for t in keep if metas[r][t]]
    return {
        "runs": len(all_meta),
        "no_answer": sum(1 for m in all_meta if not m.get("final_text")),
        "unparsed": sum(1 for r in (0, 1) for t in keep if not isinstance(objs[r][t], dict)),
        "mean_seconds": round(statistics.mean(m["seconds"] for m in all_meta), 1),
        "mean_tokens": {k: round(statistics.mean((m.get("usage") or {}).get(k) or 0 for m in all_meta)) for k in ("input_tokens", "output_tokens")},
        "cost_equiv_usd_mean": (round(statistics.mean(m["cost_equiv_usd"] for m in all_meta if m.get("cost_equiv_usd")), 3) if any(m.get("cost_equiv_usd") for m in all_meta) else None),
        "model": sorted({str(x) for m in all_meta for x in (m.get("model") or [])}),
        "single_mean": {k: round(statistics.mean(x[k] for x in single_rows), 1) for k in ("people", "open", "review", "close", "close_err", "f1_open", "p_open", "r_open")},
        "default_all": measure(decs_all, gt),
        "default_path": measure(decs_path, gt),
        "wrong_closes": sorted(t for t, d in decs_all.items() if d == "CLOSE" and gt[t]["ground_truth"] == "exploitable"),
        "decisions": decs_all,
    }


def _meta(run, t, r):
    f = ROOT / "results" / run / f"{t}__r{r}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


def _load(run, t, r):
    m = _meta(run, t, r)
    return parse_obj(m.get("final_text")) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--control", default="triage_v1")
    ap.add_argument("--out", default="results/openai_compare.json")
    ap.add_argument("--exclude", default="", help="양쪽에서 빼는 과제 ID, 쉼표")
    a = ap.parse_args()
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    keep = sorted(set(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))["dev"]) - set(filter(None, a.exclude.split(","))))
    flagged = json.loads((ROOT / "results/scanner_osv/summary.json").read_text(encoding="utf-8"))["preds"]
    cg = ROOT / "results" / "govulncheck" / "summary.json"
    called = {k for k, v in json.loads(cg.read_text(encoding="utf-8")).items() if v == "called"} if cg.exists() else set()
    res = {"split": "dev", "n": len(keep), "exploitable": sum(gt[t]["ground_truth"] == "exploitable" for t in keep), "control": evaluate(a.control, keep, tasks, gt, flagged, called), "openai": evaluate(a.run, keep, tasks, gt, flagged, called)}
    res["differs"] = sorted(t for t in keep if res["control"]["decisions"][t] != res["openai"]["decisions"][t])
    (ROOT / a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    for k in ("control", "openai"):
        r = res[k]
        print(k, r["model"], "실행", r["runs"], "무응답", r["no_answer"], "못읽음", r["unparsed"], "평균초", r["mean_seconds"], "토큰", r["mean_tokens"], "비용", r["cost_equiv_usd_mean"])
        print("  한 번 판단", r["single_mean"])
        print("  기본값 전부", {x: r["default_all"][x] for x in ("people", "open", "review", "close", "close_err", "f1_open", "f1_people", "r_people")})
        print("  기본값 실제 경로", {x: r["default_path"][x] for x in ("people", "open", "review", "close", "close_err", "missed", "f1_open")})
        print("  잘못 닫음", r["wrong_closes"])
    print("판정이 다른 건", len(res["differs"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
