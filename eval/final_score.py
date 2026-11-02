"""봉인 평가 집계. 건별 오답을 출력하지 않는다. 사전 등록은 eval/FROZEN.md.

    python3 eval/final_score.py --split test [--json out.json]
"""
from __future__ import annotations

import argparse, itertools, json, math, pathlib, statistics, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify import parse_obj, verify
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0, c - h) * 100, 1), round(min(1, c + h) * 100, 1))


def load_obj(run, tid, r):
    f = ROOT / "results" / run / f"{tid}__r{r}.json"
    if not f.exists():
        return None, None
    m = json.loads(f.read_text(encoding="utf-8"))
    return parse_obj(m.get("final_text")), m


def single(o, repo, use_verify):
    cat = o.get("category") if isinstance(o, dict) else None
    if cat == "vulnerable":
        return "OPEN"
    if cat in (None, "uncertain") or cat not in vex_score.rp.VALID_CATEGORIES:
        return "REVIEW"
    if use_verify and not verify(o, repo)["ok"]:
        return "REVIEW"
    return "CLOSE"


def agree(ds):
    if all(d == "CLOSE" for d in ds):
        return "CLOSE"
    return "OPEN" if "OPEN" in ds else "REVIEW"


def stats(decs, gt):
    n = len(decs)
    expl = [t for t in decs if gt[t]["ground_truth"] == "exploitable"]
    close = [t for t, d in decs.items() if d == "CLOSE"]
    review = [t for t, d in decs.items() if d == "REVIEW"]
    opened = [t for t, d in decs.items() if d == "OPEN"]
    err = [t for t in close if t in expl]
    tp = sum(1 for t in opened if t in expl)
    return {
        "n": n, "exploitable": len(expl), "close": len(close), "close_err": len(err), "close_err_pct": round(len(err) / len(close) * 100, 1) if close else 0.0,
        "close_err_ci": wilson(len(err), len(close)), "review": len(review), "review_pct": round(len(review) / n * 100, 1), "open": len(opened), "open_tp": tp,
        "open_precision": round(tp / len(opened) * 100, 1) if opened else 0.0, "expl_in_review": sum(1 for t in review if t in expl),
        "not_exploitable_auto_closed_pct": round((len(close) - len(err)) / max(n - len(expl), 1) * 100, 1),
    }


def show(name, rows, out):
    keys = ("close", "close_err", "close_err_pct", "review", "review_pct", "open", "open_tp", "open_precision", "expl_in_review", "not_exploitable_auto_closed_pct")
    if isinstance(rows, dict):
        rows = [rows]
    avg = {k: round(statistics.mean(r[k] for r in rows), 1) for k in keys}
    print(f"{name:34} " + " ".join(f"{k}={avg[k]}" for k in ("close", "close_err", "close_err_pct", "review", "open", "open_tp", "expl_in_review")), "| 회차별 close/err", [(r["close"], r["close_err"]) for r in rows])
    out[name] = {"mean": avg, "runs": rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--run", default="triage_v1")
    ap.add_argument("--control", default="control_sonnet")
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    keep = sorted(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))[a.split])
    out = {}
    objs = {r: {t: load_obj(a.run, t, r)[0] for t in keep} for r in (0, 1, 2)}
    missing = {r: sum(1 for t in keep if not (ROOT / "results" / a.run / f"{t}__r{r}.json").exists()) for r in (0, 1, 2)}
    print("봉인 결과 없는 건", missing)
    plain, ver = {}, {}
    for r in (0, 1, 2):
        plain[r] = {t: single(objs[r][t], vex_run.repo_dir(tasks[t]), False) for t in keep}
        ver[r] = {t: single(objs[r][t], vex_run.repo_dir(tasks[t]), True) for t in keep}
    # 대조: 스캐너 단독
    sf = ROOT / "results/scanner_osv/summary.json"
    if sf.exists():
        p = json.loads(sf.read_text(encoding="utf-8"))["preds"]
        show("스캐너 단독", stats({t: ("OPEN" if p.get(t) else "CLOSE") for t in keep}, gt), out)
    # 대조: 논문 프롬프트 단일
    ctrl = []
    for r in (0, 1, 2):
        if all((ROOT / "results" / a.control / f"{t}__r{r}.json").exists() for t in keep):
            ctrl.append(stats({t: single(load_obj(a.control, t, r)[0], vex_run.repo_dir(tasks[t]), False) for t in keep}, gt))
    if ctrl:
        show("논문 프롬프트 단일 실행", ctrl, out)
    show("판단 프롬프트 단일 실행", [stats(plain[r], gt) for r in (0, 1, 2)], out)
    show("단일 실행 + 근거 검사", [stats(ver[r], gt) for r in (0, 1, 2)], out)
    pairs = list(itertools.combinations((0, 1, 2), 2))
    show("두 회차 일치(근거 검사 없음)", [stats({t: agree([plain[x][t], plain[y][t]]) for t in keep}, gt) for x, y in pairs], out)
    show("★두 회차 일치 + 근거 검사(주 구성)", [stats({t: agree([ver[x][t], ver[y][t]]) for t in keep}, gt) for x, y in pairs], out)
    show("세 회차 일치 + 근거 검사", stats({t: agree([ver[0][t], ver[1][t], ver[2][t]]) for t in keep}, gt), out)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
