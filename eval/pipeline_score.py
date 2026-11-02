"""단계별 구성(층 제거 실험)을 채점한다. 규칙은 결과를 보기 전에 여기 고정한다.

    python eval/pipeline_score.py --triage triage_v1 --review review_v1 --split dev

결정 규칙
- 판단이 vulnerable            → OPEN(바로 조치 대상). 근거 검사 실패는 표시만 하고 열어 둔다(안전한 쪽).
- 판단이 uncertain, 답 없음     → REVIEW(사람)
- 판단이 닫기(그 외 10종)       → 근거 검사 실패면 REVIEW. 검토가 refute 나 cannot_verify 면 REVIEW. 모두 통과하면 CLOSE
지표
- 자동 닫기 수, 자동 닫기 오류(실제 exploitable 인데 닫음), 사람 검토율
- 보수 F1: REVIEW 를 「열어 둠」으로 세어 계산. 사람이 무엇을 할지 가정하지 않는다
"""
from __future__ import annotations

import argparse, collections, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify import parse_obj, verify
import vex_run
import vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(run, tid, r=0):
    f = ROOT / "results" / run / f"{tid}__r{r}.json"
    if not f.exists():
        return None
    return json.loads(f.read_text(encoding="utf-8"))


def decide(tid, repo, triage_run, review_run, use_verify, use_review):
    m = load(triage_run, tid)
    o = parse_obj((m or {}).get("final_text"))
    cat = o.get("category") if isinstance(o, dict) else None
    if cat == "vulnerable":
        return "OPEN", "판단 vulnerable"
    if cat in (None, "uncertain") or cat not in vex_score.rp.VALID_CATEGORIES:
        return "REVIEW", "판단 불가"
    if use_verify:
        v = verify(o, repo)
        if not v["ok"]:
            return "REVIEW", "근거 검사: " + "; ".join(v["fails"][:2])
    if use_review:
        rm = load(review_run, tid)
        ro = parse_obj((rm or {}).get("final_text"))
        vd = ro.get("verdict") if isinstance(ro, dict) else None
        if vd != "uphold":
            return "REVIEW", f"검토: {vd}"
    return "CLOSE", cat


def metrics(rows):
    tp = fp = fn = tn = 0
    n = collections.Counter(r["decision"] for r in rows)
    close_wrong = []
    for r in rows:
        opened = r["decision"] != "CLOSE"
        if opened and r["truth"]:
            tp += 1
        elif opened:
            fp += 1
        elif r["truth"]:
            fn += 1
            close_wrong.append(r["task_id"])
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    return {
        "n": len(rows), "OPEN": n["OPEN"], "REVIEW": n["REVIEW"], "CLOSE": n["CLOSE"],
        "auto_close_rate_pct": round(n["CLOSE"] / len(rows) * 100, 1), "review_rate_pct": round(n["REVIEW"] / len(rows) * 100, 1),
        "close_errors": len(close_wrong), "close_error_pct": round(len(close_wrong) / n["CLOSE"] * 100, 1) if n["CLOSE"] else 0,
        "conservative_precision": round(prec * 100, 1), "recall": round(rec * 100, 1),
        "conservative_f1": round(2 * prec * rec / (prec + rec) * 100, 1) if prec + rec else 0,
        "close_wrong": close_wrong,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", required=True)
    ap.add_argument("--review", default="")
    ap.add_argument("--split", default="")
    ap.add_argument("--show-wrong", action="store_true", help="개발 세트에서만 쓴다")
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    if a.show_wrong and a.split != "dev":
        raise SystemExit("틀린 사례는 개발 세트에서만 본다")
    tasks = {t["task_id"]: t for t in vex_run.tasks()}
    gt = vex_score.truth()
    keep = set(json.loads((ROOT / "eval" / "split.json").read_text(encoding="utf-8"))[a.split]) if a.split else set(tasks)
    out = {}
    for name, uv, ur in (("판단만", False, False), ("판단+근거검사", True, False), ("판단+검토", False, True), ("판단+근거검사+검토", True, True)):
        if ur and not a.review:
            continue
        rows = []
        for tid in sorted(keep):
            if load(a.triage, tid) is None:
                continue
            d, why = decide(tid, vex_run.repo_dir(tasks[tid]), a.triage, a.review, uv, ur)
            rows.append({"task_id": tid, "decision": d, "why": why, "truth": vex_score.rp.normalize_ground_truth(gt[tid]["ground_truth"]) == "exploitable"})
        out[name] = metrics(rows)
        print(name, json.dumps({k: v for k, v in out[name].items() if k != "close_wrong"}, ensure_ascii=False))
        if a.show_wrong and name.endswith("검토"):
            for r in rows:
                if (r["decision"] == "CLOSE") == r["truth"] or r["decision"] == "REVIEW":
                    print("   ", r["task_id"], r["decision"], "정답", "exploitable" if r["truth"] else "not", r["why"][:150])
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
