"""스캐너 단독 기준선 채점. 집계만 출력한다(봉인 세트 건별 결과를 보지 않기 위해)."""
import collections, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex_score, vex_run

ROOT = pathlib.Path(__file__).resolve().parents[1]
s = json.loads((ROOT / "results" / "scanner_osv" / "summary.json").read_text(encoding="utf-8"))
gt = vex_score.truth()
preds = {k: ("exploitable" if v else "not_exploitable") for k, v in s["preds"].items() if v is not None}
failed = [k for k, v in s["preds"].items() if v is None]
r = vex_score.score(preds, gt)
print(json.dumps({k: v for k, v in r.items() if k != "wrong"}, ensure_ascii=False))
print("스캔 실패(JSON 못 읽음)", len(failed), "총 스캔", len(s["preds"]))
stats = s.get("stats", {})
print("종료 코드 분포", dict(collections.Counter(v["exit"] for v in stats.values())), "평균초", round(sum(v["seconds"] for v in stats.values()) / max(len(stats), 1), 1))
for lang in ("go", "java", "python"):
    sub = {t["task_id"]: gt[t["task_id"]] for t in vex_run.tasks() if t["language"] == lang}
    rr = vex_score.score({k: v for k, v in preds.items() if k in sub}, sub)
    print(lang, {k: rr[k] for k in ("n", "failed", "tp", "fp", "fn", "tn", "precision", "recall", "f1")})
