"""규칙 줄 세우기 자체의 성능. 75건을 KEV, EPSS 로 줄 세웠을 때 상위 N 건에 실제 위험이 얼마나 드는가. 집계만 낸다.

    python3 eval/rank_score.py

주의: 벤치마크 라벨은 그 저장소에서 실제로 위험한가이고, KEV 와 EPSS 는 CVE 자체의 악용 신호다. 자산 노출 정보는 벤치마크에 없다.
"""
from __future__ import annotations

import json, pathlib, random, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "agent"))
import vex_run, vex_score
from pipeline import load_epss, load_kev


def main() -> int:
    tasks = vex_run.tasks()
    gt = vex_score.truth()
    kev = load_kev()
    epss, day = load_epss()
    rows = [{"t": t["task_id"], "kev": t["cve_id"] in kev, "epss": epss.get(t["cve_id"], 0.0), "risk": gt[t["task_id"]]["ground_truth"] == "exploitable"} for t in tasks]
    rows.sort(key=lambda x: (not x["kev"], -x["epss"]))
    total = sum(x["risk"] for x in rows)
    res = {"n": len(rows), "risk": total, "kev": sum(x["kev"] for x in rows), "kev_risk": sum(x["kev"] and x["risk"] for x in rows), "epss_day": day, "top": {}}
    rnd = random.Random(13)
    for k in (10, 20, 30, 40):
        hit = sum(x["risk"] for x in rows[:k])
        rand = sum(sum(x["risk"] for x in rnd.sample(rows, k)) for _ in range(2000)) / 2000
        res["top"][k] = {"hit": hit, "recall": round(100 * hit / total, 1), "random_hit": round(rand, 1)}
    (ROOT / "results" / "rank_score.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
