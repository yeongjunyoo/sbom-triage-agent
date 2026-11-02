"""개발 세트 전용: 잘못 닫은 건의 근거를 읽는다. 봉인 세트는 거부한다.

    python3 eval/dev_inspect.py --run triage_v1 --repeat 1
"""
import argparse, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify import parse_obj, verify
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--run", default="triage_v1")
ap.add_argument("--repeat", type=int, default=0)
a = ap.parse_args()
dev = set(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))["dev"])
gt = vex_score.truth()
tasks = {t["task_id"]: t for t in vex_run.tasks()}
for tid in sorted(dev):
    f = ROOT / "results" / a.run / f"{tid}__r{a.repeat}.json"
    if not f.exists():
        continue
    m = json.loads(f.read_text(encoding="utf-8"))
    o = parse_obj(m.get("final_text"))
    cat = o.get("category") if isinstance(o, dict) else None
    truth = gt[tid]["ground_truth"]
    tcat = gt[tid]["ground_truth_category"]
    closed = cat not in (None, "vulnerable", "uncertain")
    if closed and truth == "exploitable":
        v = verify(o, vex_run.repo_dir(tasks[tid]))
        print("=" * 90)
        print(tid, "| 판단", cat, "| 정답", tcat, "| 검사", v["ok"], v["fails"][:2], "| PR", gt[tid]["metadata"].get("pr_url"))
        print("도구", [(t["name"], str(list(t["input"].values())[:1])[:70]) for t in m["tools"]][:14])
        print("이유:", (o.get("reasoning") or "")[:900])
        print("권고:", json.dumps(o.get("advisory"), ensure_ascii=False)[:400])
        print("반증:", (o.get("disproof_attempt") or "")[:300])
        print("검색:", json.dumps(o.get("searches"), ensure_ascii=False)[:500])
