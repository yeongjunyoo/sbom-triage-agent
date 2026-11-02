"""한 실행 폴더의 결과를 근거 검증기로 돌려 건별 판정을 파일로 남긴다.

    python eval/verify_one.py --run triage_v1 [--repeat 0] [--split dev] [--show]

정답은 읽지 않는다. 카테고리도 --show 를 줄 때만 출력한다.
"""
import argparse, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify import parse_obj, verify
import vex_run

ROOT = pathlib.Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--run", required=True)
ap.add_argument("--repeat", type=int, default=0)
ap.add_argument("--split", default="")
ap.add_argument("--show", action="store_true")
a = ap.parse_args()
keep = set(json.loads((ROOT / "eval" / "split.json").read_text(encoding="utf-8"))[a.split]) if a.split else None
tasks = {t["task_id"]: t for t in vex_run.tasks()}
d = ROOT / "results" / a.run
out, ok, bad = {}, 0, 0
for f in sorted(d.glob(f"*__r{a.repeat}.json")):
    m = json.loads(f.read_text(encoding="utf-8"))
    tid = m["task_id"]
    if keep and tid not in keep:
        continue
    o = parse_obj(m.get("final_text"))
    v = verify(o, vex_run.repo_dir(tasks[tid]))
    v["category"] = (o or {}).get("category") if isinstance(o, dict) else None
    out[tid] = v
    ok += v["ok"]
    bad += not v["ok"]
    if a.show or not v["ok"]:
        print(tid, "통과" if v["ok"] else "실패", v["category"] if a.show else "", v["fails"][:3], v["notes"][:1])
(d / f"verify_r{a.repeat}{'_' + a.split if a.split else ''}.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
print("통과", ok, "실패", bad)
