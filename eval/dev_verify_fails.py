"""개발 세트에서 근거 검사가 막은 닫기 판단과 그 이유를 본다. 봉인 세트는 읽지 않는다."""
import json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify import parse_obj, verify
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
dev = sorted(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))["dev"])
gt = vex_score.truth()
tasks = {t["task_id"]: t for t in vex_run.tasks()}
for r in (0, 1):
    for t in dev:
        o = parse_obj(json.loads((ROOT / f"results/triage_v1/{t}__r{r}.json").read_text(encoding="utf-8")).get("final_text"))
        cat = o.get("category") if isinstance(o, dict) else None
        if cat in (None, "uncertain", "vulnerable"):
            continue
        v = verify(o, vex_run.repo_dir(tasks[t]))
        if not v["ok"]:
            print(f"r{r} {t} 정답={gt[t]['ground_truth']} 범주={cat}")
            for f in v["fails"][:3]:
                print("    ", f[:200])
