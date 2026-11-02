"""결과를 채점한다. 파서와 이진 변환은 VEX-Bench 의 result_parser.py 를 그대로 불러 쓴다.

    python eval/vex_score.py --run control_sonnet [--json out.json]

no_answer(답을 못 낸 건)는 FAILED 로 세어 맞힌 것에 넣지 않는다.
「자동 닫기 오류율」= not_exploitable 로 닫은 건 가운데 실제 exploitable 비율.
"""
from __future__ import annotations

import __future__, argparse, collections, json, pathlib, statistics, types

ROOT = pathlib.Path(__file__).resolve().parents[1]
BENCH = ROOT / "vendor" / "vex-bench"
# 맥 python3.9 에서 원본의 `str | None` 주석이 터지지 않도록 annotations 플래그로 컴파일한다. 내용은 그대로다.
_src = (BENCH / "src" / "evaluate" / "result_parser.py").read_text(encoding="utf-8")
rp = types.ModuleType("result_parser")
exec(compile(_src, "result_parser.py", "exec", flags=__future__.annotations.compiler_flag), rp.__dict__)


def truth() -> dict:
    out = {}
    for line in (BENCH / "benchmark" / "tasks" / "vex_bench.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            t = json.loads(line)
            out[t["task_id"]] = t
    return out


def score(pred: dict, gt: dict) -> dict:
    tp = fp = fn = tn = fail = 0
    wrong = []
    for tid, t in gt.items():
        y = rp.normalize_ground_truth(t["ground_truth"])
        p = pred.get(tid)
        if p is None:
            fail += 1
            if y == "exploitable":
                fn += 1
            wrong.append((tid, y, None))
            continue
        if p == "exploitable" and y == "exploitable":
            tp += 1
        elif p == "exploitable":
            fp += 1
            wrong.append((tid, y, p))
        elif y == "exploitable":
            fn += 1
            wrong.append((tid, y, p))
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    answered = tp + fp + tn + fn - (sum(1 for w in wrong if w[2] is None and w[1] == "exploitable"))
    closes = tn + sum(1 for w in wrong if w[2] == "not_exploitable")
    close_err = sum(1 for w in wrong if w[2] == "not_exploitable") / closes if closes else 0
    return {
        "n": len(gt), "failed": fail, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": round((tp + tn) / len(gt) * 100, 1), "precision": round(prec * 100, 1), "recall": round(rec * 100, 1), "f1": round(f1 * 100, 1),
        "closes": closes, "close_error_pct": round(close_err * 100, 1), "wrong": wrong,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--repeat", type=int, default=0)
    ap.add_argument("--split", default="", choices=["", "dev", "test"])
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    gt = truth()
    d = ROOT / "results" / a.run
    preds, cats, secs, costs = {}, {}, [], []
    leak = []
    for f in sorted(d.glob(f"*__r{a.repeat}.json")):
        m = json.loads(f.read_text(encoding="utf-8"))
        cat, _ = rp.parse_category(m.get("final_text") or "")
        if cat is not None:
            preds[m["task_id"]] = rp.to_binary(cat)
            cats[m["task_id"]] = cat
        secs.append(m.get("seconds") or 0)
        costs.append(m.get("cost_equiv_usd") or 0)
        for tool in m.get("tools", []):
            s = json.dumps(tool, ensure_ascii=False).lower()
            if "vex-bench" in s or "vex_bench" in s or "2609.08040" in s or "ground_truth" in s:
                leak.append((m["task_id"], tool["name"]))
    done = {tid: gt[tid] for tid in (p.stem.split("__r")[0] for p in d.glob(f"*__r{a.repeat}.json"))}
    if a.split:
        keep = set(json.loads((ROOT / "eval" / "split.json").read_text(encoding="utf-8"))[a.split])
        done = {k: v for k, v in done.items() if k in keep}
    r = score(preds, done)
    r["category_counts"] = dict(collections.Counter(cats.values()))
    r["mean_seconds"] = round(statistics.mean(secs), 1) if secs else 0
    r["mean_cost_equiv"] = round(statistics.mean(costs), 3) if costs else 0
    r["answer_leak_tool_calls"] = leak
    print(json.dumps({k: v for k, v in r.items() if k != "wrong"}, ensure_ascii=False))
    for w in r["wrong"]:
        print("틀림", w)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
