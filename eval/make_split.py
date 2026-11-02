"""개발용과 봉인 평가용을 저장소 단위, 언어별 약 1:2 로 나눈다. 결과를 보기 전에 한 번만 만든다.

같은 저장소가 양쪽에 들어가지 않게 repo_url 해시 순으로 넣는다. 봉인 세트는 최종 구성을 고정한 뒤 한 번만 돌리고,
틀린 사례를 프롬프트 수정에 쓰지 않는다.
"""
import collections, hashlib, json, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
rows = [json.loads(l) for l in (ROOT / "vendor/vex-bench/benchmark/tasks/vex_bench.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
repos = sorted({r["repo_url"] for r in rows}, key=lambda u: hashlib.sha256(("lotte-ax-2026:" + u).encode()).hexdigest())
by = collections.defaultdict(list)
for r in rows:
    by[r["repo_url"]].append(r)
lang_total = collections.Counter(r["metadata"]["language"] for r in rows)
dev, test = [], []
lang_dev = collections.Counter()
for u in repos:
    lang = by[u][0]["metadata"]["language"]
    if lang_dev[lang] < round(lang_total[lang] / 3):
        dev.extend(by[u])
        lang_dev[lang] += len(by[u])
    else:
        test.extend(by[u])
out = {"seed": "lotte-ax-2026", "dev": sorted(r["task_id"] for r in dev), "test": sorted(r["task_id"] for r in test)}
(ROOT / "eval" / "split.json").write_text(json.dumps(out, ensure_ascii=False, indent=0), encoding="utf-8")
for name, g in (("dev", dev), ("test", test)):
    print(name, len(g), "저장소", len({r["repo_url"] for r in g}), dict(collections.Counter(r["metadata"]["language"] for r in g)), dict(collections.Counter(r["ground_truth"] for r in g)))
