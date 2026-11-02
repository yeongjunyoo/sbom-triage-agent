"""VEX-Bench 75건의 저장소를 고정 커밋으로 받는다. 저장소 코드는 실행하지 않고 파일만 받는다.

    python lab/vex_fetch.py <vex_bench.jsonl> <받을 폴더>

정답 칸(ground_truth, pr_url)은 읽지 않는다. 에이전트가 보는 폴더에 정답을 두지 않기 위해서다.
"""
import json, pathlib, subprocess, sys

tasks = [json.loads(l) for l in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if l.strip()]
dst = pathlib.Path(sys.argv[2])
dst.mkdir(parents=True, exist_ok=True)
pairs = sorted({(t["repo_url"], t["commit_sha"]) for t in tasks})
print("과제", len(tasks), "저장소와 커밋 쌍", len(pairs), flush=True)
ok = fail = 0
for url, sha in pairs:
    name = url.rstrip("/").split("/")[-1] + "_" + sha[:10]
    p = dst / name
    if (p / ".git").exists() and any(x.name != ".git" for x in p.iterdir()):
        ok += 1
        continue
    p.mkdir(parents=True, exist_ok=True)
    cmds = [
        ["git", "-C", str(p), "init", "-q"],
        ["git", "-C", str(p), "-c", "protocol.version=2", "fetch", "-q", "--depth", "1", "--no-tags", url, sha],
        ["git", "-C", str(p), "-c", "core.longpaths=true", "-c", "core.symlinks=false", "checkout", "-q", "FETCH_HEAD"],
    ]
    try:
        for c in cmds:
            subprocess.run(c, check=True, capture_output=True, timeout=900)
        ok += 1
        print("ok", name, flush=True)
    except Exception as e:
        fail += 1
        err = getattr(e, "stderr", b"") or b""
        print("FAIL", name, type(e).__name__, err.decode("utf-8", "replace")[-300:].strip(), flush=True)
print("완료", ok, "실패", fail, flush=True)
