"""VEX-Bench 과제를 격리된 Claude Code 로 돌린다.

    python eval/vex_run.py --run control_sonnet --prompt vuln --model claude-sonnet-5-5 --parallel 3 [--limit 3] [--repeat 0]

격리: --restricted --safe-mode(사용자 설정, 메모리, 훅, MCP 끔), 도구는 읽기와 웹뿐, 작업 폴더 밖 읽기 거부.
정답 칸(ground_truth, pr_url)은 이 파일에서 읽지 않는다. 채점은 vex_score.py 가 따로 한다.
출력은 파이프가 아니라 파일로 받는다(손자 프로세스 파이프 멈춤 회피). 시간 초과는 taskkill /T /F.
"""
from __future__ import annotations

import argparse, ast, json, os, pathlib, signal, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
BENCH = ROOT / "vendor" / "vex-bench"
REPOS = ROOT / "vex-repos"
RESULTS = ROOT / "results"
PROMPTS_DIR = ROOT / "eval" / "prompts"
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0
RAM_FLOOR_MB = 3000
lock = threading.Lock()


def paper_prompt() -> str:
    """논문 프롬프트를 코드 실행 없이 문자열 그대로 꺼낸다."""
    tree = ast.parse((BENCH / "src" / "evaluate" / "prompts.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and node.targets[0].id == "VULNERABILITY_ANALYSIS_PROMPT":
            return ast.literal_eval(ast.parse(ast.unparse(node.value.func.value), mode="eval").body)
    raise SystemExit("prompt not found")


def load_prompt(name: str) -> str:
    return paper_prompt() if name == "vuln" else (PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")


def tasks() -> list[dict]:
    keep = ("task_id", "repo_url", "commit_sha", "cve_id")
    out = []
    for line in (BENCH / "benchmark" / "tasks" / "vex_bench.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            t = json.loads(line)
            out.append({k: t[k] for k in keep} | {"language": t["metadata"]["language"]})
    return out


def repo_dir(t: dict) -> pathlib.Path:
    return REPOS / (t["repo_url"].rstrip("/").split("/")[-1] + "_" + t["commit_sha"][:10])


def avail_mb() -> int:
    if not IS_WIN:
        return 99999
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"],
        capture_output=True, text=True, timeout=30, creationflags=NO_WINDOW,
    )
    try:
        return int(r.stdout.strip()) // 1024
    except ValueError:
        return 99999


def _parses(text) -> bool:
    sys.path.insert(0, str(ROOT / "eval"))
    from verify import parse_obj

    o = parse_obj(text)
    return isinstance(o, dict) and isinstance(o.get("category") or o.get("verdict"), str)


def agent_env() -> dict:
    env = dict(os.environ)
    tok = pathlib.Path(os.environ.get("AGENT_TOKEN_FILE") or os.devnull)
    if not IS_WIN and tok.exists():
        env["CLAUDE_CODE_OAUTH_TOKEN"] = tok.read_text().strip()
    return env


def run_one(t: dict, a) -> dict:
    out_dir = RESULTS / a.run
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{t['task_id']}__r{a.repeat}"
    meta_path = out_dir / f"{tag}.json"
    attempt = 1
    if meta_path.exists():
        m = json.loads(meta_path.read_text(encoding="utf-8"))
        if m.get("final_text") and m.get("exit") == 0 and not (a.retry_parse and not m.get("retried") and not _parses(m.get("final_text"))):
            return m
        attempt = 2 if a.retry_parse and m.get("final_text") else 1
    while avail_mb() < RAM_FLOOR_MB:
        print("RAM 바닥, 대기", flush=True)
        time.sleep(60)
    prompt = load_prompt(a.prompt).replace("{cve_id}", t["cve_id"]).replace("{language}", t["language"])
    if a.context_run:
        prior = json.loads((RESULTS / a.context_run / f"{t['task_id']}__r{a.context_repeat}.json").read_text(encoding="utf-8")).get("final_text") or ""
        prompt = prompt.replace("{prior}", prior)
    raw = out_dir / f"{tag}.stream.jsonl"
    err = out_dir / f"{tag}.err.txt"
    cmd = [
        a.claude, "-p", "--model", a.model, "--effort", a.effort,
        "--restricted", "--safe-mode", "--strict-mcp-config",
        "--permission-mode", "dontAsk",
        "--tools", "Read,Grep,Glob,WebSearch,WebFetch",
        "--allowedTools", "WebSearch", "WebFetch",
        "--no-session-persistence",
        "--output-format", "stream-json", "--verbose",
    ]
    start = time.time()
    with raw.open("w", encoding="utf-8") as fo, err.open("w", encoding="utf-8") as fe:
        p = subprocess.Popen(
            cmd, cwd=str(repo_dir(t)), stdin=subprocess.PIPE, stdout=fo, stderr=fe,
            creationflags=NO_WINDOW, text=True, encoding="utf-8", start_new_session=not IS_WIN, env=agent_env(),
        )
        try:
            p.stdin.write(prompt)
            p.stdin.close()
        except OSError:
            pass
        try:
            code = p.wait(timeout=a.timeout)
        except subprocess.TimeoutExpired:
            if IS_WIN:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, creationflags=NO_WINDOW)
            else:
                os.killpg(p.pid, signal.SIGKILL)
            code = -9
    final, cost, usage, tools, turns, model_used, denials = None, None, None, [], None, None, None
    for line in raw.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") == "assistant":
            for c in ev.get("message", {}).get("content", []):
                if c.get("type") == "tool_use":
                    tools.append({"name": c.get("name"), "input": {k: str(v)[:300] for k, v in (c.get("input") or {}).items()}})
        if ev.get("type") == "result":
            final, cost, usage, turns = ev.get("result"), ev.get("total_cost_usd"), ev.get("usage"), ev.get("num_turns")
            model_used = list((ev.get("modelUsage") or {}).keys())
            denials = ev.get("permission_denials")
    m = {
        "task_id": t["task_id"], "repeat": a.repeat, "cve_id": t["cve_id"], "language": t["language"], "exit": code,
        "seconds": round(time.time() - start, 1), "final_text": final, "cost_equiv_usd": cost, "turns": turns,
        "model": model_used, "tools": tools, "denials": denials,
        "usage": {k: (usage or {}).get(k) for k in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens")},
    }
    m["retried"] = attempt > 1
    if "hit your" in str(final) and "limit" in str(final):
        print("한도 초과, 중단:", str(final)[:90], flush=True)
        os._exit(75)
    meta_path.write_text(json.dumps(m, ensure_ascii=False, indent=0), encoding="utf-8")
    if a.retry_parse and attempt == 1 and not _parses(final):
        return run_one(t, a)
    with lock:
        print(f"{tag} exit={code} {m['seconds']}s turns={turns} cost_eq={cost} tools={len(tools)}", flush=True)
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--prompt", default="vuln")
    ap.add_argument("--model", default="claude-sonnet-5-5")
    ap.add_argument("--effort", default="high")
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--repeat", type=int, default=0)
    ap.add_argument("--only-lang", default="")
    ap.add_argument("--split", default="", choices=["", "dev", "test"])
    ap.add_argument("--context-run", default="", help="앞 단계 실행 이름. {prior} 에 그 결과를 넣고, 닫는 판단이 난 과제만 돌린다")
    ap.add_argument("--context-repeat", type=int, default=0)
    ap.add_argument("--retry-parse", action="store_true", help="JSON 을 못 읽으면 한 번 다시 묻는다")
    ap.add_argument("--claude", default=str(pathlib.Path.home() / ".local" / "bin" / ("claude.exe" if IS_WIN else "claude")))
    a = ap.parse_args()
    ts = tasks()
    if a.only_lang:
        ts = [t for t in ts if t["language"] == a.only_lang]
    if a.split:
        keep = set(json.loads((ROOT / "eval" / "split.json").read_text(encoding="utf-8"))[a.split])
        ts = [t for t in ts if t["task_id"] in keep]
    if a.context_run:
        sys.path.insert(0, str(ROOT / "eval"))
        from verify import parse_obj

        kept = []
        for t in ts:
            f = RESULTS / a.context_run / f"{t['task_id']}__r{a.context_repeat}.json"
            if not f.exists():
                continue
            o = parse_obj(json.loads(f.read_text(encoding="utf-8")).get("final_text"))
            if isinstance(o, dict) and o.get("category") not in (None, "vulnerable", "uncertain"):
                kept.append(t)
        ts = kept
    if a.limit:
        by = {}
        for t in ts:
            by.setdefault(t["language"], []).append(t)
        ts = [x for i in range(a.limit) for x in [v[i] for v in by.values() if i < len(v)]][: a.limit]
    missing = [t["task_id"] for t in ts if not repo_dir(t).exists()]
    if missing:
        raise SystemExit(f"저장소 없음: {missing[:5]}")
    print("과제", len(ts), flush=True)
    with ThreadPoolExecutor(a.parallel) as ex:
        res = list(ex.map(lambda t: run_one(t, a), ts))
    tot = sum(r.get("cost_equiv_usd") or 0 for r in res)
    print("끝. 환산 합계 USD", round(tot, 3), "평균초", round(sum(r["seconds"] for r in res) / max(len(res), 1), 1), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
