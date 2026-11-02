"""VEX-Bench 판단을 OpenAI 모델로 돌린다. vex_run.py 와 같은 프롬프트, 같은 종류의 도구로 모델만 바꾼다.

    OPENAI_RESPONSES_URL=... OPENAI_API_KEY=... python3 eval/vex_run_openai.py --run triage_openai --model <모델> --split dev --repeat 0 --cap 52

도구는 이 파일의 함수(읽기, 검색, 글롭, 웹 조회)뿐이다. 명령 실행 도구가 없고, 저장소 폴더 밖 경로는 거부한다.
웹 조회는 내장 웹 검색을 쓰는 짧은 하위 호출이다. 저장하지 않는 호출에서는 내장 검색 결과가 다음 턴에 남지 않아, 답을 도구 결과로 돌려줘야 모델이 이어서 쓸 수 있다.
--cap 은 이 실행 폴더에 남는 판단 수의 상한이다. 넘으면 시작하지 않는다.
정답 칸은 이 파일에서 읽지 않는다.
"""
from __future__ import annotations

import argparse, json, os, pathlib, shutil, subprocess, sys, threading, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex_run

ROOT = pathlib.Path(__file__).resolve().parents[1]
RG = shutil.which("rg") or "/opt/homebrew/bin/rg"
MAX_TOOL_CHARS = 20000
INSTRUCTIONS = "You are a coding agent with read-only tools. The working directory is the repository root. Use the tools to inspect it, then give your final answer in exactly the format the user asks for."
TOOLS = [
    {"type": "function", "name": "read_file", "description": "Read a text file in the working directory. Returns numbered lines.", "strict": False, "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "offset": {"type": "integer", "description": "First line, 1-indexed"}, "limit": {"type": "integer"}}, "required": ["path"]}},
    {"type": "function", "name": "grep", "description": "Search file contents with ripgrep regex syntax in the working directory. Returns path:line:text.", "strict": False, "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string", "description": "File or folder, default the working directory"}, "glob": {"type": "string"}, "case_insensitive": {"type": "boolean"}, "count_only": {"type": "boolean"}, "context": {"type": "integer"}}, "required": ["pattern"]}},
    {"type": "function", "name": "glob", "description": "List files in the working directory matching a glob such as **/*.go.", "strict": False, "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}}, "required": ["pattern"]}},
    {"type": "function", "name": "web_lookup", "description": "Look up public information on the web, such as a CVE advisory. Returns a short answer with exact facts and source URLs.", "strict": False, "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
]
MAX_WEB = 10
WEB_PROMPT = "Use web search and open the primary sources. Answer the request below with exact facts: package names, affected and fixed versions, vulnerable functions or classes, exploitation prerequisites, and the source URLs you read. Say plainly if you could not find something.\n\nRequest: "
lock = threading.Lock()
started = 0


class Abort(Exception):
    """한도나 인증 문제. 더 시작하지 않는다."""


def inside(repo: pathlib.Path, p: str | None) -> pathlib.Path:
    q = (repo / (p or ".")).resolve()
    if q != repo and repo not in q.parents:
        raise PermissionError("path is outside the working directory")
    return q


def t_read(repo, a):
    f = inside(repo, a.get("path"))
    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(int(a.get("offset") or 1), 1)
    limit = min(int(a.get("limit") or 2000), 2000)
    return "\n".join(f"{i}\t{l[:2000]}" for i, l in enumerate(lines[start - 1: start - 1 + limit], start)) or "(empty)"


def t_grep(repo, a):
    target = inside(repo, a.get("path"))
    cmd = [RG, "--no-config", "--no-messages", "--hidden", "--glob", "!.git", "--color", "never"]
    cmd += ["--count-matches"] if a.get("count_only") else ["-n", "--no-heading"]
    if a.get("case_insensitive"):
        cmd.append("-i")
    if a.get("context"):
        cmd += ["-C", str(min(int(a["context"]), 10))]
    if a.get("glob"):
        cmd += ["--glob", str(a["glob"])]
    cmd += ["-e", str(a["pattern"]), "--", str(target.relative_to(repo)) if target != repo else "."]
    r = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, errors="replace", timeout=90)
    return r.stdout or "(no matches)"


def t_glob(repo, a):
    base = inside(repo, a.get("path"))
    hits = []
    for x in base.glob(str(a["pattern"])):
        try:
            r = x.resolve()
        except OSError:
            continue
        if (r == repo or repo in r.parents) and ".git" not in x.relative_to(base).parts:
            hits.append(str(x.relative_to(repo)))
        if len(hits) >= 500:
            break
    return "\n".join(sorted(hits)) or "(no files)"


def t_web(repo, a):
    items = [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": WEB_PROMPT + str(a["query"])[:500]}]}]
    out, _, _ = respond(items, a["_args"], tools=[{"type": "web_search"}], effort="low", instructions="Answer briefly and precisely.")
    return "\n".join(c.get("text", "") for x in out if x.get("type") == "message" for c in x.get("content", []) if c.get("type") == "output_text") or "(no answer)"


FUNCS = {"read_file": t_read, "grep": t_grep, "glob": t_glob, "web_lookup": t_web}


def call_tool(repo, name, raw, args):
    try:
        a = json.loads(raw or "{}")
        if name == "web_lookup":
            a["_args"] = args
        return str(FUNCS[name](repo, a))[:MAX_TOOL_CHARS]
    except Exception as e:  # 도구 실패는 모델에게 돌려준다
        return f"error: {type(e).__name__}: {str(e)[:200]}"


def respond(items, a, tools=None, effort=None, instructions=None):
    """스트림을 끝까지 읽어 출력 항목과 사용량을 돌려준다. 저장하지 않는 호출이라 추론 항목은 암호문째 돌려보낸다."""
    body = {"model": a.model, "instructions": instructions or INSTRUCTIONS, "input": items, "tools": tools or TOOLS, "tool_choice": "auto", "parallel_tool_calls": True,
            "reasoning": {"effort": effort or a.effort}, "store": False, "stream": True, "include": ["reasoning.encrypted_content"]}
    head = {"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"], "Content-Type": "application/json", "Accept": "text/event-stream", **json.loads(os.environ.get("OPENAI_EXTRA_HEADERS") or "{}")}
    req = urllib.request.Request(os.environ["OPENAI_RESPONSES_URL"], data=json.dumps(body).encode("utf-8"), headers=head)
    out, usage, model = [], {}, None
    with urllib.request.urlopen(req, timeout=240) as r:
        for raw in r:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            try:
                ev = json.loads(line[5:].strip())
            except ValueError:
                continue
            ty = ev.get("type")
            if ty == "response.output_item.done":
                out.append(ev["item"])
            elif ty == "response.completed":
                usage, model = ev["response"].get("usage") or {}, ev["response"].get("model")
            elif ty in ("response.failed", "error", "response.incomplete"):
                raise RuntimeError(json.dumps(ev.get("response", {}).get("error") or ev.get("response", {}).get("incomplete_details") or ev, ensure_ascii=False)[:300])
    if not usage and not out:
        raise RuntimeError("빈 응답")
    return out, usage, model


def run_one(t, a):
    global started
    out_dir = ROOT / "results" / a.run
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{t['task_id']}__r{a.repeat}"
    meta_path = out_dir / f"{tag}.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text(encoding="utf-8"))
    with lock:
        # 시작할 때 있던 수에 이번에 시작한 수를 더한다. 끝난 파일을 다시 세면 이중으로 잡힌다
        if a.existing + started >= a.cap:
            print("상한 도달, 시작하지 않음", tag, flush=True)
            return None
        started += 1
    repo = vex_run.repo_dir(t).resolve()
    prompt = vex_run.load_prompt(a.prompt).replace("{cve_id}", t["cve_id"]).replace("{language}", t["language"])
    items = [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": prompt}]}]
    t0, turns, tools, final, model, err = time.time(), 0, [], None, None, None
    tot = {"input_tokens": 0, "cached_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0}
    while time.time() - t0 < a.timeout and turns < a.max_turns:
        fails = 0
        while True:
            try:
                out, usage, model = respond(items, a)
                break
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:300]
                if e.code in (401, 402, 403, 429):
                    raise Abort(f"HTTP {e.code}: {detail}")
                fails += 1
                if fails > 2:
                    err = f"HTTP {e.code}: {detail}"
                    out = None
                    break
                time.sleep(20)
            except (urllib.error.URLError, TimeoutError, RuntimeError, OSError) as e:
                fails += 1
                if fails > 2:
                    err = f"{type(e).__name__}: {str(e)[:300]}"
                    out = None
                    break
                time.sleep(20)
        if out is None:
            break
        turns += 1
        tot["input_tokens"] += usage.get("input_tokens") or 0
        tot["cached_tokens"] += (usage.get("input_tokens_details") or {}).get("cached_tokens") or 0
        tot["output_tokens"] += usage.get("output_tokens") or 0
        tot["reasoning_tokens"] += (usage.get("output_tokens_details") or {}).get("reasoning_tokens") or 0
        calls = [x for x in out if x.get("type") == "function_call"]
        items += [{k: v for k, v in x.items() if k != "id"} for x in out]
        if not calls:
            final = "\n".join(c.get("text", "") for x in out if x.get("type") == "message" for c in x.get("content", []) if c.get("type") == "output_text") or None
            break
        for c in calls:
            tools.append({"name": c["name"], "input": {"arguments": str(c.get("arguments"))[:300]}})
            over = c["name"] == "web_lookup" and sum(1 for x in tools if x["name"] == "web_lookup") > MAX_WEB
            items.append({"type": "function_call_output", "call_id": c["call_id"], "output": "error: web lookup limit reached, answer from what you have" if over else call_tool(repo, c["name"], c.get("arguments"), a)})
    m = {"task_id": t["task_id"], "repeat": a.repeat, "cve_id": t["cve_id"], "language": t["language"], "exit": 0 if final else 1, "seconds": round(time.time() - t0, 1),
         "final_text": final, "cost_equiv_usd": None, "turns": turns, "model": [model], "tools": tools, "denials": None, "usage": tot, "error": err}
    meta_path.write_text(json.dumps(m, ensure_ascii=False, indent=0), encoding="utf-8")
    with lock:
        print(f"{tag} exit={m['exit']} {m['seconds']}s turns={turns} tools={len(tools)} in={tot['input_tokens']} out={tot['output_tokens']} err={err}", flush=True)
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--prompt", default="triage_v1")
    ap.add_argument("--model", required=True)
    ap.add_argument("--effort", default="high")
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--max-turns", type=int, default=60)
    ap.add_argument("--repeat", type=int, default=0)
    ap.add_argument("--split", default="dev", choices=["dev", "test"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--cap", type=int, required=True)
    ap.add_argument("--exclude", default="", help="빼는 과제 ID, 쉼표")
    a = ap.parse_args()
    keep = set(json.loads((ROOT / "eval" / "split.json").read_text(encoding="utf-8"))[a.split])
    keep -= set(filter(None, a.exclude.split(",")))
    ts = [t for t in vex_run.tasks() if t["task_id"] in keep]
    if a.limit:
        ts = ts[: a.limit]
    a.existing = len(list((ROOT / "results" / a.run).glob("*__r*.json"))) if (ROOT / "results" / a.run).exists() else 0
    print("과제", len(ts), "모델", a.model, "이미 있는 판단", a.existing, flush=True)
    try:
        with ThreadPoolExecutor(a.parallel) as ex:
            res = [r for r in ex.map(lambda t: run_one(t, a), ts) if r]
    except Abort as e:
        print("중단:", e, flush=True)
        return 75
    print("끝", len(res), "응답 있음", sum(1 for r in res if r.get("final_text")), "평균초", round(sum(r["seconds"] for r in res) / max(len(res), 1), 1), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
