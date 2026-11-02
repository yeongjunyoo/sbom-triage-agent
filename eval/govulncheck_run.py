"""Go 건에 govulncheck 를 돌려 호출 그래프 판정을 모은다. 저장소 코드는 실행하지 않고 샌드박스 안에서 분석만 한다.

    python3 eval/govulncheck_run.py [--parallel 3] [--timeout 900]

결과: results/govulncheck/<폴더>.json(원본), results/govulncheck/summary.json(과제별 called, imported, required, none, failed)
"""
from __future__ import annotations

import argparse, json, os, pathlib, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex_run

ROOT = pathlib.Path(__file__).resolve().parents[1]
GO = ROOT / "tools" / "go" / "bin" / "go"
GV = ROOT / "tools" / "govulncheck"
OUT = ROOT / "results" / "govulncheck"
OUT.mkdir(parents=True, exist_ok=True)
HOME = pathlib.Path.home()
PROFILE = OUT / "sandbox.sb"
PROFILE.write_text(f"""(version 1)
(allow default)
(deny file-read* file-write*
  (subpath "{HOME}/.nova") (subpath "{HOME}/.ssh") (subpath "{HOME}/.codex") (subpath "{HOME}/.claude") (subpath "{HOME}/.aws") (subpath "{HOME}/.gnupg"))
""", encoding="utf-8")


def go_dirs(repo: pathlib.Path) -> list[pathlib.Path]:
    root = repo / "go.mod"
    if root.exists():
        return [repo]
    found = [p.parent for p in repo.rglob("go.mod") if "vendor" not in p.parts and "testdata" not in p.parts]
    return sorted(found, key=lambda p: len(p.parts))[:3]


def toolchain_for(d: pathlib.Path) -> str:
    """저장소가 적은 Go 버전으로 돌린다. 너무 새 도구로는 옛 의존성이 컴파일되지 않는다."""
    try:
        m = re.search(r"^go[ \t]+(\d+)\.(\d+)(?:\.(\d+))?", (d / "go.mod").read_text(encoding="utf-8", errors="replace"), re.M)
    except OSError:
        return "auto"
    if not m:
        return "auto"
    major, minor = int(m.group(1)), int(m.group(2))
    if (major, minor) < (1, 21):
        return "go1.21.13"
    patch = m.group(3) if m.group(3) is not None else "0"
    return f"go{major}.{minor}.{patch}"


def run_repo(repo: pathlib.Path, timeout: int) -> dict:
    out = OUT / f"{repo.name}.json"
    if out.exists() and out.stat().st_size > 2:
        old = json.loads(out.read_text(encoding="utf-8"))
        if any(x["exit"] in (0, 3) for x in old["runs"]):
            return old
    env = dict(os.environ, PATH=f"{GO.parent}:{os.environ['PATH']}", GOPATH=str(OUT / "gopath"), GOCACHE=str(OUT / "gocache"), GOFLAGS="-mod=mod", GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
    res = {"repo": repo.name, "runs": [], "findings": {}}
    for d in go_dirs(repo):
        env["GOTOOLCHAIN"] = toolchain_for(d)
        try:
            r = subprocess.run(["sandbox-exec", "-f", str(PROFILE), str(GV), "-format", "json", "./..."], cwd=d, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
            code, stdout, stderr = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = -9, "", "timeout"
        dec = json.JSONDecoder()
        i, aliases, levels = 0, {}, {}
        while i < len(stdout):
            while i < len(stdout) and stdout[i].isspace():
                i += 1
            if i >= len(stdout):
                break
            try:
                o, i = dec.raw_decode(stdout, i)
            except ValueError:
                break
            if "osv" in o:
                aliases[o["osv"]["id"]] = o["osv"].get("aliases") or []
            if "finding" in o:
                f = o["finding"]
                t = (f.get("trace") or [{}])[0]
                level = "called" if t.get("function") else ("imported" if t.get("package") else "required")
                rank = {"required": 0, "imported": 1, "called": 2}
                if rank[level] >= rank.get(levels.get(f["osv"]), -1):
                    levels[f["osv"]] = level
        res["runs"].append({"dir": str(d.relative_to(repo)), "exit": code, "err": stderr[-300:], "findings": len(levels)})
        for oid, lv in levels.items():
            for name in [oid] + aliases.get(oid, []):
                if {"required": 0, "imported": 1, "called": 2}[lv] >= {"required": 0, "imported": 1, "called": 2}.get(res["findings"].get(name), -1):
                    res["findings"][name] = lv
    out.write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--repo", default="", help="저장소 폴더 하나만")
    a = ap.parse_args()
    if a.repo:
        print(json.dumps(run_repo(pathlib.Path(a.repo).resolve(), a.timeout), ensure_ascii=False)[:1500])
        return 0
    tasks = [t for t in vex_run.tasks() if t["language"].lower() == "go"]
    repos = sorted({vex_run.repo_dir(t) for t in tasks}, key=str)
    print("Go 과제", len(tasks), "저장소", len(repos), flush=True)
    with ThreadPoolExecutor(a.parallel) as ex:
        results = {r["repo"]: r for r in ex.map(lambda p: run_repo(p, a.timeout), repos)}
    summary = {}
    for t in tasks:
        r = results[vex_run.repo_dir(t).name]
        ok = any(x["exit"] in (0, 3) for x in r["runs"])
        summary[t["task_id"]] = r["findings"].get(t["cve_id"]) or ("none" if ok else "failed")
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=0), encoding="utf-8")
    counts = {}
    for v in summary.values():
        counts[v] = counts.get(v, 0) + 1
    print("판정 분포", counts, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
