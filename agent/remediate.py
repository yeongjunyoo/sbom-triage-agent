"""조치안 만들기(Go): OPEN 판단이 난 패키지의 버전을 올리고 빌드와 시험, 재스캔으로 확인한다.

    python3 agent/remediate.py <저장소> --out out/<이름> [--test-timeout 900]

원본은 건드리지 않고 복사본에서 작업한다. 결과는 fix.patch 와 remediation.json 이다. PR 을 올리거나 배포하지 않는다.
빌드와 시험은 저장소 코드를 실행하므로 sandbox-exec 로 비밀 폴더 읽기를 막고 돌린다(맥). 실패하면 사람에게 넘긴다.
"""
from __future__ import annotations

import argparse, json, os, pathlib, re, shutil, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
GO = ROOT / "tools" / "go" / "bin" / "go"
HOME = pathlib.Path.home()
PROFILE = """(version 1)
(allow default)
(deny file-read* file-write*
  (subpath "{h}/.nova") (subpath "{h}/.ssh") (subpath "{h}/.codex") (subpath "{h}/.claude") (subpath "{h}/.aws") (subpath "{h}/.gnupg"))
""".format(h=HOME)


def sh(cmd, cwd, timeout, env):
    t0 = time.time()
    prof = cwd.parent / "sandbox.sb"
    prof.write_text(PROFILE, encoding="utf-8")
    wrapped = ["sandbox-exec", "-f", str(prof)] + cmd if shutil.which("sandbox-exec") else cmd
    try:
        r = subprocess.run(wrapped, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=env)
        return {"cmd": " ".join(cmd), "exit": r.returncode, "seconds": round(time.time() - t0, 1), "tail": (r.stdout + r.stderr)[-1500:]}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "exit": -9, "seconds": round(time.time() - t0, 1), "tail": "시간 초과"}


def semver_key(v: str):
    return [int(x) for x in re.findall(r"\d+", v)[:4]] or [0]


def choose_fix(fixed: list[str], current: str) -> str | None:
    cur = semver_key(current)
    cands = [v for v in fixed if semver_key(v) > cur]
    return ("v" + max(cands, key=semver_key).lstrip("v")) if cands else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--out", required=True)
    ap.add_argument("--test-timeout", type=int, default=900)
    a = ap.parse_args()
    repo = pathlib.Path(a.repo).resolve()
    out = pathlib.Path(a.out).resolve()
    findings = {f["id"]: f for f in json.loads((out / "findings.json").read_text(encoding="utf-8"))}
    decisions = json.loads((out / "decisions.json").read_text(encoding="utf-8"))
    # 조치 대상과 사람 검토 건 모두 조치안을 미리 검증해 둔다. 적용은 사람이 승인한다.
    targets = {}
    for d in decisions.values():
        if d["decision"] in ("OPEN", "REVIEW"):
            f = findings[d["id"]]
            v = choose_fix(f.get("fixed", []), f.get("version", "0"))
            if v and f.get("ecosystem") == "Go":
                t = targets.setdefault(f["package"], {"version": v, "cves": [], "from": f.get("version")})
                t["cves"].append(f["cve"])
                if semver_key(v) > semver_key(t["version"]):
                    t["version"] = v
    work = out / "fix"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(repo, work, ignore=shutil.ignore_patterns(".git"))
    subprocess.run(["git", "init", "-q"], cwd=work)
    subprocess.run(["git", "add", "-A"], cwd=work, capture_output=True)
    subprocess.run(["git", "-c", "user.name=agent", "-c", "user.email=agent@local", "commit", "-qm", "base"], cwd=work, capture_output=True)
    env = dict(os.environ, PATH=f"{GO.parent}:{os.environ['PATH']}", GOPATH=str(out / "gopath"), GOFLAGS="-mod=mod", GOTOOLCHAIN="auto", GOCACHE=str(out / "gocache"))
    steps = []
    for pkg, t in sorted(targets.items()):
        steps.append(sh([str(GO), "get", f"{pkg}@{t['version']}"], work, 300, env))
    steps.append(sh([str(GO), "mod", "tidy"], work, 300, env))
    build = sh([str(GO), "build", "./..."], work, 900, env)
    steps.append(build)
    vet = sh([str(GO), "vet", "./..."], work, 600, env)
    steps.append(vet)
    test = sh([str(GO), "test", "-short", "-count=1", "./..."], work, a.test_timeout, env)
    steps.append(test)
    diff = subprocess.run(["git", "diff", "--", "go.mod", "go.sum"], cwd=work, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    (out / "fix.patch").write_text(diff, encoding="utf-8")
    # 재스캔: 조치 뒤 go.mod 로 SBOM 을 다시 만들어 같은 CVE 가 사라졌는지 본다
    bom2 = out / "bom_after.cdx.json"
    subprocess.run([str(ROOT / "tools" / "syft"), "scan", f"dir:{work}", "-o", f"cyclonedx-json={bom2}", "-q"], capture_output=True, timeout=600)
    r = subprocess.run([str(ROOT / "tools" / "osv-scanner"), "scan", "source", "-L", str(bom2), "--format", "json"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    still = set()
    raw_after = 0
    try:
        for res in json.loads(r.stdout).get("results", []):
            for pk in res.get("packages", []):
                for v in pk.get("vulnerabilities", []):
                    raw_after += 1
                    still.update([v.get("id", "")] + (v.get("aliases") or []))
    except ValueError:
        pass
    wanted = sorted({c for t in targets.values() for c in t["cves"]})
    result = {
        "targets": targets, "build_ok": build["exit"] == 0, "vet_ok": vet["exit"] == 0, "test_ok": test["exit"] == 0, "test_tail": test["tail"][-800:],
        "cves_targeted": wanted, "cves_still_reported": [c for c in wanted if c in still], "alerts_after": raw_after, "steps": steps, "patch_lines": diff.count("\n"),
    }
    (out / "remediation.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in ("steps", "test_tail")}, ensure_ascii=False)[:1200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
