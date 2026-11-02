"""조치안 만들기(Go): 패키지별로 버전을 올려 보고, 빌드가 되는 것만 남기고, 시험과 재스캔으로 확인한다.

    python3 agent/remediate.py <저장소> --out out/<이름> [--test-timeout 1200]

원본은 건드리지 않고 복사본에서 작업한다. 결과는 fix.patch 와 remediation.json 이다. PR 을 올리거나 배포하지 않는다.
- 먼저 고치기 전 빌드와 시험을 재서, 원래 실패하던 것을 조치 탓으로 돌리지 않는다.
- 한 번에 다 올리면 하나가 전체를 깨뜨린다(2026-11-02 headscale: runc 를 올리자 dockertest 가 깨졌다). 하나씩 시도해 깨지면 되돌리고 사람에게 넘긴다.
- 정식 릴리스가 없는 수정 버전(rc, beta)은 자동으로 고르지 않는다.
- 시험은 저장소 코드를 실행하므로 sandbox-exec 로 비밀 폴더 읽기를 막고 돌린다(맥).
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


def semver_key(v: str):
    return [int(x) for x in re.findall(r"\d+", v)[:4]] or [0]


def choose_fix(fixed: list[str], current: str) -> tuple[str | None, bool]:
    cur = semver_key(current)
    cands = [v for v in fixed if semver_key(v) > cur]
    stable = [v for v in cands if not re.search(r"(rc|beta|alpha|pre)", v, re.I)]
    if stable:
        return "v" + max(stable, key=semver_key).lstrip("v"), False
    return (("v" + max(cands, key=semver_key).lstrip("v")) if cands else None), bool(cands)


class Work:
    def __init__(self, repo: pathlib.Path, out: pathlib.Path):
        self.dir = out / "fix"
        if self.dir.exists():
            shutil.rmtree(self.dir)
        shutil.copytree(repo, self.dir, ignore=shutil.ignore_patterns(".git"))
        self.prof = out / "sandbox.sb"
        self.prof.write_text(PROFILE, encoding="utf-8")
        self.env = dict(os.environ, PATH=f"{GO.parent}:{os.environ['PATH']}", GOPATH=str(out / "gopath"), GOFLAGS="-mod=mod", GOTOOLCHAIN="auto", GOCACHE=str(out / "gocache"))
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("-c", "user.name=agent", "-c", "user.email=agent@local", "commit", "-qm", "base")

    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.dir, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def go(self, args, timeout):
        cmd = ["sandbox-exec", "-f", str(self.prof), str(GO), *args] if shutil.which("sandbox-exec") else [str(GO), *args]
        t0 = time.time()
        try:
            r = subprocess.run(cmd, cwd=self.dir, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=self.env)
            return {"args": " ".join(args)[:120], "exit": r.returncode, "seconds": round(time.time() - t0, 1), "out": r.stdout + r.stderr}
        except subprocess.TimeoutExpired:
            return {"args": " ".join(args)[:120], "exit": -9, "seconds": round(time.time() - t0, 1), "out": "시간 초과"}

    def packages(self):
        r = self.go(["list", "./..."], 300)
        return [p for p in r["out"].split() if p and "/integration" not in p and not p.startswith("go:")]

    def test(self, pkgs, timeout):
        r = self.go(["test", "-short", "-count=1", *pkgs], timeout)
        failed = sorted(set(re.findall(r"^(?:FAIL|--- FAIL:?)\s+(\S+)", r["out"], re.M)))
        ok = len(re.findall(r"^ok\s", r["out"], re.M))
        return {"exit": r["exit"], "seconds": r["seconds"], "ok_packages": ok, "failed": [f for f in failed if "/" in f], "tail": r["out"][-700:]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--out", required=True)
    ap.add_argument("--test-timeout", type=int, default=1200)
    a = ap.parse_args()
    repo = pathlib.Path(a.repo).resolve()
    out = pathlib.Path(a.out).resolve()
    findings = {f["id"]: f for f in json.loads((out / "findings.json").read_text(encoding="utf-8"))}
    decisions = json.loads((out / "decisions.json").read_text(encoding="utf-8"))
    targets, prerelease_only = {}, []
    order = {"OPEN": 0, "REVIEW": 1}
    for d in sorted(decisions.values(), key=lambda x: order.get(x["decision"], 9)):
        if d["decision"] not in order:
            continue
        f = findings[d["id"]]
        if f.get("ecosystem") != "Go":
            continue
        v, pre = choose_fix(f.get("fixed", []), f.get("version", "0"))
        if not v or pre:
            prerelease_only.append({"package": f["package"], "cve": f["cve"], "fixed": f.get("fixed")})
            continue
        t = targets.setdefault(f["package"], {"version": v, "cves": [], "from": f.get("version"), "decision": d["decision"]})
        t["cves"].append(f["cve"])
        if semver_key(v) > semver_key(t["version"]):
            t["version"] = v
        if d["decision"] == "OPEN":
            t["decision"] = "OPEN"
    w = Work(repo, out)
    pkgs = w.packages()
    base_build = w.go(["build", *pkgs], 1200)
    base_test = w.test(pkgs, a.test_timeout) if base_build["exit"] == 0 else {"exit": -1, "failed": [], "ok_packages": 0, "seconds": 0, "tail": base_build["out"][-500:]}
    print("고치기 전 빌드", base_build["exit"], "시험", base_test["exit"], "통과 패키지", base_test["ok_packages"], "실패", base_test["failed"][:5], flush=True)
    accepted, rejected = [], []
    for pkg, t in sorted(targets.items(), key=lambda kv: (order[kv[1]["decision"]], kv[0])):
        g = w.go(["get", f"{pkg}@{t['version']}"], 300)
        tidy = w.go(["mod", "tidy"], 300) if g["exit"] == 0 else {"exit": 1, "out": ""}
        b = w.go(["build", *pkgs], 1200) if tidy["exit"] == 0 else {"exit": 1, "out": tidy["out"]}
        if g["exit"] == 0 and tidy["exit"] == 0 and b["exit"] == 0:
            w.git("add", "-A")
            w.git("-c", "user.name=agent", "-c", "user.email=agent@local", "commit", "-qm", f"bump {pkg} {t['version']}")
            accepted.append(pkg)
            print("적용", pkg, t["version"], flush=True)
        else:
            w.git("checkout", "--", ".")
            w.git("clean", "-fdq")
            reason = (g["out"] if g["exit"] else (tidy["out"] if tidy["exit"] else b["out"]))[-400:]
            rejected.append({"package": pkg, "version": t["version"], "cves": t["cves"], "reason": reason})
            print("되돌림", pkg, t["version"], reason[-120:].replace("\n", " "), flush=True)
    after_test = w.test(pkgs, a.test_timeout)
    new_failures = sorted(set(after_test["failed"]) - set(base_test["failed"]))
    diff = w.git("diff", "HEAD~%d" % len(accepted), "--", "go.mod").stdout if accepted else ""
    full = w.git("diff", "HEAD~%d" % len(accepted)).stdout if accepted else ""
    (out / "fix.patch").write_text(full, encoding="utf-8")
    bom2 = out / "bom_after.cdx.json"
    subprocess.run([str(ROOT / "tools" / "syft"), "scan", f"dir:{w.dir}", "-o", f"cyclonedx-json={bom2}", "-q"], capture_output=True, timeout=600)
    r = subprocess.run([str(ROOT / "tools" / "osv-scanner"), "scan", "source", "-L", str(bom2), "--format", "json"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    still, raw_after = set(), 0
    try:
        for res in json.loads(r.stdout).get("results", []):
            for pk in res.get("packages", []):
                for v in pk.get("vulnerabilities", []):
                    raw_after += 1
                    still.update([v.get("id", "")] + (v.get("aliases") or []))
    except ValueError:
        pass
    wanted = sorted({c for p in accepted for c in targets[p]["cves"]})
    before = json.loads((out / "scan_counts.json").read_text(encoding="utf-8"))["raw_alerts"]
    result = {
        "targets": targets, "accepted": accepted, "rejected": rejected, "prerelease_only": prerelease_only,
        "baseline": {"build": base_build["exit"], "test_exit": base_test["exit"], "ok_packages": base_test["ok_packages"], "failed": base_test["failed"]},
        "after": {"test_exit": after_test["exit"], "ok_packages": after_test["ok_packages"], "failed": after_test["failed"], "seconds": after_test["seconds"]},
        "new_test_failures": new_failures, "cves_fixed_targeted": wanted, "cves_still_reported": [c for c in wanted if c in still],
        "alerts_before": before, "alerts_after": raw_after, "go_mod_diff": diff[:3000],
    }
    (out / "remediation.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in ("targets", "go_mod_diff", "rejected")}, ensure_ascii=False)[:1500], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
