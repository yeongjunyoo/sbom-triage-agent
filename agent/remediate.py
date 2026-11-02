"""조치안 만들기(Go): 패키지별로 버전을 올려 빌드와 시험을 돌리고, 새 실패가 없는 것만 남기고, 재스캔으로 확인한다.

    python3 agent/remediate.py <저장소> --out out/<이름> [--test-timeout 1200]

원본은 건드리지 않고 복사본에서 작업한다. 결과는 fix.patch 와 remediation.json 이다. PR 을 올리거나 배포하지 않는다.
- 먼저 고치기 전 빌드와 시험을 재서, 원래 실패하던 것을 조치 탓으로 돌리지 않는다.
- 한 번에 다 올리면 하나가 전체를 깨뜨린다(2026-11-02 headscale: runc 를 올리자 dockertest 가 깨졌다). 하나씩 시도해 깨지면 되돌리고 사람에게 넘긴다.
- 정식 릴리스가 없는 수정 버전(rc, beta)은 자동으로 고르지 않는다.
- 시험 비교는 패키지가 아니라 시험 이름까지 본다. 원래 실패하던 패키지 안의 새 실패를 놓치지 않으려는 것이다. 종료 코드가 0이 아닌데 실패를 읽지 못하면 통과로 치지 않는다.
- 언어 버전 상승과 간접 의존성 상승은 빌드가 되어도 담당자가 볼 일이라 따로 적는다.
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


def parse_go_test(out: str) -> dict:
    """go test 출력에서 실패 패키지와 실패 시험 이름을 읽는다.

    줄 안의 공백만 건너뛴다. 줄바꿈까지 건너뛰면 단독 「FAIL」 줄이 다음 줄의 「FAIL 패키지」 를 삼켜 실패가 안 보인다.
    """
    packages = sorted({" ".join(m.groups(default="")).strip() for m in re.finditer(r"^FAIL[ \t]+(\S+)(?:[ \t]+(\[\w+ failed\]))?", out, re.M)})
    tests = sorted(set(re.findall(r"^[ \t]*--- FAIL:[ \t]+(\S+)", out, re.M)))
    return {"ok_packages": len(re.findall(r"^ok[ \t]", out, re.M)), "failed_packages": packages, "failed_tests": tests}


def new_failures(base: dict, now: dict) -> list[str]:
    """고치기 전에 없던 실패. 실패를 읽지 못했거나 통과 패키지가 줄어도 새 실패로 친다."""
    seen = set(base["failed_packages"]) | set(base["failed_tests"])
    found = set(now["failed_packages"]) | set(now["failed_tests"])
    new = sorted(found - seen)
    if now["exit"] != 0 and not found:
        new.append(f"읽지 못한 시험 실패(종료 코드 {now['exit']})")
    if now["ok_packages"] < base["ok_packages"]:
        new.append(f"통과 패키지 감소({base['ok_packages']}에서 {now['ok_packages']}로)")
    return new


def go_mod_state(text: str) -> tuple[str | None, dict[str, str]]:
    """go.mod 의 언어 버전과 모듈별 버전."""
    m = re.search(r"^go[ \t]+(\S+)", text, re.M)
    mods = {a: b for a, b in re.findall(r"^[ \t]*(?:require[ \t]+)?(\S+)[ \t]+(v\S+)", text, re.M)}
    return (m.group(1) if m else None), mods


def side_effects(before: str, after: str, targets: set[str]) -> dict:
    """요청하지 않았는데 함께 바뀐 것."""
    go_a, mods_a = go_mod_state(before)
    go_b, mods_b = go_mod_state(after)
    bumps = {k: [mods_a[k], v] for k, v in mods_b.items() if k in mods_a and mods_a[k] != v and k not in targets}
    return {"go_directive": [go_a, go_b] if go_a != go_b else None, "also_changed": bumps}


def alert_ids(raw: str) -> tuple[set[str], set[str], int]:
    """스캐너 JSON 의 경보 ID, 별칭까지 합친 ID, 경보 수. JSON 이 아니면 오류를 낸다(빈 결과를 「다 고침」 으로 읽지 않는다)."""
    ids, names, n = set(), set(), 0
    for res in json.loads(raw).get("results", []):
        for pk in res.get("packages", []):
            for v in pk.get("vulnerabilities", []):
                n += 1
                ids.add(v.get("id", ""))
                names.update([v.get("id", "")] + (v.get("aliases") or []))
    return ids, names, n


def report_section(res: dict) -> list[str]:
    """보고서에 붙일 조치안 검증 절."""
    fx = res["side_effects"]
    L = ["## 조치안 검증", "", "복사본에서 패키지별로 버전을 올려 빌드와 시험을 돌렸다. 코드 반영과 배포는 담당자가 한다.", "",
         "| 패키지 | 올린 버전 | 대상 CVE | 결과 |", "|---|---|---|---|"]
    for pkg, t in res["targets"].items():
        L.append(f"| {pkg} | {t['from']} > {t['version']} | {', '.join(t['cves'])} | {'반영' if pkg in res['accepted'] else '되돌림, 사람에게 넘김'} |")
    b, a = res["baseline"], res["after"]
    L += ["", f"- 시험: 고치기 전 통과 패키지 {b['ok_packages']}, 실패 시험 {len(b['failed_tests'])}. 고친 뒤 통과 패키지 {a['ok_packages']}, 실패 시험 {len(a['failed_tests'])}. 새 실패 {len(res['new_test_failures'])}건.",
          f"- 재스캔: 경보 {res['alerts_before']}건에서 {res['alerts_after']}건. 대상 취약점 {len(res['cves_fixed_targeted'])}건 중 남은 것 {len(res['cves_still_reported'])}건. 새로 생긴 경보 ID {len(res['alerts_new_ids'])}건."]
    if fx["go_directive"]:
        L.append(f"- 담당자 확인: Go 언어 버전이 {fx['go_directive'][0]}에서 {fx['go_directive'][1]}로 올라간다. CI와 컨테이너 이미지를 함께 올려야 한다.")
    if fx["also_changed"]:
        L.append("- 담당자 확인: 함께 올라가는 간접 의존성 " + ", ".join(f"{k} {v[0]} > {v[1]}" for k, v in sorted(fx["also_changed"].items())))
    return L + [""]


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
            return {"args": " ".join(args)[:120], "exit": r.returncode, "seconds": round(time.time() - t0, 1), "out": r.stdout + r.stderr, "stdout": r.stdout}
        except subprocess.TimeoutExpired:
            return {"args": " ".join(args)[:120], "exit": -9, "seconds": round(time.time() - t0, 1), "out": "시간 초과", "stdout": ""}

    def packages(self):
        r = self.go(["list", "./..."], 300)
        # 표준 출력만 읽는다. 표준 오류의 「go: downloading x v0.3.0」 이 패키지로 섞이면 안 된다
        return [p.strip() for p in r["stdout"].splitlines() if p.strip() and "/integration" not in p]

    def test(self, pkgs, timeout):
        r = self.go(["test", "-short", "-count=1", *pkgs], timeout)
        return {"exit": r["exit"], "seconds": r["seconds"], **parse_go_test(r["out"]), "tail": r["out"][-700:]}


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
    base_test = w.test(pkgs, a.test_timeout) if base_build["exit"] == 0 else {"exit": -1, "failed_packages": [], "failed_tests": [], "ok_packages": 0, "seconds": 0, "tail": base_build["out"][-500:]}
    print("고치기 전 빌드", base_build["exit"], "시험", base_test["exit"], "통과 패키지", base_test["ok_packages"], "실패", base_test["failed_packages"][:5], base_test["failed_tests"][:5], flush=True)
    accepted, rejected = [], []
    for pkg, t in sorted(targets.items(), key=lambda kv: (order[kv[1]["decision"]], kv[0])):
        g = w.go(["get", f"{pkg}@{t['version']}"], 300)
        tidy = w.go(["mod", "tidy"], 300) if g["exit"] == 0 else {"exit": 1, "out": ""}
        b = w.go(["build", *pkgs], 1200) if tidy["exit"] == 0 else {"exit": 1, "out": tidy["out"]}
        tried = w.test(pkgs, a.test_timeout) if g["exit"] == 0 and tidy["exit"] == 0 and b["exit"] == 0 else None
        broke = new_failures(base_test, tried) if tried else []
        if tried and not broke:
            w.git("add", "-A")
            w.git("-c", "user.name=agent", "-c", "user.email=agent@local", "commit", "-qm", f"bump {pkg} {t['version']}")
            accepted.append(pkg)
            print("적용", pkg, t["version"], flush=True)
        else:
            w.git("checkout", "--", ".")
            w.git("clean", "-fdq")
            reason = "새 시험 실패: " + ", ".join(broke[:8]) if broke else (g["out"] if g["exit"] else (tidy["out"] if tidy["exit"] else b["out"]))[-400:]
            rejected.append({"package": pkg, "version": t["version"], "cves": t["cves"], "reason": reason})
            print("되돌림", pkg, t["version"], reason[-120:].replace("\n", " "), flush=True)
    after_test = w.test(pkgs, a.test_timeout)
    still_broken = new_failures(base_test, after_test)
    mod_before = w.git("show", f"HEAD~{len(accepted)}:go.mod").stdout
    effects = side_effects(mod_before, (w.dir / "go.mod").read_text(encoding="utf-8"), set(accepted))
    diff = w.git("diff", "HEAD~%d" % len(accepted), "--", "go.mod").stdout if accepted else ""
    full = w.git("diff", "HEAD~%d" % len(accepted)).stdout if accepted else ""
    (out / "fix.patch").write_text(full, encoding="utf-8")
    bom2 = out / "bom_after.cdx.json"
    subprocess.run([str(ROOT / "tools" / "syft"), "scan", f"dir:{w.dir}", "-o", f"cyclonedx-json={bom2}", "-q"], capture_output=True, timeout=600)
    r = subprocess.run([str(ROOT / "tools" / "osv-scanner"), "scan", "source", "-L", str(bom2), "--format", "json"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    ids_after, still, raw_after = alert_ids(r.stdout)
    ids_before, _, _ = alert_ids((out / "scan.json").read_text(encoding="utf-8"))
    wanted = sorted({c for p in accepted for c in targets[p]["cves"]})
    before = json.loads((out / "scan_counts.json").read_text(encoding="utf-8"))["raw_alerts"]
    result = {
        "targets": targets, "accepted": accepted, "rejected": rejected, "prerelease_only": prerelease_only,
        "baseline": {"build": base_build["exit"], "test_exit": base_test["exit"], "ok_packages": base_test["ok_packages"], "failed_packages": base_test["failed_packages"], "failed_tests": base_test["failed_tests"]},
        "after": {"test_exit": after_test["exit"], "ok_packages": after_test["ok_packages"], "failed_packages": after_test["failed_packages"], "failed_tests": after_test["failed_tests"], "seconds": after_test["seconds"]},
        "new_test_failures": still_broken, "side_effects": effects, "cves_fixed_targeted": wanted, "cves_still_reported": [c for c in wanted if c in still],
        "alerts_before": before, "alerts_after": raw_after, "alerts_new_ids": sorted(ids_after - ids_before), "go_mod_diff": diff[:3000],
    }
    (out / "remediation.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    rep = out / "report.md"
    if rep.exists():
        head = rep.read_text(encoding="utf-8").split("## 조치안 검증")[0].rstrip()
        rep.write_text(head + "\n\n" + "\n".join(report_section(result)), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in ("targets", "go_mod_diff", "rejected")}, ensure_ascii=False)[:1500], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
