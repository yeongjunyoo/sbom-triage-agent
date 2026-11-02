"""SW 공급망 스캐닝 에이전트 시제품.

스캐너를 새로 만들지 않는다. 시중 도구 결과 위에서 위험한 것만 근거와 함께 추리고, 조치안과 기록을 남긴다.

    python3 agent/pipeline.py run <저장소> --out out/<이름> [--asset assets.json] [--top 40] [--model claude-sonnet-5-5]

단계와 산출물
  1. sbom     syft 로 CycloneDX SBOM                     bom.cdx.json
  2. scan     osv-scanner 로 취약점 대조                 scan.json, findings.json
  3. enrich   KEV, EPSS 결합. 규칙으로 우선순위          findings.json
  4. triage   격리된 에이전트가 코드를 읽어 판단          triage/<id>.json
  5. verify   인용과 검색을 스크립트로 재현              decisions.json
  6. review   닫는 판단만 두 번째 독립 검토              review/<id>.json
  7. output   OpenVEX, 사람 검토 목록, 보고서            vex.json, report.md, audit.jsonl
모델이 실패하면 조용히 넘어가지 않고 REVIEW 로 떨어진다. 코드 수정 권한은 에이전트에게 없다.
"""
from __future__ import annotations

import argparse, csv, datetime as dt, gzip, io, json, os, pathlib, signal, subprocess, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
from verify import parse_obj, verify  # noqa: E402

IS_WIN = os.name == "nt"
SUFFIX = ".exe" if IS_WIN else ""
NO_WINDOW = 0x08000000 if IS_WIN else 0
TOOLS = ROOT / "tools"
CACHE = ROOT / "results" / "feeds"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
CLOSE_CATS = {
    "false_positive", "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
    "requires_environment", "compiler_protected", "runtime_protected", "perimeter_protected", "mitigating_control_protected",
}
VEX_JUSTIFICATION = {
    "false_positive": "component_not_present",
    "code_not_present": "component_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "vulnerable_code_not_in_execute_path",
    "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
    "compiler_protected": "inline_mitigations_already_exist",
    "runtime_protected": "inline_mitigations_already_exist",
    "perimeter_protected": "inline_mitigations_already_exist",
    "mitigating_control_protected": "inline_mitigations_already_exist",
}


def log(audit: pathlib.Path, step: str, **kw) -> None:
    rec = {"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "step": step} | kw
    with audit.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def run_cmd(cmd, stdout=None, stderr=None, timeout=600, cwd=None, env=None, stdin_text=None):
    p = subprocess.Popen(
        cmd, cwd=cwd, stdout=stdout or subprocess.DEVNULL, stderr=stderr or subprocess.DEVNULL,
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        creationflags=NO_WINDOW, start_new_session=not IS_WIN, env=env, text=True, encoding="utf-8",
    )
    if stdin_text is not None:
        try:
            p.stdin.write(stdin_text)
            p.stdin.close()
        except OSError:
            pass
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if IS_WIN:
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, creationflags=NO_WINDOW)
        else:
            os.killpg(p.pid, signal.SIGKILL)
        return -9


def fetch_cached(url: str, name: str, max_age_h: int = 24) -> bytes:
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / name
    if p.exists() and time.time() - p.stat().st_mtime < max_age_h * 3600:
        return p.read_bytes()
    data = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=120).read()
    p.write_bytes(data)
    return data


def load_kev() -> dict:
    d = json.loads(fetch_cached(KEV_URL, "kev.json"))
    return {v["cveID"]: v for v in d["vulnerabilities"]}


def load_epss() -> tuple[dict, str]:
    for back in range(1, 6):
        day = (dt.date.today() - dt.timedelta(days=back)).isoformat()
        try:
            raw = fetch_cached(EPSS_URL.format(d=day), f"epss_{day}.csv.gz", 24 * 7)
        except Exception:
            continue
        lines = [l for l in gzip.decompress(raw).decode().splitlines() if not l.startswith("#")]
        return {r["cve"]: float(r["epss"]) for r in csv.DictReader(io.StringIO("\n".join(lines)))}, day
    return {}, ""


def step_sbom(repo: pathlib.Path, out: pathlib.Path) -> pathlib.Path:
    bom = out / "bom.cdx.json"
    if not bom.exists():
        code = run_cmd([str(TOOLS / f"syft{SUFFIX}"), "scan", f"dir:{repo}", "-o", f"cyclonedx-json={bom}", "-q"], timeout=600)
        if code != 0:
            raise SystemExit(f"syft 실패 {code}")
    return bom


def fixed_versions(vuln: dict, pkg: str) -> list[str]:
    out = []
    for a in vuln.get("affected", []):
        if a.get("package", {}).get("name") != pkg:
            continue
        for r in a.get("ranges", []):
            for ev in r.get("events", []):
                if ev.get("fixed"):
                    out.append(ev["fixed"])
    return sorted(set(out))


def step_scan(bom: pathlib.Path, out: pathlib.Path) -> list[dict]:
    rep_path = out / "scan.json"
    if not rep_path.exists():
        with rep_path.open("w", encoding="utf-8") as fo:
            code = run_cmd([str(TOOLS / f"osv-scanner{SUFFIX}"), "scan", "source", "-L", str(bom), "--format", "json"], stdout=fo, timeout=600)
        if code not in (0, 1):
            raise SystemExit(f"osv-scanner 실패 {code}")
    rep = json.loads(rep_path.read_text(encoding="utf-8"))
    seen, findings, raw_alerts = {}, [], 0
    for res in rep.get("results", []):
        for pk in res.get("packages", []):
            info = pk.get("package", {})
            sev = {}
            for g in pk.get("groups", []):
                for i in g.get("ids", []):
                    sev[i] = g.get("max_severity")
            for v in pk.get("vulnerabilities", []):
                raw_alerts += 1
                ids = [v.get("id", "")] + (v.get("aliases") or [])
                cve = next((i for i in ids if i.startswith("CVE-")), v.get("id"))
                key = (info.get("name"), cve)
                f = seen.get(key)
                if f is None:
                    f = {
                        "id": f"{str(info.get('name')).replace('/', '_').replace(':', '_')}__{cve}", "package": info.get("name"), "version": info.get("version"),
                        "ecosystem": info.get("ecosystem"), "cve": cve, "ids": sorted(set(ids)), "summary": (v.get("summary") or "")[:200], "fixed": [], "cvss": None,
                    }
                    seen[key] = f
                    findings.append(f)
                f["fixed"] = sorted(set(f["fixed"] + fixed_versions(v, info.get("name"))))
                s = next((sev[i] for i in ids if sev.get(i)), None)
                try:
                    f["cvss"] = max(float(s), f["cvss"] or 0) if s else f["cvss"]
                except ValueError:
                    pass
    (out / "scan_counts.json").write_text(json.dumps({"raw_alerts": raw_alerts, "unique": len(findings)}), encoding="utf-8")
    return findings


def step_enrich(findings: list[dict], asset: dict) -> tuple[list[dict], dict]:
    kev, (epss, epss_day) = load_kev(), load_epss()
    internet = bool(asset.get("internet_facing"))
    for f in findings:
        f["kev"] = any(i in kev for i in f["ids"])
        f["epss"] = max((epss.get(i, 0.0) for i in f["ids"]), default=0.0)
        f["epss_known"] = any(i in epss for i in f["ids"])
        # 규칙으로 되는 판정은 규칙으로. LLM 은 순서를 정하지 않는다.
        if f["kev"]:
            f["tier"] = 1
        elif f["epss"] >= 0.1 or ((f["cvss"] or 0) >= 9.0 and internet):
            f["tier"] = 2
        elif (f["cvss"] or 0) >= 7.0 or not f["epss_known"]:
            f["tier"] = 3
        else:
            f["tier"] = 4
    findings.sort(key=lambda f: (f["tier"], -f["epss"], -(f["cvss"] or 0), f["id"]))
    return findings, {"kev_total": len(kev), "epss_day": epss_day}


def claude(prompt: str, cwd: pathlib.Path, raw: pathlib.Path, model: str, effort: str, timeout: int) -> dict:
    env = dict(os.environ)
    tok = pathlib.Path.home() / ".nova" / "claude_oauth_token"
    if not IS_WIN and tok.exists():
        env["CLAUDE_CODE_OAUTH_TOKEN"] = tok.read_text().strip()
    exe = str(pathlib.Path.home() / ".local" / "bin" / f"claude{SUFFIX}")
    cmd = [
        exe, "-p", "--model", model, "--effort", effort, "--restricted", "--safe-mode", "--strict-mcp-config",
        "--permission-mode", "dontAsk", "--tools", "Read,Grep,Glob,WebSearch,WebFetch", "--allowedTools", "WebSearch", "WebFetch",
        "--no-session-persistence", "--output-format", "stream-json", "--verbose",
    ]
    t0 = time.time()
    with raw.open("w", encoding="utf-8") as fo:
        code = run_cmd(cmd, stdout=fo, cwd=str(cwd), env=env, timeout=timeout, stdin_text=prompt)
    final, cost, tools = None, None, 0
    for line in raw.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") == "assistant":
            tools += sum(1 for c in ev.get("message", {}).get("content", []) if c.get("type") == "tool_use")
        if ev.get("type") == "result":
            final, cost = ev.get("result"), ev.get("total_cost_usd")
    return {"exit": code, "text": final, "cost": cost, "seconds": round(time.time() - t0, 1), "tool_calls": tools}


def triage_one(f: dict, repo: pathlib.Path, out: pathlib.Path, a) -> dict:
    tdir, rdir = out / "triage", out / "review"
    tdir.mkdir(exist_ok=True)
    rdir.mkdir(exist_ok=True)
    meta = tdir / f"{f['id']}.json"
    if meta.exists():
        m = json.loads(meta.read_text(encoding="utf-8"))
    else:
        prompt = (ROOT / "eval/prompts" / f"{a.triage_prompt}.md").read_text(encoding="utf-8").replace("{cve_id}", f["cve"])
        m = claude(prompt, repo, tdir / f"{f['id']}.stream.jsonl", a.model, a.effort, a.timeout)
        meta.write_text(json.dumps(m, ensure_ascii=False), encoding="utf-8")
    o = parse_obj(m.get("text"))
    cat = o.get("category") if isinstance(o, dict) else None
    v = verify(o, repo)
    d = {"id": f["id"], "cve": f["cve"], "package": f["package"], "category": cat, "verify_ok": v["ok"], "verify_fails": v["fails"], "reasoning": (o or {}).get("reasoning") if isinstance(o, dict) else None,
         "evidence": (o or {}).get("evidence", [])[:6] if isinstance(o, dict) else [], "advisory": (o or {}).get("advisory") if isinstance(o, dict) else None, "cost": m.get("cost") or 0, "seconds": m.get("seconds")}
    if cat == "vulnerable":
        d["decision"], d["why"] = "OPEN", "코드에서 쓰임이 확인됨" + ("" if v["ok"] else " (근거 검사 실패 표시)")
    elif cat not in CLOSE_CATS:
        d["decision"], d["why"] = "REVIEW", "판단 불가" if cat else "모델 응답 없음"
    elif not v["ok"]:
        d["decision"], d["why"] = "REVIEW", "근거 검사 실패: " + "; ".join(v["fails"][:2])
    else:
        rmeta = rdir / f"{f['id']}.json"
        if rmeta.exists():
            r = json.loads(rmeta.read_text(encoding="utf-8"))
        else:
            prompt = (ROOT / "eval/prompts" / f"{a.review_prompt}.md").read_text(encoding="utf-8").replace("{cve_id}", f["cve"]).replace("{prior}", m.get("text") or "")
            r = claude(prompt, repo, rdir / f"{f['id']}.stream.jsonl", a.model, a.effort, a.timeout)
            rmeta.write_text(json.dumps(r, ensure_ascii=False), encoding="utf-8")
        ro = parse_obj(r.get("text"))
        vd = ro.get("verdict") if isinstance(ro, dict) else None
        d["review"] = {"verdict": vd, "reason": (ro or {}).get("reason") if isinstance(ro, dict) else None}
        d["cost"] += r.get("cost") or 0
        if vd == "uphold":
            d["decision"], d["why"] = "CLOSE", cat
        else:
            d["decision"], d["why"] = "REVIEW", f"두 번째 검토 결과 {vd}"
    return d


def write_vex(findings: list[dict], decisions: dict, out: pathlib.Path, product: str) -> None:
    stmts = []
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    for f in findings:
        d = decisions.get(f["id"])
        purl = f"pkg:{str(f['ecosystem']).lower()}/{f['package']}@{f['version']}"
        s = {"vulnerability": {"name": f["cve"], "aliases": [i for i in f["ids"] if i != f["cve"]]}, "products": [{"@id": product, "subcomponents": [{"@id": purl}]}], "timestamp": now}
        if d is None:
            s["status"] = "under_investigation"
            s["status_notes"] = "우선순위 예산 밖이라 아직 판단하지 않음"
        elif d["decision"] == "CLOSE":
            s["status"] = "not_affected"
            s["justification"] = VEX_JUSTIFICATION[d["category"]]
            s["impact_statement"] = (d.get("reasoning") or "")[:900]
        elif d["decision"] == "OPEN":
            s["status"] = "affected"
            s["action_statement"] = f"{f['package']} 를 {', '.join(f['fixed'][:2]) or '수정 버전'} 이상으로 올린다"
        else:
            s["status"] = "under_investigation"
            s["status_notes"] = d["why"]
        stmts.append(s)
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"urn:lotte-ax:{product}:{int(time.time())}", "author": "SW 공급망 스캐닝 에이전트 시제품", "timestamp": now, "version": 1, "statements": stmts}
    (out / "vex.json").write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")


def write_report(findings, decisions, counts, feeds, out, repo, components, wall) -> None:
    ds = list(decisions.values())
    n = {k: sum(1 for d in ds if d["decision"] == k) for k in ("OPEN", "REVIEW", "CLOSE")}
    cost = sum(d.get("cost") or 0 for d in ds)
    tiers = {t: sum(1 for f in findings if f["tier"] == t) for t in (1, 2, 3, 4)}
    L = [
        f"# SW 공급망 점검 보고서: {repo.name}", "",
        "| 단계 | 건수 |", "|---|---:|",
        f"| SBOM 구성요소 | {components} |", f"| 스캐너 경보(중복 포함) | {counts['raw_alerts']} |", f"| 패키지와 CVE 기준 고유 건 | {counts['unique']} |",
        f"| 규칙 등급 1 실제 악용(KEV) / 2 / 3 / 4 | {tiers[1]} / {tiers[2]} / {tiers[3]} / {tiers[4]} |",
        f"| 에이전트 판단 | {len(ds)} |", f"| 조치 대상 OPEN | {n['OPEN']} |", f"| 사람 검토 REVIEW | {n['REVIEW']} |", f"| 근거와 함께 닫음 CLOSE | {n['CLOSE']} |", "",
        f"소요 {wall/60:.1f}분, 모델 비용 환산 {cost:.2f}달러. KEV 판 {feeds['kev_total']}건, EPSS {feeds['epss_day']}.", "",
    ]
    for key, title in (("OPEN", "조치 대상"), ("REVIEW", "사람 검토 필요"), ("CLOSE", "근거와 함께 닫음")):
        L += [f"## {title}", "", "| 패키지 | 버전 | CVE | KEV | EPSS | 수정 버전 | 이유 |", "|---|---|---|---|---:|---|---|"]
        for f in findings:
            d = decisions.get(f["id"])
            if d and d["decision"] == key:
                L.append(f"| {f['package']} | {f['version']} | {f['cve']} | {'예' if f['kev'] else ''} | {f['epss']:.3f} | {', '.join(f['fixed'][:2])} | {str(d['why'])[:90]} |")
        L.append("")
    (out / "report.md").write_text("\n".join(L), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["run"])
    ap.add_argument("repo")
    ap.add_argument("--out", required=True)
    ap.add_argument("--asset", default="")
    ap.add_argument("--top", type=int, default=40, help="에이전트 판단 예산. 규칙 우선순위 상위 N 건")
    ap.add_argument("--model", default="claude-sonnet-5-5")
    ap.add_argument("--effort", default="high")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--parallel", type=int, default=6)
    ap.add_argument("--triage-prompt", default="triage_v1")
    ap.add_argument("--review-prompt", default="review_v1")
    a = ap.parse_args()
    repo = pathlib.Path(a.repo).resolve()
    out = pathlib.Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    audit = out / "audit.jsonl"
    asset = json.loads(pathlib.Path(a.asset).read_text(encoding="utf-8")) if a.asset else {}
    t0 = time.time()
    bom = step_sbom(repo, out)
    components = len(json.loads(bom.read_text(encoding="utf-8")).get("components", []))
    log(audit, "sbom", components=components)
    findings = step_scan(bom, out)
    counts = json.loads((out / "scan_counts.json").read_text(encoding="utf-8"))
    log(audit, "scan", **counts)
    findings, feeds = step_enrich(findings, asset)
    log(audit, "enrich", **feeds)
    (out / "findings.json").write_text(json.dumps(findings, ensure_ascii=False, indent=0), encoding="utf-8")
    picked = findings[: a.top]
    with ThreadPoolExecutor(a.parallel) as ex:
        res = list(ex.map(lambda f: triage_one(f, repo, out, a), picked))
    decisions = {d["id"]: d for d in res}
    for d in res:
        log(audit, "decision", id=d["id"], cve=d["cve"], decision=d["decision"], category=d["category"], verify_ok=d["verify_ok"], why=d["why"])
    (out / "decisions.json").write_text(json.dumps(decisions, ensure_ascii=False, indent=1), encoding="utf-8")
    write_vex(findings, decisions, out, repo.name)
    write_report(findings, decisions, counts, feeds, out, repo, components, time.time() - t0)
    print((out / "report.md").read_text(encoding="utf-8")[:900])
    return 0


if __name__ == "__main__":
    sys.exit(main())
