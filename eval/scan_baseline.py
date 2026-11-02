"""스캐너 단독 기준선. syft 로 SBOM 을 만들고 osv-scanner 로 스캔해 그 CVE 가 보고되면 exploitable 로 친다. LLM 없음.

    python eval/scan_baseline.py [--limit N]

결과: results/sbom/<폴더>.cdx.json, results/scanner_osv/<폴더>.json, 요약 results/scanner_osv/summary.json
OSV 응답은 오늘 기준이다(과거 시점 재현 아님). 메모리 바닥(가용 2.5GB) 아래면 기다린다.
함정: osv-scanner 2.7.0 의 `scan source -r <폴더>` 는 윈도우에서 C:\\ 한 칸만 걷고 종료 128 로 끝난다. -L 로 파일을 직접 준다.
"""
import argparse, json, os, pathlib, subprocess, sys, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex_run

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "scanner_osv"
BOM = ROOT / "results" / "sbom"
OUT.mkdir(parents=True, exist_ok=True)
BOM.mkdir(parents=True, exist_ok=True)
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0
BELOW_NORMAL = 0x00004000 if IS_WIN else 0
SUFFIX = ".exe" if IS_WIN else ""
OSV = ROOT / "tools" / f"osv-scanner{SUFFIX}"
SYFT = ROOT / "tools" / f"syft{SUFFIX}"


def run(cmd, stdout, stderr, timeout, cwd=None, env=None):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=stdout, stderr=stderr, creationflags=NO_WINDOW | BELOW_NORMAL, env=env)
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if IS_WIN:
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, creationflags=NO_WINDOW)
        else:
            p.kill()
        return -9


def ids_in(report: dict) -> set[str]:
    found = set()
    for res in report.get("results", []):
        for pk in res.get("packages", []):
            for v in pk.get("vulnerabilities", []):
                found.add(v.get("id", ""))
                found.update(v.get("aliases") or [])
    return found


ap = argparse.ArgumentParser()
ap.add_argument("--limit", type=int, default=0)
a = ap.parse_args()
tasks = vex_run.tasks()
dirs = sorted({vex_run.repo_dir(t) for t in tasks}, key=lambda p: p.name)
if a.limit:
    dirs = dirs[: a.limit]
stats = {}
for d in dirs:
    fo = OUT / f"{d.name}.json"
    if fo.exists() and fo.stat().st_size > 0:
        continue
    while vex_run.avail_mb() < 2600:
        print("RAM 바닥, 대기", flush=True)
        time.sleep(60)
    t0 = time.time()
    bom = BOM / f"{d.name}.cdx.json"
    with (OUT / f"{d.name}.syft.err.txt").open("w", encoding="utf-8") as err:
        c1 = run([str(SYFT), "scan", f"dir:{d}", "-o", f"cyclonedx-json={bom}", "-q"], subprocess.DEVNULL, err, 420)
    with fo.open("w", encoding="utf-8") as out, (OUT / f"{d.name}.err.txt").open("w", encoding="utf-8") as err:
        c2 = run([str(OSV), "scan", "source", "-L", str(bom), "--format", "json"], out, err, 420)
    stats[d.name] = {"syft": c1, "osv": c2, "seconds": round(time.time() - t0, 1), "bom_bytes": bom.stat().st_size if bom.exists() else 0}
    print(d.name, stats[d.name], flush=True)
preds = {}
for t in tasks:
    fo = OUT / f"{vex_run.repo_dir(t).name}.json"
    if not fo.exists():
        continue
    try:
        rep = json.loads(fo.read_text(encoding="utf-8"))
    except ValueError:
        preds[t["task_id"]] = None
        continue
    preds[t["task_id"]] = t["cve_id"] in ids_in(rep)
prev = OUT / "summary.json"
if prev.exists():
    old = json.loads(prev.read_text(encoding="utf-8")).get("stats", {})
    stats = old | stats
prev.write_text(json.dumps({"preds": preds, "stats": stats}, ensure_ascii=False, indent=0), encoding="utf-8")
print("완료", len(preds), "보고됨", sum(1 for v in preds.values() if v), "실패", sum(1 for v in preds.values() if v is None), flush=True)
