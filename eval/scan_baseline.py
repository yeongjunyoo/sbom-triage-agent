"""스캐너 단독 기준선. 저장소를 osv-scanner 로 스캔해 그 CVE 가 보고되면 exploitable 로 친다. LLM 없음.

    python eval/scan_baseline.py [--limit N]

결과: results/scanner_osv/<폴더>.json, 요약 results/scanner_osv/summary.json
OSV 응답은 오늘 기준이다(과거 시점 재현 아님). 메모리 바닥(가용 2.5GB) 아래면 기다린다.
"""
import argparse, json, pathlib, subprocess, sys, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex_run

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "scanner_osv"
OUT.mkdir(parents=True, exist_ok=True)
EXE = ROOT / "tools" / "osv-scanner.exe"
NO_WINDOW = 0x08000000
BELOW_NORMAL = 0x00004000


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
    if not fo.exists():
        while vex_run.avail_mb() < 2600:
            print("RAM 바닥, 대기", flush=True)
            time.sleep(60)
        t0 = time.time()
        with fo.open("w", encoding="utf-8") as out, (OUT / f"{d.name}.err.txt").open("w", encoding="utf-8") as err:
            p = subprocess.Popen([str(EXE), "scan", "source", "-r", "--format", "json", "."], cwd=str(d), stdout=out, stderr=err, creationflags=NO_WINDOW | BELOW_NORMAL)
            try:
                code = p.wait(timeout=420)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, creationflags=NO_WINDOW)
                code = -9
        stats[d.name] = {"exit": code, "seconds": round(time.time() - t0, 1)}
        print(d.name, code, stats[d.name]["seconds"], flush=True)
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
(OUT / "summary.json").write_text(json.dumps({"preds": preds, "stats": stats}, ensure_ascii=False, indent=0), encoding="utf-8")
print("완료", len(preds), "보고됨", sum(1 for v in preds.values() if v), "실패", sum(1 for v in preds.values() if v is None), flush=True)
