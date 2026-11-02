"""닫은 판단을 언제 다시 볼지 정한다. 모델을 쓰지 않는다.

    python3 agent/recheck.py <저장소> --out out/<이름> [--online]

닫을 때 남긴 근거(인용한 파일과 의존성 파일의 해시, 권고문 수정일, KEV 여부)를 지금 상태와 대조해, 달라진 건을 다시 판단 목록으로 낸다.
--online 이면 OSV 의 권고문 수정일과 CISA KEV 를 새로 받아 비교한다. 결과는 recheck.json 이다.
"""
from __future__ import annotations

import argparse, hashlib, json, pathlib, sys, urllib.error, urllib.request

MANIFESTS = ("go.mod", "go.sum", "requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock", "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock")


def file_hash(path: pathlib.Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return None


def basis_of(repo: pathlib.Path, objs: list, f: dict) -> dict:
    """닫을 때의 근거 상태."""
    paths = {m for m in MANIFESTS if (repo / m).is_file()}
    for o in objs:
        if isinstance(o, dict):
            for e in o.get("evidence") or []:
                if isinstance(e, dict) and e.get("path"):
                    paths.add(str(e["path"]).replace("\\", "/"))
    return {"version": f.get("version"), "advisory_modified": f.get("modified"), "kev": bool(f.get("kev")), "files": {p: file_hash(repo / p) for p in sorted(paths)}}


def changed(repo: pathlib.Path, basis: dict, advisory_modified: str | None = None, kev_now: bool | None = None) -> list[str]:
    """다시 판단해야 하는 이유. 비어 있으면 그대로 둔다."""
    why = [f"근거 파일 변경: {p}" for p, h in (basis.get("files") or {}).items() if file_hash(repo / p) != h]
    if advisory_modified and basis.get("advisory_modified") and advisory_modified > basis["advisory_modified"]:
        why.append(f"권고문 수정: {basis['advisory_modified']} 이후 {advisory_modified}")
    if kev_now and not basis.get("kev"):
        why.append("실제 악용 목록(KEV)에 새로 올라옴")
    return why


def osv_modified(ids: list[str]) -> str | None:
    best = None
    for i in ids:
        try:
            req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{i}", headers={"User-Agent": "recheck"})
            with urllib.request.urlopen(req, timeout=30) as r:
                m = json.load(r).get("modified")
        except (urllib.error.URLError, ValueError):
            continue
        if m and (best is None or m > best):
            best = m
    return best


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--out", required=True)
    ap.add_argument("--online", action="store_true")
    a = ap.parse_args()
    repo, out = pathlib.Path(a.repo).resolve(), pathlib.Path(a.out).resolve()
    decisions = json.loads((out / "decisions.json").read_text(encoding="utf-8"))
    findings = {f["id"]: f for f in json.loads((out / "findings.json").read_text(encoding="utf-8"))}
    kev = {}
    if a.online:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        from pipeline import load_kev

        kev = load_kev()
    rows = []
    closed = [d for d in decisions.values() if d["decision"] == "CLOSE"]
    for d in closed:
        f = findings.get(d["id"], {})
        mod = osv_modified(f.get("ids") or [d["cve"]]) if a.online else None
        why = changed(repo, d.get("basis") or {}, mod, any(i in kev for i in f.get("ids") or []) if a.online else None)
        if why:
            rows.append({"id": d["id"], "cve": d["cve"], "package": d["package"], "why": why})
    (out / "recheck.json").write_text(json.dumps({"closed": len(closed), "recheck": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"닫은 {len(closed)}건 중 다시 판단 {len(rows)}건")
    for r in rows[:20]:
        print(" ", r["package"], r["cve"], "|", "; ".join(r["why"])[:140])
    return 0


if __name__ == "__main__":
    sys.exit(main())
