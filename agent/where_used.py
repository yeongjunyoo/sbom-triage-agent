"""그룹 SBOM 역조회: 새 취약점이 터졌을 때 어느 자산에 어느 버전이 있는지 SBOM 묶음에서 찾는다. 모델을 쓰지 않는다.

    python3 agent/where_used.py <SBOM 폴더> --cve CVE-2021-44228 [--json out.json]
    python3 agent/where_used.py <SBOM 폴더> --package log4j-core

CVE 를 주면 OSV 에서 영향 패키지와 영향 버전 목록을 받아 대조한다. 코드를 읽지 않으므로 「있다」 까지만 답하고, 쓰이는지는 판단 단계가 본다.
"""
from __future__ import annotations

import argparse, json, pathlib, re, sys, time, urllib.error, urllib.request


def components(path: pathlib.Path) -> list[dict]:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return []
    return d.get("components") or []


def purl_name(c: dict) -> str:
    """purl 의 생태계를 뺀 이름. pkg:maven/org.apache.logging.log4j/log4j-core@2.14 는 org.apache.logging.log4j:log4j-core."""
    p = str(c.get("purl") or "")
    if not p.startswith("pkg:") or "/" not in p:
        return str(c.get("name") or "")
    kind, _, rest = p[4:].partition("/")
    rest = rest.split("@")[0].split("?")[0]
    return rest.replace("/", ":") if kind == "maven" else rest


def osv_get(vuln_id: str) -> dict:
    req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{vuln_id}", headers={"User-Agent": "where-used"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError:
        return {}


def osv_affected(cve: str) -> list[dict]:
    """CVE 레코드에는 패키지가 비어 있을 때가 많아 별칭(GHSA, GO)까지 따라가 합친다."""
    first = osv_get(cve)
    records = [first] + [osv_get(a) for a in first.get("aliases") or [] if a.startswith(("GHSA-", "GO-", "PYSEC-"))]
    out = []
    for d in records:
        for a in d.get("affected") or []:
            pkg = a.get("package") or {}
            if pkg.get("name"):
                ranges = []
                for rg in a.get("ranges") or []:
                    if rg.get("type") in ("SEMVER", "ECOSYSTEM"):
                        intro = None
                        for ev in rg.get("events") or []:
                            if "introduced" in ev:
                                intro = ev["introduced"]
                            elif "fixed" in ev and intro is not None:
                                ranges.append((intro, ev["fixed"]))
                                intro = None
                        if intro is not None:
                            ranges.append((intro, None))
                out.append({"name": pkg["name"], "ecosystem": pkg.get("ecosystem", ""), "versions": set(a.get("versions") or []), "ranges": ranges})
    return out


def ver_key(v: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", v.split("+")[0].split("-")[0])[:4]] or [0]


def in_ranges(v: str, ranges: list[tuple]) -> bool:
    k = ver_key(v)
    return any(ver_key(i) <= k and (f is None or k < ver_key(f)) for i, f in ranges)


def find(folder: pathlib.Path, names: dict[str, dict] | None, needle: str | None) -> list[dict]:
    hits = []
    for f in sorted(folder.glob("*.json")):
        for c in components(f):
            n, v = purl_name(c), str(c.get("version") or "").lstrip("v")
            if needle is not None:
                if needle.lower() not in n.lower():
                    continue
                affected = None
            else:
                if n not in names:
                    continue
                known = names[n]
                # 버전을 못 읽은 구성요소는 빼지 않고 「확인 필요」 로 남긴다
                if v in ("", "UNKNOWN") or not (known["versions"] or known["ranges"]):
                    affected = None
                else:
                    affected = v in known["versions"] or in_ranges(v, known["ranges"])
                if affected is False:
                    continue
            hits.append({"asset": f.name.replace(".cdx.json", ""), "package": n, "version": v, "affected": affected})
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--cve", default="")
    ap.add_argument("--package", default="")
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    folder = pathlib.Path(a.folder)
    t0 = time.time()
    names = None
    if a.cve:
        names = {}
        for x in osv_affected(a.cve):
            e = names.setdefault(x["name"], {"versions": set(), "ranges": []})
            e["versions"].update(v.lstrip("v") for v in x["versions"])
            e["ranges"].extend(x["ranges"])
    hits = find(folder, names, a.package or None)
    assets = sorted({h["asset"] for h in hits})
    confirmed = sorted({h["asset"] for h in hits if h["affected"]})
    res = {"query": a.cve or a.package, "sboms": len(list(folder.glob("*.json"))), "assets": len(assets), "assets_affected_version": len(confirmed), "hits": len(hits), "seconds": round(time.time() - t0, 2), "packages": sorted(names) if names else None, "rows": hits}
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{res['query']}: SBOM {res['sboms']}개 중 {res['assets']}개 자산(영향 버전 확인 {res['assets_affected_version']}개), {res['hits']}건, {res['seconds']}초")
    for h in hits[:40]:
        print(f"  {h['asset']}  {h['package']} {h['version']} " + ("버전 확인 필요" if h["affected"] is None else "영향 버전"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
