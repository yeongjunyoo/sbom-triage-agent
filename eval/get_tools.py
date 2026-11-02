"""스캐너와 검색 도구를 고정 버전으로 받는다. Trivy 사고 뒤라 태그 이름을 믿지 않고 체크섬을 대조한다.

    python eval/get_tools.py        # tools/ 에 받고 manifest.json 에 버전과 SHA256 을 남긴다
"""
import hashlib, io, json, pathlib, re, urllib.request, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
TOOLS.mkdir(exist_ok=True)
UA = {"User-Agent": "lotte-ax-supplychain"}

SPEC = [
    {"name": "rg", "url": "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip",
     "sum_url": "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip.sha256", "member": "rg.exe"},
    {"name": "osv-scanner", "url": "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_windows_amd64.exe",
     "sum_url": "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_SHA256SUMS", "member": None},
    {"name": "syft", "url": "https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_windows_amd64.zip",
     "sum_url": "https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_checksums.txt", "member": "syft.exe"},
    {"name": "grype", "url": "https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_windows_amd64.zip",
     "sum_url": "https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_checksums.txt", "member": "grype.exe"},
]


def get(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=300).read()


def parse_sum(raw: bytes, fname: str) -> str | None:
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*").endswith(fname):
            return parts[0].lower()
    hexes = re.findall(r"(?i)\b[0-9a-f]{64}\b", text)
    return hexes[0].lower() if len(hexes) == 1 else None


manifest = {}
for s in SPEC:
    data = get(s["url"])
    digest = hashlib.sha256(data).hexdigest()
    fname = s["url"].rsplit("/", 1)[-1]
    expected = parse_sum(get(s["sum_url"]), fname)
    if expected != digest:
        raise SystemExit(f"{s['name']} 체크섬 불일치 expected={expected} got={digest}")
    out = TOOLS / f"{s['name']}.exe"
    if s["member"]:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            name = next(n for n in z.namelist() if n.endswith(s["member"]))
            out.write_bytes(z.read(name))
    else:
        out.write_bytes(data)
    manifest[s["name"]] = {"url": s["url"], "sha256": digest, "size": len(data)}
    print(s["name"], "ok", len(data))
(TOOLS / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
