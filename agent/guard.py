"""닫는 근거가 사람이 쓴 설명에 기대면 자동으로 닫지 않는다.

저장소 안의 글은 누구나 쓸 수 있다. 「보안팀이 봤다」 는 문장은 코드가 아니므로, 그 문장을 인용했다면 인용이 정확해도 근거가 아니다.
- 문서 파일이나 주석 줄을 인용한 근거는 세지 않는다.
- 인용한 근거가 있어야 하는 범주인데 코드 근거가 하나도 남지 않으면 사람 검토로 보낸다.
- 저장소가 이 CVE 번호를 스스로 언급하면(변경 기록과 잠금 파일 제외) 사람 검토로 보낸다.
"""
from __future__ import annotations

import functools, pathlib, re, shutil, subprocess

RG = shutil.which("rg") or "/opt/homebrew/bin/rg"
DOC_SUFFIX = {".md", ".rst", ".txt", ".adoc", ".html", ".htm", ".org"}
DOC_NAME = {"readme", "security", "notes", "license", "contributing"}
COMMENT = re.compile(r"^\s*(//|#(?!include|define|if|!)|/\*|\*|<!--|--|;|%)")
NOT_CLAIMS = re.compile(r"(^|/)(changelog|changes|history|news|release[-_ ]?notes)[^/]*$|\.(lock|sum)$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock)$", re.I)
JSON_NOTE = re.compile(r'^\s*"//"\s*:')


def is_prose(path: str, quote: str) -> bool:
    p = pathlib.PurePosixPath(str(path).replace("\\", "/"))
    if p.suffix.lower() in DOC_SUFFIX and not p.name.lower().startswith("requirements"):
        return True
    if p.stem.lower() in DOC_NAME:
        return True
    return bool(COMMENT.match(str(quote))) or bool(JSON_NOTE.match(str(quote)))


@functools.lru_cache(maxsize=4096)
def mentions_of(repo: pathlib.Path, cve: str) -> list[str]:
    """저장소에서 이 CVE 번호를 쓴 파일. 변경 기록과 잠금 파일은 뺀다."""
    r = subprocess.run([RG, "-l", "-F", "--no-messages", "--hidden", "--no-ignore", "-g", "!.git", cve, str(repo)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"rg 실패 {r.returncode}: {r.stderr[:200]}")
    rel = [str(pathlib.Path(x).relative_to(repo)).replace("\\", "/") for x in r.stdout.splitlines() if x.strip()]
    return [x for x in rel if not NOT_CLAIMS.search(x)]


def evidence_guard(obj: dict, repo: pathlib.Path, cve: str) -> list[str]:
    """자동으로 닫으면 안 되는 이유. 비어 있으면 통과."""
    reasons = []
    ev = [e for e in (obj.get("evidence") or []) if isinstance(e, dict)]
    prose = [e for e in ev if is_prose(e.get("path", ""), e.get("quote", ""))]
    if prose:
        reasons.append("사람이 쓴 글을 근거로 인용: " + ", ".join(sorted({str(e.get("path")) for e in prose})[:3]))
    named = mentions_of(repo, cve)
    if named:
        reasons.append("저장소가 이 CVE 를 언급: " + ", ".join(named[:3]))
    return reasons
