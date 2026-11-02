"""에이전트 판단의 근거를 스크립트로 검증한다. LLM 을 쓰지 않는다.

입력은 triage 결과 JSON 과 저장소 폴더. 출력은 검사 목록과 통과 여부.
- 인용 검사: path 가 있고, line 근처(앞뒤 3줄)에 quote 가 그대로 있는가
- 검색 재현: 에이전트가 적은 정규식을 ripgrep 으로 다시 돌려 0건 주장이 맞는가
- 형식 검사: 닫는 판단에 필요한 근거 칸이 있는가
실패가 하나라도 있으면 사람 검토(needs_review)로 넘긴다. 근거를 지어냈는지만 보며, 판단이 옳은지는 보지 않는다.
"""
from __future__ import annotations

import json, os, pathlib, re, shutil, subprocess

NO_WINDOW = 0x08000000 if os.name == "nt" else 0
RG = shutil.which("rg") or "/opt/homebrew/bin/rg"
if os.name == "nt":
    RG = str(pathlib.Path(__file__).resolve().parents[1] / "tools" / "rg.exe")
NEEDS_EVIDENCE = {
    "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment",
    "compiler_protected", "runtime_protected", "perimeter_protected", "mitigating_control_protected", "vulnerable",
}
NEEDS_ZERO_SEARCH = {"code_not_present", "code_not_reachable", "requires_dependency"}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def check_quote(repo: pathlib.Path, ev: dict) -> tuple[bool, str]:
    rel = str(ev.get("path", "")).replace("\\", "/")
    rel = rel[2:] if rel.startswith("./") else rel
    p = (repo / rel).resolve()
    if repo.resolve() not in p.parents or not p.is_file():
        return False, f"없는 파일: {rel}"
    q = _norm(str(ev.get("quote", "")))
    if len(q) < 3:
        return False, f"인용 없음: {rel}"
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        ln = int(ev.get("line") or 0)
    except (TypeError, ValueError):
        ln = 0
    lo, hi = max(0, ln - 4), min(len(lines), ln + 3)
    if q in _norm(" ".join(lines[lo:hi])):
        return True, ""
    if q in _norm(" ".join(lines)):
        return True, f"줄 번호 어긋남(파일 안에는 있음): {rel}:{ln}"
    return False, f"인용 불일치: {rel}:{ln}"


def _scope_globs(scope: str) -> tuple[list[str], str]:
    """에이전트가 적은 범위를 ripgrep 인자로 바꾼다. 쉼표 목록과 설명 문구를 견딘다."""
    scope = re.sub(r"\(.*?\)", " ", scope).replace("\\", "/").strip()
    parts = [x.strip() for x in scope.split(",") if x.strip()]
    globs, target = [], "."
    for x in parts:
        if " " in x:
            continue
        if any(c in x for c in "*?{!"):
            globs.append(x)
        elif len(parts) == 1 and x not in (".", "./"):
            target = x[2:] if x.startswith("./") else x
        elif x not in (".", "./"):
            globs.append(x if "." in x.split("/")[-1] else x.rstrip("/") + "/**")
    return globs, target


def _rg_count(repo: pathlib.Path, pat: str, globs: list[str], target: str, timeout: int) -> int | None:
    cmd = [RG, "--count-matches", "--no-messages", "--no-ignore", "--hidden", "--glob", "!.git"]
    if "\\n" in pat:
        cmd += ["--multiline"]
    for g in globs:
        cmd += ["--glob", g]
    cmd += ["-e", pat, target]
    try:
        r = subprocess.run(cmd, cwd=str(repo), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode not in (0, 1):
        return None
    return sum(int(l.rsplit(":", 1)[-1]) for l in r.stdout.splitlines() if l.rsplit(":", 1)[-1].isdigit())


def rerun_search(repo: pathlib.Path, s: dict, timeout: int = 90) -> tuple[bool, str, int | None]:
    """0건 주장이 틀렸는지 본다. 범위 해석이 어긋나 건수가 다를 수 있으므로 실패는 지어낸 근거가 분명할 때만 낸다."""
    pat = str(s.get("pattern") or "")
    scope = str(s.get("scope") or ".")
    globs, target = _scope_globs(scope)
    actual = _rg_count(repo, pat, globs, target, timeout)
    if actual is None:
        actual = _rg_count(repo, pat, [], ".", timeout)
        if actual is None:
            return True, f"검색 재현 불가, 판단에 쓰지 않음: {pat[:60]}", None
        globs, target = [], "."
    try:
        claimed = int(s.get("hits"))
    except (TypeError, ValueError):
        return True, f"건수 미기재: {pat[:60]}", None
    if claimed == 0 and actual > 0:
        return False, f"0건 주장이 틀림({actual}건): {pat[:60]} @ {scope[:60]}", actual
    if claimed > 0 and actual == 0:
        whole = _rg_count(repo, pat, [], ".", timeout)
        if whole == 0:
            return False, f"있다던 것이 저장소 전체에 없음({claimed}건 주장): {pat[:60]}", 0
    return True, "", actual


def verify(obj: dict | None, repo: pathlib.Path) -> dict:
    fails, notes = [], []
    if not isinstance(obj, dict):
        return {"ok": False, "fails": ["JSON 없음"], "notes": [], "searches_checked": 0, "quotes_checked": 0}
    cat = obj.get("category")
    evidence = obj.get("evidence") if isinstance(obj.get("evidence"), list) else []
    searches = obj.get("searches") if isinstance(obj.get("searches"), list) else []
    for ev in evidence[:30]:
        if isinstance(ev, dict):
            ok, msg = check_quote(repo, ev)
            if not ok:
                fails.append(msg)
            elif msg:
                notes.append(msg)
    zero_ok = 0
    for s in searches[:20]:
        if isinstance(s, dict):
            ok, msg, actual = rerun_search(repo, s)
            if not ok:
                fails.append(msg)
            elif msg:
                notes.append(msg)
            elif actual == 0:
                zero_ok += 1
    if cat in NEEDS_EVIDENCE and not evidence:
        fails.append("근거 인용 없음")
    if cat in NEEDS_ZERO_SEARCH and zero_ok == 0:
        fails.append("없다는 주장을 뒷받침하는 재현 가능한 0건 검색 없음")
    return {"ok": not fails, "fails": fails, "notes": notes, "searches_checked": min(len(searches), 20), "quotes_checked": min(len(evidence), 30), "zero_searches_ok": zero_ok}


def parse_obj(text: str | None) -> dict | None:
    """result_parser 와 같은 방식(첫 번째로 해석되는 JSON 객체)."""
    if not text:
        return None
    s = text.strip()
    m = re.match(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", s, re.S)
    if m:
        s = m.group(1).strip()
    if s.startswith("{"):
        try:
            return json.loads(s)
        except ValueError:
            pass
    depth, start = 0, -1
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(s[start : i + 1])
                except ValueError:
                    start = -1
    return None
