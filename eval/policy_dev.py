"""닫기 정책을 비교한다. 개발 세트 전용.

정책 P0: 근거 검사만 통과하면 어떤 범주든 닫는다
정책 P1: 「없음」을 기계로 증명하는 범주(code_not_present, code_not_reachable)만 닫고, 나머지 닫기 판단은 사람 검토
정책 P2: P1 + 0건 검색이 권고문의 패키지나 취약 함수를 실제로 겨냥했는지 확인
A2: 두 회차가 모두 닫자고 할 때만 닫는다
"""
import collections, json, pathlib, re, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from verify import parse_obj, verify
import vex_run, vex_score

ROOT = pathlib.Path(__file__).resolve().parents[1]
dev = sorted(json.loads((ROOT / "eval/split.json").read_text(encoding="utf-8"))["dev"])
gt = vex_score.truth()
tasks = {t["task_id"]: t for t in vex_run.tasks()}
PROOF = {"code_not_present", "code_not_reachable"}


def tokens(adv):
    out = set()
    if not isinstance(adv, dict):
        return out
    for x in [adv.get("package")] + list(adv.get("vulnerable_symbols") or []):
        for w in re.findall(r"[A-Za-z_][A-Za-z0-9_\-]{2,}", str(x)):
            out.add(w.lower())
    return out - {"github", "com", "org", "golang", "the", "and", "http", "stdlib", "net", "server", "go"}


def aimed(o, repo):
    """0건 검색 중 하나라도 권고문의 패키지나 함수 낱말을 담고 있는가."""
    toks = tokens(o.get("advisory"))
    for s in o.get("searches") or []:
        if not isinstance(s, dict):
            continue
        try:
            if int(s.get("hits")) != 0:
                continue
        except (TypeError, ValueError):
            continue
        p = str(s.get("pattern")).lower()
        if any(t in p for t in toks):
            return True
    return False


def decision(o, repo, policy):
    cat = o.get("category") if isinstance(o, dict) else None
    if cat == "vulnerable":
        return "OPEN"
    if cat in (None, "uncertain") or cat not in vex_score.rp.VALID_CATEGORIES:
        return "REVIEW"
    if not verify(o, repo)["ok"]:
        return "REVIEW"
    if policy in ("P1", "P2") and cat not in PROOF:
        return "REVIEW"
    if policy == "P2" and not aimed(o, repo):
        return "REVIEW"
    return "CLOSE"


def row(name, decs):
    n = collections.Counter(decs.values())
    wrong = [t for t, d in decs.items() if d == "CLOSE" and gt[t]["ground_truth"] == "exploitable"]
    miss_open = sum(1 for t, d in decs.items() if d == "OPEN" and gt[t]["ground_truth"] == "exploitable")
    fp_open = sum(1 for t, d in decs.items() if d == "OPEN" and gt[t]["ground_truth"] != "exploitable")
    print(f"{name:18} CLOSE {n['CLOSE']:>2} 오류 {len(wrong)} | REVIEW {n['REVIEW']:>2} | OPEN {n['OPEN']:>2} (맞음 {miss_open}, 오탐 {fp_open}) | 틀린 닫기 {[w.split('-CVE')[0][:24] for w in wrong]}")


objs = {r: {t: parse_obj((json.loads((ROOT / f"results/triage_v1/{t}__r{r}.json").read_text(encoding="utf-8"))).get("final_text")) for t in dev} for r in (0, 1)}
for r in (0, 1):
    for pol in ("P0", "P1", "P2"):
        row(f"r{r} {pol}", {t: decision(objs[r][t], vex_run.repo_dir(tasks[t]), pol) for t in dev})
for pol in ("P0", "P1", "P2"):
    decs = {}
    for t in dev:
        a, b = decision(objs[0][t], vex_run.repo_dir(tasks[t]), pol), decision(objs[1][t], vex_run.repo_dir(tasks[t]), pol)
        decs[t] = "CLOSE" if a == b == "CLOSE" else ("OPEN" if "OPEN" in (a, b) else "REVIEW")
    row(f"두 회차 일치 {pol}", decs)
print("개발 세트 위험 없음(정답) 17, 위험 9")
