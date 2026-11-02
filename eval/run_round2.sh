#!/bin/bash
# 콜드리드 뒤 측정: 스캐너 합치기, 규칙 순위, 역조회, 호출 그래프, 공격 시험 2판.
cd "$HOME/lotte-ax" || exit 2
export PATH=/opt/homebrew/bin:$PATH LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
rm -f round2.done
log() { echo "== $(date +%H:%M) $1" >> round2.log; }
log 시작
python3 eval/rank_score.py >> round2.log 2>&1; log "규칙 순위 $?"
python3 agent/where_used.py results/sbom --cve CVE-2021-44228 --json results/where_used_log4shell.json >> round2.log 2>&1; log "역조회 $?"
python3 eval/grype_scan.py >> round2.log 2>&1; log "grype $?"
python3 eval/path_score.py --scanner results/scanner_union/summary.json --out results/path_score_union.json > results/path_score_union.txt 2>&1; log "합집합 경로 $?"
for style in code exfil; do
  for r in 0 1; do
    python3 eval/inject_run2.py --style $style --repeat $r >> inject2.log 2>&1
    code=$?
    log "공격 $style r$r $code"
    [ $code -eq 75 ] && { echo stopped > round2.done; exit 75; }
  done
done
python3 eval/inject_run2.py --score >> round2.log 2>&1; log "공격 집계 $?"
GOPATH=$PWD/tools/gopath PATH=$PWD/tools/go/bin:$PATH go install golang.org/x/vuln/cmd/govulncheck@latest >> round2.log 2>&1
cp tools/gopath/bin/govulncheck tools/govulncheck; log "govulncheck 설치 $?"
python3 eval/govulncheck_run.py --parallel 3 --timeout 900 >> round2.log 2>&1; log "호출 그래프 $?"
echo ok > round2.done
