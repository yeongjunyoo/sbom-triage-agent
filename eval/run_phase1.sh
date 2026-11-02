#!/bin/zsh
# 맥에서 돌리는 1단계: 저장소 내려받기가 끝나면 스캐너 기준선, 개발 세트 판단과 검토.
cd ~/lotte-ax
while pgrep -f vex_fetch.py >/dev/null; do sleep 10; done
python3 eval/scan_baseline.py > scan.log 2>&1 &
python3 eval/vex_run.py --run triage_v1 --prompt triage_v1 --split dev --parallel 6 --timeout 600 > triage_dev.log 2>&1
python3 eval/vex_run.py --run review_v1 --prompt review_v1 --context-run triage_v1 --split dev --parallel 6 --timeout 600 > review_dev.log 2>&1
wait
touch phase1.done
