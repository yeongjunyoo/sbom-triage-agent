#!/bin/zsh
# 봉인 평가. 구성은 eval/FROZEN.md 대로이고 건별 오답은 출력하지 않는다.
cd ~/lotte-ax
for r in 0 1 2; do
  python3 eval/vex_run.py --run triage_v1 --prompt triage_v1 --split test --retry-parse --repeat $r --parallel 6 --timeout 600 > sealed_r$r.log 2>&1
done
python3 eval/vex_run.py --run control_sonnet --prompt vuln --split test --repeat 2 --parallel 6 --timeout 600 > control_r2_test.log 2>&1
touch phase2.done
