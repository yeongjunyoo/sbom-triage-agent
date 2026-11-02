#!/bin/bash
# 좁힌 닫기 규칙을 정한 뒤 봉인 세트에 새 회차 둘을 돌린다. 건별 오답은 보지 않는다.
cd "$HOME/lotte-ax" || exit 2
rm -f confirm.done
for r in 3 4; do
  python3 eval/vex_run.py --run confirm_v1 --prompt triage_v1 --split test --retry-parse --repeat $r --parallel 5 --timeout 600 >> confirm.log 2>&1
  code=$?
  echo "== confirm r$r 종료 $code" >> confirm.log
  [ $code -eq 75 ] && { echo stopped > confirm.done; exit 75; }
done
echo ok > confirm.done
