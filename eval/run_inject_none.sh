#!/bin/bash
# 심지 않은 대조군 4회차.
cd "$HOME/lotte-ax" || exit 2
rm -f inject_none.done
for r in 0 1 2 3; do
  python3 eval/inject_none.py --repeat $r --parallel 3 >> inject_none.log 2>&1
  code=$?
  echo "== none r$r 종료 $code" >> inject_none.log
  [ $code -eq 75 ] && { echo stopped > inject_none.done; exit 75; }
done
echo ok > inject_none.done
