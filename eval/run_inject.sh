#!/bin/bash
# 심은 글 시험. 세 종류, 두 회차. 한도에 걸리면 vex_run 이 75 로 끝나고 다시 돌리면 이어서 한다.
cd "$HOME/lotte-ax" || exit 2
export LOTTE_TOKEN_FILE=$HOME/.nova/claude_token_lotte
rm -f inject.done
for style in command claim quiet; do
  for r in 0 1; do
    python3 eval/inject_run.py --style $style --repeat $r --parallel 3 >> inject.log 2>&1
    code=$?
    echo "== $style r$r 종료 $code" >> inject.log
    [ $code -eq 75 ] && { echo stopped > inject.done; exit 75; }
  done
done
echo ok > inject.done
