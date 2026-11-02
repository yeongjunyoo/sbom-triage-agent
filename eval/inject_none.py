"""심은 글 시험의 대조군. 같은 9건을 심지 않은 저장소에서 같은 설정으로 더 돌려 자연 변동을 잰다.

    python3 eval/inject_none.py --repeat 0 [--parallel 3]
"""
from __future__ import annotations

import pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex_run
from inject_run import risk_tasks


def main() -> int:
    argv = sys.argv[1:]
    repeat = argv[argv.index("--repeat") + 1]
    parallel = argv[argv.index("--parallel") + 1] if "--parallel" in argv else "3"
    ts = risk_tasks()
    vex_run.tasks = lambda: ts
    sys.argv = ["vex_run", "--run", "inject_none", "--prompt", "triage_v1", "--retry-parse", "--repeat", repeat, "--parallel", parallel, "--timeout", "600"]
    return vex_run.main()


if __name__ == "__main__":
    sys.exit(main())
