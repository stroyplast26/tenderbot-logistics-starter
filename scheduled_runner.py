# -*- coding: utf-8 -*-
"""Run TenderBot scheduled jobs in the background and keep their output in logs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


BASE = Path(__file__).resolve().parent
# The runner can only execute after a working interpreter has already started it.
# Reuse that exact interpreter instead of binding jobs to a Windows user profile.
PYTHON = Path(sys.executable).resolve()

JOBS = {
    "builder_poll": (PYTHON, ["tb_builder_campaign.py", "--poll"], "builder_poll.log"),
    "dealer_poll": (PYTHON, ["tb_dealer_campaign.py", "--poll"], "dealer_poll.log"),
    "dealer_seedtest": (PYTHON, ["tb_seed_test.py"], "seed_test.log"),
    "dealer_send": (PYTHON, ["tb_dealer_campaign.py", "--send", "--new-first"], "dealer_send.log"),
    "morning_resume": (
        PYTHON,
        ["-c", "import tb_control; tb_control.update(paused=False); print('resume ok')"],
        "morning_resume.log",
    ),
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in JOBS:
        return 2

    # AK-MDOS-V7 RC1 has no ratified beachhead.  Scheduled legacy jobs can
    # read or write external systems and therefore remain frozen as a unit.
    from lead_factory.mdos_v7.authority import external_block_reason
    print(external_block_reason(f"scheduled_job:{sys.argv[1]}"))
    return 77

    interpreter, args, log_name = JOBS[sys.argv[1]]
    if not interpreter.is_file():
        return 3

    log_dir = BASE / "logs"
    log_dir.mkdir(exist_ok=True)
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    with (log_dir / log_name).open("a", encoding="utf-8") as log_file:
        result = subprocess.run(
            [str(interpreter), *args],
            cwd=BASE,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
            check=False,
        )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
