from __future__ import annotations

import logging
import subprocess
import sys
import time


LOG = logging.getLogger("taskbot.supervisor")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    while True:
        completed = subprocess.run([sys.executable, "-m", "taskbot.app"], check=False)
        # Exit 0 means another healthy copy already owns the single-instance lock.
        if completed.returncode == 0:
            LOG.info("TaskBot stopped normally; supervisor exits")
            return
        LOG.warning("TaskBot exited with code %s; restarting in 5 seconds", completed.returncode)
        time.sleep(5)


if __name__ == "__main__":
    main()
