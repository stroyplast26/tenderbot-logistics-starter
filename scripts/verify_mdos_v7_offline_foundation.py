"""Fixed local entrypoint for the MDOS v7 offline-foundation gate."""

from __future__ import annotations

from pathlib import Path
import sys


WORKSPACE_ROOT = Path(__file__).resolve(strict=True).parents[1]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from lead_factory.mdos_v7.offline_foundation_manifest import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
