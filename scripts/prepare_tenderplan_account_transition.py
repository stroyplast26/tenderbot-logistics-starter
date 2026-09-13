"""Preview or apply one local account transition; never access a provider."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.tenderplan_account_connection import (  # noqa: E402
    TenderPlanAccountConnectionError,
    validate_tenderplan_account_connection,
)
from lead_factory.tenderplan_read_only_store import (  # noqa: E402
    TENDERPLAN_ACCOUNT_TRANSITION_CONFIRMATION,
    TENDERPLAN_READ_ONLY_QUEUE_PATH,
    TenderPlanReadOnlyStoreError,
    prepare_tenderplan_account_transition,
)


def _backup_existing_store(path: Path, expected_sha256: str) -> Path:
    """Preserve exact original bytes without overwriting an earlier backup."""
    backup = path.with_name(path.name + ".before-account-transition.bak")
    source_info = path.stat()
    if source_info.st_nlink != 1:
        raise ValueError
    if backup.exists():
        info = backup.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or getattr(info, "st_file_attributes", 0) & 0x400
                or (info.st_dev, info.st_ino) == (source_info.st_dev, source_info.st_ino)):
            raise ValueError
        with backup.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != expected_sha256:
                raise ValueError
        return backup
    if backup.is_symlink():
        raise ValueError
    digest = hashlib.sha256()
    with path.open("rb") as source, backup.open("xb") as target:
        for block in iter(lambda: source.read(262144), b""):
            digest.update(block)
            target.write(block)
        target.flush()
        os.fsync(target.fileno())
    if digest.hexdigest() != expected_sha256:
        raise ValueError
    return backup


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, default=TENDERPLAN_READ_ONLY_QUEUE_PATH)
    parser.add_argument("--expected-store-sha256", required=True)
    parser.add_argument("--expected-origin-path-sha256", required=True)
    parser.add_argument("--expected-store-identity-sha256", required=True)
    parser.add_argument("--legacy-run-id", required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--expected-profile-sha256", required=True)
    parser.add_argument("--owner-confirmation-sha256", required=True)
    parser.add_argument("--apply", action="store_true", help="apply the reviewed local migration")
    parser.add_argument("--confirm-local-transition", action="store_true")
    args = parser.parse_args(argv)
    if args.apply and not args.confirm_local_transition:
        print(json.dumps({"error": "explicit_local_transition_confirmation_required"}))
        return 2
    try:
        active = validate_tenderplan_account_connection(
            args.profile, expected_sha256=args.expected_profile_sha256
        )
        inputs = {
            "expected_store_sha256": args.expected_store_sha256,
            "expected_origin_path_sha256": args.expected_origin_path_sha256,
            "expected_store_identity_sha256": args.expected_store_identity_sha256,
            "legacy_run_id": args.legacy_run_id,
            "active_connection": active,
            "owner_confirmation_sha256": args.owner_confirmation_sha256,
            "confirmation": TENDERPLAN_ACCOUNT_TRANSITION_CONFIRMATION,
        }
        result = prepare_tenderplan_account_transition(args.store, **inputs, apply=False)
        if args.apply:
            _backup_existing_store(args.store, args.expected_store_sha256)
            # Revalidate the profile after the preview.  Store.apply also
            # rechecks the exact queue under its exclusive SQL transaction.
            if active != validate_tenderplan_account_connection(
                args.profile, expected_sha256=args.expected_profile_sha256
            ):
                raise ValueError
            result = prepare_tenderplan_account_transition(args.store, **inputs, apply=True)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except (TenderPlanAccountConnectionError, TenderPlanReadOnlyStoreError, OSError, ValueError, TypeError):
        print(json.dumps({"error": "tenderplan_account_transition_rejected", "request_count": 0}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
