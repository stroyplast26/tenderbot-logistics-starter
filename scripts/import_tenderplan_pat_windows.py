"""One-time, non-replacing TenderPlan PAT import into Windows Credential Manager."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.tenderplan_windows_credential import (  # noqa: E402
    TenderPlanCredentialProvisioningError,
    TenderPlanCredentialProvisioningReceipt,
    TenderPlanCredentialReconciliationRequired,
    import_tenderplan_pat_from_file,
    tenderplan_windows_auth_reference,
)


def _valid_receipt(value: object) -> bool:
    if type(value) is not TenderPlanCredentialProvisioningReceipt:
        return False
    try:
        tenderplan_windows_auth_reference(value.auth_reference_id)
        return (
            len(value.target_sha256) == 64
            and len(value.registration_sha256) == 64
            and all(
                character in "0123456789abcdef" for character in value.target_sha256
            )
            and all(
                character in "0123456789abcdef"
                for character in value.registration_sha256
            )
            and value.credential_bytes == 128
            and value.stored_new is True
            and value.readback_verified is True
            and value.source_file_retained is True
            and value.live_release_eligible is False
        )
    except (TenderPlanCredentialProvisioningError, TypeError, ValueError):
        return False


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            json.dumps(
                {"status": "not_stored", "error": "one_absolute_source_file_required"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        receipt = import_tenderplan_pat_from_file(arguments[0])
    except TenderPlanCredentialReconciliationRequired as error:
        print(
            json.dumps(
                {
                    "auth_reference_id": error.auth_reference_id,
                    "error": error.code,
                    "live_release_eligible": False,
                    "status": "reconciliation_required",
                    "target_sha256": error.target_sha256,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4
    except TenderPlanCredentialProvisioningError as error:
        print(
            json.dumps(
                {"status": "not_stored", "error": error.code},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3
    except Exception:
        print(
            json.dumps(
                {"status": "not_stored", "error": "provisioning_failed"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 5
    if not _valid_receipt(receipt):
        print(
            json.dumps(
                {"status": "not_stored", "error": "receipt_invalid"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 6
    print(
        json.dumps(
            {
                "auth_reference_id": receipt.auth_reference_id,
                "credential_bytes": receipt.credential_bytes,
                "live_release_eligible": receipt.live_release_eligible,
                "readback_verified": receipt.readback_verified,
                "registration_sha256": receipt.registration_sha256,
                "source_file_retained": receipt.source_file_retained,
                "status": "stored_and_verified",
                "target_sha256": receipt.target_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
