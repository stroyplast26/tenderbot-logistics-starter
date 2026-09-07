"""Import the live connection bundle into the fixed Windows credential target."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.live_connection_credentials import (  # noqa: E402
    LiveConnectionCredentialError,
    LiveConnectionCredentialReceipt,
    import_live_connection_credentials_from_env,
    verify_live_connection_credentials_from_env,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and import the project live-connection .env snapshot into "
            "the fixed Windows Credential Manager target."
        )
    )
    parser.add_argument(
        "--env-file",
        default=str(ROOT / ".env"),
        help="source dotenv file (default: project root .env)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="validate and fingerprint without writing Credential Manager",
    )
    return parser


def _receipt_json(
    receipt: LiveConnectionCredentialReceipt,
    *,
    verify_only: bool,
) -> dict[str, object]:
    if type(receipt) is not LiveConnectionCredentialReceipt:
        raise TypeError
    if verify_only:
        status = "valid_not_stored"
    elif receipt.stored:
        status = "stored_and_verified"
    else:
        status = "already_current"
    return {
        "bitrix_source_name": receipt.bitrix_source_name,
        "bundle_sha256": receipt.bundle_sha256,
        "credential_blob_bytes": receipt.credential_blob_bytes,
        "readback_verified": receipt.readback_verified,
        "replaced_existing": receipt.replaced_existing,
        "source_binding_sha256": receipt.source_binding_sha256,
        "status": status,
        "stored": receipt.stored,
        "target_sha256": receipt.target_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if arguments.verify_only:
            receipt = verify_live_connection_credentials_from_env(arguments.env_file)
        else:
            receipt = import_live_connection_credentials_from_env(arguments.env_file)
        output = _receipt_json(receipt, verify_only=bool(arguments.verify_only))
    except LiveConnectionCredentialError as error:
        print(
            json.dumps(
                {"error": error.code, "status": "not_stored"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3
    except Exception:
        print(
            json.dumps(
                {"error": "live_connection_import_failed", "status": "not_stored"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
