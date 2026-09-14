"""Preview (default) or explicitly archive one expired Yandex activation root."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.radar_yandex_root_rotation import (  # noqa: E402
    YANDEX_ROOT_ROTATION_CONFIRMATION,
    YandexRootRotationError,
    apply_yandex_root_rotation,
    preview_yandex_root_rotation,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "new-job-id", "expected-new-draft-sha256", "expected-new-scope-sha256",
        "expected-old-root-sha256", "completion-audit-path", "expected-completion-audit-sha256",
        "native-receipt-path", "expected-native-receipt-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--apply", action="store_true")
    for name in ("expected-preview-sha256", "activation-evidence-sha256", "approval-path",
                 "expected-approval-sha256", "confirmation"):
        parser.add_argument("--" + name)
    options = vars(parser.parse_args(argv))
    apply = options.pop("apply")
    extra = {name: options.pop(name) for name in (
        "expected_preview_sha256", "activation_evidence_sha256", "approval_path",
        "expected_approval_sha256", "confirmation",
    )}
    if apply:
        if any(value is None for value in extra.values()) or extra["confirmation"] != YANDEX_ROOT_ROTATION_CONFIRMATION:
            parser.error("apply requires fresh evidence, approval and preview pins plus exact confirmation")
    elif any(value is not None for value in extra.values()):
        parser.error("apply-only arguments require --apply")
    try:
        result = apply_yandex_root_rotation(**options, **extra) if apply else preview_yandex_root_rotation(**options)
    except YandexRootRotationError as error:
        print(json.dumps({"ok": False, "error": error.code, "external_requests_this_run": 0}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
