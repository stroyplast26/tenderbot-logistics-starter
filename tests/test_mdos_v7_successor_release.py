from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from lead_factory.mdos_v7.authority import PACKAGE_VERSION as ACTIVE_PACKAGE_VERSION
from lead_factory.mdos_v7.successor_release import (
    EXPECTED_ARTIFACT_COUNT,
    SUCCESSOR_MANIFEST_PATH,
    SUCCESSOR_PACKAGE_VERSION,
    SUCCESSOR_RELEASE_PIN_PATH,
    SuccessorAuthorityError,
    assert_successor_live_allowed,
    load_successor_release_pin,
)


ROOT = Path(__file__).resolve().parents[1]


class SuccessorReleaseTests(unittest.TestCase):
    def _copy_release(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        shutil.copytree(
            ROOT / "docs" / "market_demand_os_v7_2",
            root / "docs" / "market_demand_os_v7_2",
        )
        predecessor = root / "docs" / "market_demand_os_v7" / "contract-manifest.json"
        predecessor.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "docs" / "market_demand_os_v7" / "contract-manifest.json", predecessor)
        return temporary, root

    def test_exact_successor_pin_is_verified_but_not_activated(self):
        pin = load_successor_release_pin(ROOT)
        self.assertEqual(pin.package_version, SUCCESSOR_PACKAGE_VERSION)
        self.assertEqual(pin.artifact_count, EXPECTED_ARTIFACT_COUNT)
        self.assertEqual(pin.authority_status, "DEFAULT_DENY_NOT_RATIFIED")
        self.assertTrue(all(value is False for value in pin.live_gates.values()))
        self.assertEqual(ACTIVE_PACKAGE_VERSION, "7.1.0-rc.1")

    def test_live_successor_operation_is_unconditionally_denied(self):
        with self.assertRaisesRegex(
            SuccessorAuthorityError,
            "MDOS_V7_2_UNRATIFIED_DEFAULT_DENY:mango_call",
        ):
            assert_successor_live_allowed("mango_call")

    def test_manifest_change_is_rejected_even_if_package_root_field_is_unchanged(self):
        temporary, root = self._copy_release()
        self.addCleanup(temporary.cleanup)
        path = root / SUCCESSOR_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["required_approver_roles"] = ["BusinessOwner"]
        path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(SuccessorAuthorityError, "manifest SHA256 drift"):
            load_successor_release_pin(root)

    def test_release_pin_change_is_rejected_before_manifest_is_trusted(self):
        temporary, root = self._copy_release()
        self.addCleanup(temporary.cleanup)
        path = root / SUCCESSOR_RELEASE_PIN_PATH
        pin = json.loads(path.read_text(encoding="utf-8"))
        pin["package_version"] = "7.2.0"
        path.write_text(json.dumps(pin, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(SuccessorAuthorityError, "release-pin SHA256 drift"):
            load_successor_release_pin(root)


if __name__ == "__main__":
    unittest.main()
