from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from lead_factory.bitrix_graph_deployment import (
    BitrixGraphDeploymentError,
    build_bitrix_graph_mapping_manifest,
    load_bitrix_graph_deployment_input,
    validate_bitrix_graph_deployment_input,
)
from lead_factory.bitrix_graph_mapping import validate_graph_mapping_manifest
from lead_factory.bitrix_graph_schema_admin import build_bitrix_graph_uf_plan


_DEPLOYMENT = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "LEAD_FACTORY_BITRIX_GRAPH_DEPLOYMENT.json"
)


class BitrixGraphDeploymentTests(unittest.TestCase):
    def test_checked_in_input_is_canonical_sealed_and_compiles_exact_graph(self):
        value = load_bitrix_graph_deployment_input(_DEPLOYMENT)
        input_hash = validate_bitrix_graph_deployment_input(value)
        manifest = build_bitrix_graph_mapping_manifest(value)
        manifest_hash = validate_graph_mapping_manifest(manifest)
        plan = build_bitrix_graph_uf_plan(manifest)
        self.assertEqual(input_hash, value.declared_input_hash)
        self.assertEqual(manifest_hash, manifest.declared_manifest_hash)
        self.assertEqual(len(plan.fields), 38)
        self.assertEqual(manifest.route.deal_category_id, "1")
        self.assertEqual(manifest.route.deal_stage_id, "C1:NEW")
        self.assertEqual(
            tuple(item.lf_source_id for item in manifest.source_bindings),
            tuple(sorted(item.lf_source_id for item in manifest.source_bindings)),
        )

    def test_hash_tamper_and_noncanonical_file_fail_closed(self):
        value = load_bitrix_graph_deployment_input(_DEPLOYMENT)
        with self.assertRaises(BitrixGraphDeploymentError):
            validate_bitrix_graph_deployment_input(
                replace(value, mapping_version="2026-08-22.tampered")
            )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment.json"
            target.write_text(_DEPLOYMENT.read_text(encoding="utf-8") + "\n\n", encoding="utf-8")
            with self.assertRaises(BitrixGraphDeploymentError):
                load_bitrix_graph_deployment_input(target)


if __name__ == "__main__":
    unittest.main()
