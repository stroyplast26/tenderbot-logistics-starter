from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from lead_factory.bitrix_graph_canary_cohort import (
    GRAPH_CANARY_EXPANSION_COHORT_VERSION,
    GRAPH_CANARY_EXPANSION_ORDINALS,
    GraphCanaryExpansionCohortSpec,
    build_graph_canary_expansion_cohort,
    load_graph_canary_expansion_cohort,
    validate_sealed_graph_canary_expansion_cohort,
)
from lead_factory.ids import canonical_json
from lead_factory.bitrix_graph_canary_stage import stage_graph_canary_member
from lead_factory.store import FactoryStore


class BitrixGraphCanaryCohortTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = GraphCanaryExpansionCohortSpec(
            cohort_version=GRAPH_CANARY_EXPANSION_COHORT_VERSION,
            cohort_id="owner-approved-20260822",
            approved_at_utc="2026-08-22T12:00:00Z",
            activity_deadline_utc="2026-08-29T12:00:00Z",
            owner_approval_evidence_ref="owner:desia:graph-cap5:20260822",
            reviewer_ref="owner:desia",
            lf_source_id="alumkomplekt-site",
            portal_identity="bitrix-host-v1:" + "1" * 64,
            deployment_input_hash="2" * 64,
            mapping_manifest_hash="3" * 64,
            cap_one_evidence_hash="4" * 64,
            cap_one_control_snapshot_hash="5" * 64,
        )

    @staticmethod
    def _valid_inn10(value: str) -> bool:
        digits = [int(item) for item in value]
        expected = sum(
            digit * weight
            for digit, weight in zip(
                digits[:9], (2, 4, 10, 3, 5, 9, 4, 6, 8), strict=True
            )
        )
        return len(value) == 10 and digits[-1] == expected % 11 % 10

    def test_exact_slots_two_through_five_are_deterministic_and_sealed(self):
        first = build_graph_canary_expansion_cohort(self.spec)
        second = build_graph_canary_expansion_cohort(self.spec)
        self.assertEqual(first, second)
        self.assertEqual(len(first.candidates), 4)
        self.assertEqual(len(set(first.candidate_hashes)), 4)
        self.assertEqual(
            tuple(
                int(item.company_title.split()[3].split("/")[0])
                for item in first.candidates
            ),
            GRAPH_CANARY_EXPANSION_ORDINALS,
        )
        self.assertTrue(all(self._valid_inn10(item.company_inn) for item in first.candidates))
        self.assertTrue(
            all(item.contact_address.endswith("@tenderbot.example") for item in first.candidates)
        )
        self.assertEqual(validate_sealed_graph_canary_expansion_cohort(first), first.cohort_hash)

    def test_named_inputs_bind_cap_one_and_every_candidate(self):
        cohort = build_graph_canary_expansion_cohort(self.spec)
        named = dict(cohort.named_input_hashes())
        self.assertEqual(named["cap_one_evidence"], "4" * 64)
        self.assertEqual(named["cap_one_control_snapshot"], "5" * 64)
        self.assertEqual(named["deployment_input"], "2" * 64)
        self.assertEqual(named["mapping_manifest"], "3" * 64)
        self.assertEqual(named["expansion_cohort"], cohort.cohort_hash)
        self.assertEqual(
            tuple(named[f"expansion_candidate_{item}"] for item in GRAPH_CANARY_EXPANSION_ORDINALS),
            cohort.candidate_hashes,
        )

    def test_tamper_and_invalid_approval_or_deadline_fail_closed(self):
        cohort = build_graph_canary_expansion_cohort(self.spec)
        with self.assertRaises(ValueError):
            validate_sealed_graph_canary_expansion_cohort(
                replace(cohort, cohort_hash="0" * 64)
            )
        with self.assertRaises(ValueError):
            build_graph_canary_expansion_cohort(
                replace(self.spec, owner_approval_evidence_ref="contains space")
            )
        with self.assertRaises(ValueError):
            build_graph_canary_expansion_cohort(
                replace(self.spec, activity_deadline_utc=self.spec.approved_at_utc)
            )
        with self.assertRaises(ValueError):
            build_graph_canary_expansion_cohort(
                replace(self.spec, cap_one_control_snapshot_hash="not-a-hash")
            )

    def test_canonical_file_loader_rejects_tamper_and_noncanonical_bytes(self):
        cohort = build_graph_canary_expansion_cohort(self.spec)
        document = {
            "candidate_hashes": list(cohort.candidate_hashes),
            "declared_cohort_hash": cohort.cohort_hash,
            "declared_spec_hash": self.spec.seal_hash(),
            "spec": {
                name: getattr(self.spec, name)
                for name in GraphCanaryExpansionCohortSpec.__annotations__
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "cohort.json"
            target.write_text(canonical_json(document) + "\n", encoding="utf-8")
            self.assertEqual(load_graph_canary_expansion_cohort(target), cohort)
            target.write_text(
                json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                load_graph_canary_expansion_cohort(target)
            document["declared_cohort_hash"] = "0" * 64
            target.write_text(canonical_json(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_graph_canary_expansion_cohort(target)

    def test_four_members_stage_idempotently_without_minting_authority(self):
        cohort = build_graph_canary_expansion_cohort(self.spec)
        with tempfile.TemporaryDirectory() as temporary:
            store = FactoryStore(Path(temporary) / "cohort.sqlite3")
            store.init()
            first = tuple(
                stage_graph_canary_member(
                    store,
                    candidate,
                    mapping_manifest_hash=self.spec.mapping_manifest_hash,
                    actor="owner",
                )
                for candidate in cohort.candidates
            )
            second = tuple(
                stage_graph_canary_member(
                    store,
                    candidate,
                    mapping_manifest_hash=self.spec.mapping_manifest_hash,
                    actor="owner",
                )
                for candidate in cohort.candidates
            )
            for initial, replay in zip(first, second, strict=True):
                self.assertEqual(initial.interaction_id, replay.interaction_id)
                self.assertEqual(initial.lf_opportunity_id, replay.lf_opportunity_id)
                self.assertEqual(initial.candidate_hash, replay.candidate_hash)
                self.assertEqual(
                    (
                        initial.stage.company_operation_id,
                        initial.stage.contact_operation_id,
                        initial.stage.deal_operation_id,
                        initial.stage.activity_operation_id,
                    ),
                    (
                        replay.stage.company_operation_id,
                        replay.stage.contact_operation_id,
                        replay.stage.deal_operation_id,
                        replay.stage.activity_operation_id,
                    ),
                )
                self.assertEqual(len(initial.stage.created_operation_ids), 4)
                self.assertEqual(replay.stage.created_operation_ids, ())
            con = store.connect()
            try:
                self.assertEqual(con.execute("SELECT COUNT(*) FROM crm_outbox").fetchone()[0], 16)
                self.assertEqual(con.execute("SELECT COUNT(*) FROM interactions").fetchone()[0], 4)
                self.assertEqual(con.execute("SELECT COUNT(*) FROM canary_runs").fetchone()[0], 0)
                self.assertEqual(
                    con.execute("SELECT COUNT(*) FROM canary_approvals").fetchone()[0], 0
                )
            finally:
                con.close()


if __name__ == "__main__":
    unittest.main()
