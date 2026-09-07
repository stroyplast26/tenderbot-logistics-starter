from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest

from lead_factory.bitrix_graph_canary_cohort import (
    GRAPH_CANARY_EXPANSION_COHORT_VERSION,
    GraphCanaryExpansionCohortSpec,
    build_graph_canary_expansion_cohort,
)
from lead_factory.bitrix_graph_canary_control import (
    BitrixGraphCanaryControl,
    GraphCanaryCredentialEvidence,
    GraphCanaryEvidenceError,
)
from lead_factory.bitrix_graph_canary_expansion_stage import (
    prepare_graph_canary_expansion,
    seal_graph_canary_expansion_cutover,
)
from lead_factory.bitrix_graph_canary_stage import (
    GraphCanaryCandidate,
    prepare_graph_canary,
)
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.store import FactoryStore


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BitrixGraphCanaryExpansionStageTests(unittest.TestCase):
    def _completed_cap_one(self, root: Path):
        database = root / "schema17-cap-one.sqlite3"
        store = FactoryStore(database)
        store.init()
        control = BitrixGraphCanaryControl(store)
        deployment_hash = "1" * 64
        manifest_hash = "2" * 64
        candidate = GraphCanaryCandidate(
            candidate_id="cap-one-completed",
            mailbox="INBOX",
            campaign_id="bitrix-graph-cap-one",
            canonical_thread="<cap-one-completed@tenderbot.example>",
            contact_address="cap-one-completed@tenderbot.example",
            company_title="TenderBot cap one company",
            company_inn="7701000099",
            contact_name="TenderBot cap one",
            contact_post="System canary",
            project_title="TenderBot cap one project",
            deal_title="TenderBot cap one deal",
            product_key="system_canary",
            activity_subject="TenderBot cap one activity",
            activity_description="Automated bounded integration canary.",
            activity_deadline_utc="2030-01-01T00:00:00Z",
            lf_source_id="alumkomplekt-site",
            reviewer_ref="owner:desia",
        )
        prepared = prepare_graph_canary(
            control,
            candidate,
            mapping_manifest_hash=manifest_hash,
            owner_approval_evidence_ref="owner:cap-one",
            cutover_evidence_ref="cutover:cap-one",
            credential=GraphCanaryCredentialEvidence.exact_crm_only(
                credential_fingerprint="credential:shared-cap-one",
                evidence_ref="credential-evidence:shared-cap-one",
            ),
            sealed_input_hashes=(
                ("deployment_input", deployment_hash),
                ("live_preflight_evidence", "3" * 64),
                ("mapping_manifest", manifest_hash),
            ),
            actor="owner:desia",
        )
        control.activate_cutover(prepared.cutover_evidence, actor="owner:desia")
        operation_ids = (
            prepared.stage.company_operation_id,
            prepared.stage.contact_operation_id,
            prepared.stage.deal_operation_id,
            prepared.stage.activity_operation_id,
        )
        remote_types = ("company", "contact", "deal", "activity")
        remote_ids = ("101", "201", "301", "401")
        with store.transaction(min_schema_version=17) as con:
            for operation_id, remote_type, remote_id in zip(
                operation_ids, remote_types, remote_ids, strict=True
            ):
                row = con.execute(
                    "SELECT * FROM crm_outbox WHERE operation_id=?", (operation_id,)
                ).fetchone()
                con.execute(
                    """UPDATE crm_outbox
                       SET state='SENT',remote_entity_type=?,remote_entity_id=?
                       WHERE operation_id=?""",
                    (remote_type, remote_id, operation_id),
                )
                if remote_type != "activity":
                    con.execute(
                        """INSERT INTO crm_mappings(
                               lf_entity_type,lf_entity_id,remote_entity_type,
                               remote_entity_id,state,last_readback_at_utc,created_at_utc
                           ) VALUES(?,?,?,?,?,?,?)""",
                        (
                            row["lf_entity_type"],
                            row["lf_entity_id"],
                            remote_type,
                            remote_id,
                            "ACTIVE",
                            row["updated_at_utc"],
                            row["updated_at_utc"],
                        ),
                    )
        control.stop_run(
            prepared.run_id,
            actor="owner:desia",
            reason="cap_one_complete",
            evidence_ref="stop:cap-one",
        )
        snapshot_hash = _file_hash(database)
        evidence = {
            "activation_gate": {"cap1_complete": True},
            "cap1": {
                "control_schema_version": 17,
                "operations": [
                    {"remote_id": remote_id, "state": "SENT"}
                    for remote_id in remote_ids
                ],
                "run_id": prepared.run_id,
                "run_state": "STOPPED",
            },
            "deployment_input_hash": deployment_hash,
            "evidence_version": "bitrix-graph-live-evidence-v2",
            "final_flags": {
                "external_source_reads_enabled": False,
                "external_writers_enabled": False,
                "manual_import_commits_enabled": False,
            },
            "mapping_manifest_hash": manifest_hash,
        }
        evidence["declared_evidence_hash"] = payload_hash(evidence)
        evidence_path = root / "cap-one-evidence.json"
        evidence_path.write_text(canonical_json(evidence), encoding="utf-8")
        spec = GraphCanaryExpansionCohortSpec(
            cohort_version=GRAPH_CANARY_EXPANSION_COHORT_VERSION,
            cohort_id="expansion-stage-test",
            approved_at_utc="2026-08-22T12:00:00Z",
            activity_deadline_utc="2026-08-29T12:00:00Z",
            owner_approval_evidence_ref="owner:cap-five",
            reviewer_ref="owner:desia",
            lf_source_id="alumkomplekt-site",
            portal_identity="bitrix-host-v1:" + "4" * 64,
            deployment_input_hash=deployment_hash,
            mapping_manifest_hash=manifest_hash,
            cap_one_evidence_hash=evidence["declared_evidence_hash"],
            cap_one_control_snapshot_hash=snapshot_hash,
        )
        return control, evidence_path, spec

    def test_prepares_four_members_idempotently_and_keeps_writers_off(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control, evidence_path, spec = self._completed_cap_one(root)
            cohort = build_graph_canary_expansion_cohort(spec)
            first = prepare_graph_canary_expansion(
                control,
                cohort,
                allowed_control_root=root,
                cap_one_evidence_path=evidence_path,
                actor="owner:desia",
            )
            replay = prepare_graph_canary_expansion(
                control,
                cohort,
                allowed_control_root=root,
                cap_one_evidence_path=evidence_path,
                actor="owner:desia",
            )
            self.assertEqual(first, replay)
            self.assertEqual(len(first.members), 4)
            con = control.store.connect()
            try:
                self.assertEqual(
                    con.execute("SELECT state FROM canary_runs").fetchone()[0],
                    "DRAFT",
                )
                self.assertEqual(
                    con.execute("SELECT COUNT(*) FROM canary_approvals").fetchone()[0],
                    2,
                )
                self.assertEqual(
                    con.execute("SELECT COUNT(*) FROM canary_scope_members").fetchone()[0],
                    5,
                )
                self.assertEqual(
                    con.execute("SELECT COUNT(*) FROM canary_operation_bindings").fetchone()[0],
                    20,
                )
                self.assertEqual(
                    dict(
                        con.execute(
                            "SELECT state,COUNT(*) FROM crm_outbox GROUP BY state"
                        ).fetchall()
                    ),
                    {"PENDING": 16, "SENT": 4},
                )
                self.assertEqual(
                    con.execute(
                        "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
                    ).fetchone()[0],
                    "0",
                )
            finally:
                con.close()

    def test_snapshot_tamper_and_shared_credential_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control, evidence_path, spec = self._completed_cap_one(root)
            bad = build_graph_canary_expansion_cohort(
                replace(spec, cap_one_control_snapshot_hash="0" * 64)
            )
            with self.assertRaises(ValueError):
                prepare_graph_canary_expansion(
                    control,
                    bad,
                    allowed_control_root=root,
                    cap_one_evidence_path=evidence_path,
                    actor="owner:desia",
                )
            cohort = build_graph_canary_expansion_cohort(spec)
            prepared = prepare_graph_canary_expansion(
                control,
                cohort,
                allowed_control_root=root,
                cap_one_evidence_path=evidence_path,
                actor="owner:desia",
            )
            shared = seal_graph_canary_expansion_cutover(
                prepared,
                credential=GraphCanaryCredentialEvidence.exact_crm_only(
                    credential_fingerprint="credential:shared-cap-one",
                    evidence_ref="credential-evidence:shared-cap-one",
                ),
                cutover_evidence_ref="cutover:cap-five",
                credential_isolation_evidence_ref="isolation:missing",
            )
            with self.assertRaises(GraphCanaryEvidenceError):
                control.activate_expansion_cutover(shared, actor="owner:desia")
            con = control.store.connect()
            try:
                self.assertEqual(
                    con.execute(
                        "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
                    ).fetchone()[0],
                    "0",
                )
            finally:
                con.close()


if __name__ == "__main__":
    unittest.main()
