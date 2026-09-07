"""Crash-recoverable offline preparation for graph-canary slots two through five.

The preparation path only writes to an explicitly bounded schema17 control
store.  It never enables an external writer and it never performs network or
host access.  Live cutover remains a separate, sealed controller operation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from .bitrix_graph_canary_cohort import (
    GRAPH_CANARY_EXPANSION_ORDINALS,
    SealedGraphCanaryExpansionCohort,
    validate_sealed_graph_canary_expansion_cohort,
)
from .bitrix_graph_canary_control import (
    BitrixGraphCanaryControl,
    GraphCanaryCredentialEvidence,
    GraphCanaryExpansionCutoverEvidence,
    GraphCanaryMemberCutoverEvidence,
)
from .bitrix_graph_canary_stage import stage_graph_canary_member
from .ids import canonical_json, payload_hash


_PRODUCER = "bitrix_graph_canary_expansion_stage"
_HEX64 = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True, repr=False)
class PreparedGraphCanaryExpansion:
    """Offline-only result.  Possession grants no dispatch authority."""

    run_id: str
    approval_id: str
    checkpoint_event_id: str
    members: tuple[GraphCanaryMemberCutoverEvidence, ...]
    cohort_hash: str
    preparation_event_id: str
    completion_event_id: str

    def __repr__(self) -> str:
        return "<PreparedGraphCanaryExpansion redacted>"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_hash(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _HEX64 for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 hash")
    return value


def _load_cap_one_evidence(path: str | Path, expected_hash: str) -> dict[str, Any]:
    target = Path(path).expanduser().resolve(strict=True)
    raw_bytes = target.read_bytes()
    if not raw_bytes or len(raw_bytes) > 256 * 1024:
        raise ValueError("cap-one evidence file is invalid")
    try:
        raw = raw_bytes.decode("utf-8")
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("cap-one evidence file is invalid") from None
    if (
        not isinstance(document, dict)
        or raw
        not in {
            canonical_json(document),
            canonical_json(document) + "\n",
            canonical_json(document) + "\r\n",
        }
        or document.get("evidence_version") != "bitrix-graph-live-evidence-v2"
    ):
        raise ValueError("cap-one evidence file is not canonical")
    declared = document.get("declared_evidence_hash")
    body = dict(document)
    body.pop("declared_evidence_hash", None)
    if (
        declared != _exact_hash(expected_hash, "cap_one_evidence_hash")
        or payload_hash(body) != declared
        or document.get("activation_gate", {}).get("cap1_complete") is not True
        or document.get("cap1", {}).get("run_state") != "STOPPED"
        or document.get("cap1", {}).get("control_schema_version") != 17
        or document.get("final_flags")
        != {
            "external_source_reads_enabled": False,
            "external_writers_enabled": False,
            "manual_import_commits_enabled": False,
        }
    ):
        raise ValueError("cap-one evidence seal or completion proof is invalid")
    operations = document.get("cap1", {}).get("operations")
    if (
        not isinstance(operations, list)
        or len(operations) != 4
        or [item.get("state") for item in operations] != ["SENT"] * 4
        or any(
            type(item.get("remote_id")) is not str
            or not item["remote_id"].isascii()
            or not item["remote_id"].isdigit()
            or int(item["remote_id"]) < 1
            for item in operations
        )
    ):
        raise ValueError("cap-one evidence does not prove four positive SENT receipts")
    return document


def _bounded_control_path(control: BitrixGraphCanaryControl, root: str | Path) -> Path:
    if not isinstance(control, BitrixGraphCanaryControl):
        raise TypeError("durable graph canary control is required")
    allowed = Path(root).expanduser().resolve(strict=True)
    target = Path(control.store.path).expanduser().resolve(strict=True)
    try:
        target.relative_to(allowed)
    except ValueError:
        raise ValueError("schema17 control store is outside the allowed root") from None
    if target == allowed or target.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
        raise ValueError("schema17 control store path is invalid")
    if Path(str(target) + "-wal").exists() or Path(str(target) + "-shm").exists():
        raise ValueError("schema17 control store must have no sidecars during preparation")
    return target


def _preparation_payload(
    cohort: SealedGraphCanaryExpansionCohort,
) -> dict[str, Any]:
    return {
        "cap_one_control_snapshot_hash": cohort.spec.cap_one_control_snapshot_hash,
        "cap_one_evidence_hash": cohort.spec.cap_one_evidence_hash,
        "cohort_hash": cohort.cohort_hash,
        "candidate_hashes": list(cohort.candidate_hashes),
        "deployment_input_hash": cohort.spec.deployment_input_hash,
        "mapping_manifest_hash": cohort.spec.mapping_manifest_hash,
        "owner_approval_evidence_ref": cohort.spec.owner_approval_evidence_ref,
        "portal_identity": cohort.spec.portal_identity,
        "cumulative_cap": 5,
    }


def _assert_store_boundary(
    control: BitrixGraphCanaryControl,
    *,
    expected_run_id: str,
    preparation_payload: dict[str, Any],
    initial_snapshot_matches: bool,
) -> None:
    con = control.store.connect()
    try:
        if con.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("schema17 control store quick_check failed")
        if con.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("schema17 control store has foreign-key violations")
        meta = dict(con.execute("SELECT key,value FROM schema_meta").fetchall())
        if (
            meta.get("schema_version") != "17"
            or meta.get("external_writers_enabled") != "0"
            or meta.get("external_source_reads_enabled") != "0"
            or meta.get("manual_import_commits_enabled") != "0"
        ):
            raise ValueError("schema17 control store flags are not safely disabled")
        runs = con.execute("SELECT run_id,state FROM canary_runs").fetchall()
        if len(runs) != 1 or str(runs[0]["run_id"]) != expected_run_id:
            raise ValueError("control store must contain the exact cap-one run")
        if str(runs[0]["state"]) not in {"STOPPED", "DRAFT"}:
            raise ValueError("control store is not in a preparable state")
        states = dict(
            con.execute(
                "SELECT state,COUNT(*) FROM crm_outbox GROUP BY state"
            ).fetchall()
        )
        if states.get("SENT") != 4 or set(states) - {"SENT", "PENDING"}:
            raise ValueError("control store contains unrelated or uncertain CRM work")
        if int(states.get("PENDING", 0)) > 16:
            raise ValueError("control store exceeds the bounded expansion graph")
        if not initial_snapshot_matches:
            row = con.execute(
                """SELECT payload_json FROM events
                   WHERE producer=? AND idempotency_key=?""",
                (_PRODUCER, f"graph-canary-expansion-preparation:{expected_run_id}"),
            ).fetchone()
            if not row or json.loads(str(row[0])) != preparation_payload:
                raise ValueError("control snapshot changed before sealed preparation")
    finally:
        con.close()


def _checkpoint_inputs(
    control: BitrixGraphCanaryControl, checkpoint_event_id: str
) -> tuple[tuple[str, str], ...]:
    con = control.store.connect()
    try:
        row = con.execute(
            "SELECT payload_json FROM events WHERE event_id=?", (checkpoint_event_id,)
        ).fetchone()
    finally:
        con.close()
    if not row:
        raise ValueError("cap-one checkpoint event disappeared")
    try:
        payload = json.loads(str(row[0]))
        inputs = tuple(
            sorted((str(item[0]), _exact_hash(item[1], "sealed input")) for item in payload["sealed_input_hashes"])
        )
    except (KeyError, TypeError, ValueError, IndexError, json.JSONDecodeError):
        raise ValueError("cap-one checkpoint input bindings are invalid") from None
    if not inputs or len(dict(inputs)) != len(inputs):
        raise ValueError("cap-one checkpoint input bindings are invalid")
    return inputs


def _existing_checkpoint_event_id(
    control: BitrixGraphCanaryControl, run_id: str
) -> str:
    con = control.store.connect()
    try:
        row = con.execute(
            """SELECT event_id FROM events
               WHERE producer='bitrix_graph_canary_control'
                 AND idempotency_key=?""",
            (f"graph-canary-cap-one-completed:{run_id}",),
        ).fetchone()
    finally:
        con.close()
    return str(row[0]) if row else ""


def prepare_graph_canary_expansion(
    control: BitrixGraphCanaryControl,
    cohort: SealedGraphCanaryExpansionCohort,
    *,
    allowed_control_root: str | Path,
    cap_one_evidence_path: str | Path,
    actor: str,
) -> PreparedGraphCanaryExpansion:
    """Prepare four bound graphs while keeping every external flag disabled."""

    validate_sealed_graph_canary_expansion_cohort(cohort)
    principal = str(actor or "").strip()
    if not principal:
        raise ValueError("actor is required")
    target = _bounded_control_path(control, allowed_control_root)
    evidence = _load_cap_one_evidence(
        cap_one_evidence_path, cohort.spec.cap_one_evidence_hash
    )
    if (
        evidence.get("deployment_input_hash") != cohort.spec.deployment_input_hash
        or evidence.get("mapping_manifest_hash") != cohort.spec.mapping_manifest_hash
    ):
        raise ValueError("cohort differs from completed cap-one deployment bindings")
    run_id = str(evidence["cap1"]["run_id"])
    preparation_payload = _preparation_payload(cohort)
    initial_snapshot_matches = (
        _sha256_file(target) == cohort.spec.cap_one_control_snapshot_hash
    )
    _assert_store_boundary(
        control,
        expected_run_id=run_id,
        preparation_payload=preparation_payload,
        initial_snapshot_matches=initial_snapshot_matches,
    )
    start_event, _ = control.store.append_event(
        event_type="bitrix_graph_canary_expansion_preparation_started",
        aggregate_type="canary_run",
        aggregate_id=run_id,
        producer=_PRODUCER,
        idempotency_key=f"graph-canary-expansion-preparation:{run_id}",
        payload=preparation_payload,
        evidence_ref=cohort.spec.owner_approval_evidence_ref,
        actor=principal,
    )
    checkpoint_event_id = _existing_checkpoint_event_id(control, run_id)
    if not checkpoint_event_id:
        checkpoint_event_id = control.record_cap_one_completion_checkpoint(
            run_id,
            actor=principal,
            evidence_ref="cap-one-live-evidence:" + cohort.spec.cap_one_evidence_hash,
        )
    _, approval_id = control.create_cap_five_expansion(
        run_id=run_id,
        checkpoint_event_id=checkpoint_event_id,
        approver=principal,
        approval_evidence_ref=cohort.spec.owner_approval_evidence_ref,
        approval_id="lf_graph_canary_expansion_approval_" + cohort.cohort_hash[:32],
    )
    baseline_inputs = _checkpoint_inputs(control, checkpoint_event_id)
    baseline = dict(baseline_inputs)
    if (
        baseline.get("deployment_input") != cohort.spec.deployment_input_hash
        or baseline.get("mapping_manifest") != cohort.spec.mapping_manifest_hash
    ):
        raise ValueError("cap-one checkpoint differs from expansion deployment bindings")

    members: list[GraphCanaryMemberCutoverEvidence] = []
    for ordinal, candidate, candidate_hash in zip(
        GRAPH_CANARY_EXPANSION_ORDINALS,
        cohort.candidates,
        cohort.candidate_hashes,
        strict=True,
    ):
        staged = stage_graph_canary_member(
            control.store,
            candidate,
            mapping_manifest_hash=cohort.spec.mapping_manifest_hash,
            actor=principal,
        )
        if staged.candidate_hash != candidate_hash:
            raise ValueError("staged candidate differs from sealed expansion cohort")
        member_id = control.arm_scope_member(
            run_id,
            mailbox=candidate.mailbox,
            campaign_id=candidate.campaign_id,
            contact_address=candidate.contact_address,
            canonical_thread=candidate.canonical_thread,
            lf_opportunity_id=staged.lf_opportunity_id,
            armed_by=principal,
            evidence_ref="candidate-hash:" + candidate_hash,
            member_id="lf_graph_canary_member_" + candidate_hash[:32],
        )
        operation_ids = (
            staged.stage.company_operation_id,
            staged.stage.contact_operation_id,
            staged.stage.deal_operation_id,
            staged.stage.activity_operation_id,
        )
        control.bind_graph(
            run_id,
            member_id=member_id,
            interaction_id=staged.interaction_id,
            operation_ids=operation_ids,
            actor=principal,
        )
        con = control.store.connect()
        try:
            rows = [
                con.execute(
                    """SELECT payload_hash,dependency_operation_id
                       FROM crm_outbox WHERE operation_id=?""",
                    (operation_id,),
                ).fetchone()
                for operation_id in operation_ids
            ]
        finally:
            con.close()
        if any(row is None for row in rows):
            raise ValueError("sealed expansion graph operation disappeared")
        member_inputs = baseline_inputs + (
            ("expansion_cohort", cohort.cohort_hash),
            (f"expansion_candidate_{ordinal}", candidate_hash),
        )
        members.append(
            GraphCanaryMemberCutoverEvidence.seal(
                member_id=member_id,
                interaction_id=staged.interaction_id,
                operation_ids=operation_ids,
                operation_payload_hashes=tuple(str(row[0]) for row in rows),
                dependency_operation_ids=tuple(str(row[1] or "") for row in rows),
                sealed_input_hashes=member_inputs,
            )
        )
    member_tuple = tuple(members)
    completion_payload = {
        **preparation_payload,
        "approval_id": approval_id,
        "checkpoint_event_id": checkpoint_event_id,
        "member_seal_hashes": [member.seal_hash for member in member_tuple],
        "external_writers_enabled": False,
    }
    completion_event, _ = control.store.append_event(
        event_type="bitrix_graph_canary_expansion_prepared",
        aggregate_type="canary_run",
        aggregate_id=run_id,
        producer=_PRODUCER,
        idempotency_key=f"graph-canary-expansion-prepared:{run_id}",
        payload=completion_payload,
        evidence_ref=cohort.spec.owner_approval_evidence_ref,
        actor=principal,
    )
    _assert_store_boundary(
        control,
        expected_run_id=run_id,
        preparation_payload=preparation_payload,
        initial_snapshot_matches=False,
    )
    return PreparedGraphCanaryExpansion(
        run_id=run_id,
        approval_id=approval_id,
        checkpoint_event_id=checkpoint_event_id,
        members=member_tuple,
        cohort_hash=cohort.cohort_hash,
        preparation_event_id=str(start_event["event_id"]),
        completion_event_id=str(completion_event["event_id"]),
    )


def seal_graph_canary_expansion_cutover(
    prepared: PreparedGraphCanaryExpansion,
    *,
    credential: GraphCanaryCredentialEvidence,
    cutover_evidence_ref: str,
    credential_isolation_evidence_ref: str,
) -> GraphCanaryExpansionCutoverEvidence:
    """Seal cutover authority separately; this function does not activate it."""

    if type(prepared) is not PreparedGraphCanaryExpansion:
        raise TypeError("exact prepared graph canary expansion is required")
    return GraphCanaryExpansionCutoverEvidence.seal(
        run_id=prepared.run_id,
        approval_id=prepared.approval_id,
        checkpoint_event_id=prepared.checkpoint_event_id,
        members=prepared.members,
        cutover_evidence_ref=cutover_evidence_ref,
        credential_isolation_evidence_ref=credential_isolation_evidence_ref,
        credential=credential,
    )


__all__ = [
    "PreparedGraphCanaryExpansion",
    "prepare_graph_canary_expansion",
    "seal_graph_canary_expansion_cutover",
]
