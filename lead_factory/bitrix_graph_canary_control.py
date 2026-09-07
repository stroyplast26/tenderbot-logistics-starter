"""Durable, transport-free control plane for one Bitrix CRM graph canary.

The controller is deliberately schema-17-only and default-off.  It binds one
already staged ``Company -> Contact -> Deal -> Activity`` graph to one exact
canary scope member, opens the global writer gate only from sealed cutover
evidence, and issues fenced, action-bound permits.  It never imports or calls a
network transport.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Iterable

from .canary_control import (
    CanaryApprovalRequired,
    CanaryCapacityExceeded,
    CanaryControlError,
    CanaryLeaseUnavailable,
    CanaryScopeMismatch,
    CanaryStaleLease,
    canonical_campaign_id,
    canonical_mailbox,
    canonical_outbound_thread,
)
from .crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphOutbox,
    CrmGraphReadback,
    GraphInvariantError,
)
from .crm_outbox import MappingConflict
from .ids import new_lf_id, normalize_email, payload_hash, utc_now
from .store import CURRENT_SCHEMA_VERSION, FactoryStore, IdempotencyConflict


BITRIX_GRAPH_CANARY_CONNECTOR = "bitrix_graph_canary"
GRAPH_OPERATION_ORDER = (
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    ACTIVITY_CREATE,
)
_PRODUCER = "bitrix_graph_canary_control"


class GraphCanaryEvidenceError(CanaryControlError):
    """Cutover evidence is absent, unsealed, or no longer exact."""


@dataclass(frozen=True, slots=True, repr=False)
class GraphCanaryCredentialEvidence:
    """Non-secret proof of the explicitly accepted canary credential."""

    credential_fingerprint: str
    granted_scopes: tuple[str, ...]
    owner_accepted_existing_credential: bool
    evidence_ref: str

    def __repr__(self) -> str:
        return "<GraphCanaryCredentialEvidence redacted>"

    @classmethod
    def exact_crm_only(
        cls,
        *,
        credential_fingerprint: str,
        evidence_ref: str,
        owner_accepted_existing_credential: bool = True,
    ) -> GraphCanaryCredentialEvidence:
        return cls(
            _required_text(credential_fingerprint, "credential_fingerprint"),
            ("crm",),
            bool(owner_accepted_existing_credential),
            _required_text(evidence_ref, "credential evidence_ref"),
        )


@dataclass(frozen=True, slots=True, repr=False)
class GraphCanaryCutoverEvidence:
    """Immutable caller-owned evidence envelope sealed over every authority."""

    run_id: str
    member_id: str
    approval_id: str
    interaction_id: str
    operation_ids: tuple[str, ...]
    operation_payload_hashes: tuple[str, ...]
    sealed_input_hashes: tuple[tuple[str, str], ...]
    owner_approval_evidence_ref: str
    cutover_evidence_ref: str
    credential: GraphCanaryCredentialEvidence
    seal_hash: str

    def __repr__(self) -> str:
        return "<GraphCanaryCutoverEvidence redacted>"

    @classmethod
    def seal(
        cls,
        *,
        run_id: str,
        member_id: str,
        approval_id: str,
        interaction_id: str,
        operation_ids: Iterable[str],
        operation_payload_hashes: Iterable[str],
        sealed_input_hashes: Iterable[tuple[str, str]],
        owner_approval_evidence_ref: str,
        cutover_evidence_ref: str,
        credential: GraphCanaryCredentialEvidence,
    ) -> GraphCanaryCutoverEvidence:
        values = tuple(_required_text(item, "operation_id") for item in operation_ids)
        if len(values) != len(GRAPH_OPERATION_ORDER):
            raise ValueError("operation_ids must contain the exact four-operation graph")
        command_hashes = tuple(
            _exact_hash(item, "operation_payload_hash")
            for item in operation_payload_hashes
        )
        if len(command_hashes) != len(GRAPH_OPERATION_ORDER):
            raise ValueError("operation_payload_hashes must contain exactly four hashes")
        inputs = _sealed_inputs(sealed_input_hashes)
        if not isinstance(credential, GraphCanaryCredentialEvidence):
            raise TypeError("credential evidence is required")
        fields = {
            "run_id": _required_text(run_id, "run_id"),
            "member_id": _required_text(member_id, "member_id"),
            "approval_id": _required_text(approval_id, "approval_id"),
            "interaction_id": _required_text(interaction_id, "interaction_id"),
            "operation_ids": list(values),
            "operation_payload_hashes": list(command_hashes),
            "sealed_input_hashes": [list(item) for item in inputs],
            "owner_approval_evidence_ref": _required_text(
                owner_approval_evidence_ref, "owner_approval_evidence_ref"
            ),
            "cutover_evidence_ref": _required_text(
                cutover_evidence_ref, "cutover_evidence_ref"
            ),
            "credential": _credential_payload(credential),
        }
        return cls(
            fields["run_id"],
            fields["member_id"],
            fields["approval_id"],
            fields["interaction_id"],
            values,
            command_hashes,
            inputs,
            fields["owner_approval_evidence_ref"],
            fields["cutover_evidence_ref"],
            credential,
            payload_hash(fields),
        )


@dataclass(frozen=True, slots=True, repr=False)
class GraphCanaryMemberCutoverEvidence:
    """One sealed additional graph admitted by a cap-five expansion."""

    member_id: str
    interaction_id: str
    operation_ids: tuple[str, ...]
    operation_payload_hashes: tuple[str, ...]
    dependency_operation_ids: tuple[str, ...]
    sealed_input_hashes: tuple[tuple[str, str], ...]
    seal_hash: str

    def __repr__(self) -> str:
        return "<GraphCanaryMemberCutoverEvidence redacted>"

    @classmethod
    def seal(
        cls,
        *,
        member_id: str,
        interaction_id: str,
        operation_ids: Iterable[str],
        operation_payload_hashes: Iterable[str],
        dependency_operation_ids: Iterable[str],
        sealed_input_hashes: Iterable[tuple[str, str]],
    ) -> GraphCanaryMemberCutoverEvidence:
        ids = tuple(_required_text(item, "operation_id") for item in operation_ids)
        hashes = tuple(
            _exact_hash(item, "operation_payload_hash")
            for item in operation_payload_hashes
        )
        dependencies = tuple(str(item or "").strip() for item in dependency_operation_ids)
        inputs = _sealed_inputs(sealed_input_hashes)
        if (
            len(ids) != 4
            or len(set(ids)) != 4
            or len(hashes) != 4
            or len(dependencies) != 4
            or dependencies != ("", ids[0], ids[1], ids[2])
        ):
            raise ValueError("member evidence requires one exact four-operation lineage")
        fields = {
            "member_id": _required_text(member_id, "member_id"),
            "interaction_id": _required_text(interaction_id, "interaction_id"),
            "operation_ids": list(ids),
            "operation_payload_hashes": list(hashes),
            "dependency_operation_ids": list(dependencies),
            "sealed_input_hashes": [list(item) for item in inputs],
        }
        return cls(
            fields["member_id"],
            fields["interaction_id"],
            ids,
            hashes,
            dependencies,
            inputs,
            payload_hash(fields),
        )


@dataclass(frozen=True, slots=True, repr=False)
class GraphCanaryExpansionCutoverEvidence:
    """Sealed authority for one to four graphs after a proved cap-one STOP."""

    run_id: str
    approval_id: str
    checkpoint_event_id: str
    members: tuple[GraphCanaryMemberCutoverEvidence, ...]
    cutover_evidence_ref: str
    credential_isolation_evidence_ref: str
    credential: GraphCanaryCredentialEvidence
    seal_hash: str

    def __repr__(self) -> str:
        return "<GraphCanaryExpansionCutoverEvidence redacted>"

    @classmethod
    def seal(
        cls,
        *,
        run_id: str,
        approval_id: str,
        checkpoint_event_id: str,
        members: Iterable[GraphCanaryMemberCutoverEvidence],
        cutover_evidence_ref: str,
        credential_isolation_evidence_ref: str,
        credential: GraphCanaryCredentialEvidence,
    ) -> GraphCanaryExpansionCutoverEvidence:
        member_tuple = tuple(members)
        if not 1 <= len(member_tuple) <= 4 or any(
            not isinstance(member, GraphCanaryMemberCutoverEvidence)
            for member in member_tuple
        ):
            raise ValueError("expansion evidence requires one to four sealed members")
        if len({member.member_id for member in member_tuple}) != len(member_tuple):
            raise ValueError("expansion members must be distinct")
        if not isinstance(credential, GraphCanaryCredentialEvidence):
            raise TypeError("credential evidence is required")
        fields = {
            "run_id": _required_text(run_id, "run_id"),
            "approval_id": _required_text(approval_id, "approval_id"),
            "checkpoint_event_id": _required_text(
                checkpoint_event_id, "checkpoint_event_id"
            ),
            "member_seal_hashes": [member.seal_hash for member in member_tuple],
            "cutover_evidence_ref": _required_text(
                cutover_evidence_ref, "cutover_evidence_ref"
            ),
            "credential_isolation_evidence_ref": _required_text(
                credential_isolation_evidence_ref,
                "credential_isolation_evidence_ref",
            ),
            "credential": _credential_payload(credential),
        }
        return cls(
            fields["run_id"],
            fields["approval_id"],
            fields["checkpoint_event_id"],
            member_tuple,
            fields["cutover_evidence_ref"],
            fields["credential_isolation_evidence_ref"],
            credential,
            payload_hash(fields),
        )


@dataclass(frozen=True, slots=True, repr=False)
class GraphCanaryWriterLease:
    connector: str
    run_id: str
    owner_id: str
    fence_token: int
    lease_until_utc: str

    def __repr__(self) -> str:
        return "<GraphCanaryWriterLease redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class GraphCanaryDispatchPermit:
    connector: str
    run_id: str
    member_id: str
    approval_id: str
    operation_id: str
    operation_type: str
    action: str
    payload_hash: str
    correlation_token: str
    fence_token: int
    operation_lease_token: str
    dependency_remote_ids: tuple[tuple[str, str], ...]

    def __repr__(self) -> str:
        return "<GraphCanaryDispatchPermit redacted>"


def _required_text(value: object, label: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise ValueError(f"{label} is required")
    return result


def _exact_hash(value: object, label: str) -> str:
    result = _required_text(value, label)
    if len(result) != 64 or any(ch not in "0123456789abcdef" for ch in result):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return result


def _safe_hash(value: object) -> str:
    result = str(value or "")
    return (
        result
        if len(result) == 64
        and all(ch in "0123456789abcdef" for ch in result)
        else ""
    )


def _sealed_inputs(
    values: Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    result = tuple(
        sorted(
            (
                _required_text(name, "sealed input name"),
                _exact_hash(digest, "sealed input hash"),
            )
            for name, digest in values
        )
    )
    if not result or len({name for name, _ in result}) != len(result):
        raise ValueError("sealed_input_hashes must have unique names")
    return result


def _future(seconds: int) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=max(1, int(seconds)))
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def _credential_payload(value: GraphCanaryCredentialEvidence) -> dict[str, object]:
    return {
        "credential_fingerprint": str(value.credential_fingerprint),
        "granted_scopes": list(value.granted_scopes),
        "owner_accepted_existing_credential": bool(
            value.owner_accepted_existing_credential
        ),
        "evidence_ref": str(value.evidence_ref),
    }


class BitrixGraphCanaryControl:
    """Own the durable cap-one graph canary admission and writer fence."""

    def __init__(self, store: FactoryStore):
        self.store = store
        self.graph_outbox = CrmGraphOutbox(store)

    def _assert_schema17_tx(self, con: Any) -> None:
        if (
            CURRENT_SCHEMA_VERSION != 17
            or int(self.store._probe_schema(con)) != 17
            or str(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
            )
            != "17"
        ):
            raise CanaryControlError("Bitrix graph canary requires schema exactly 17")

    def create_run(self, *, created_by: str, run_id: str = "") -> str:
        actor = _required_text(created_by, "created_by")
        rid = _required_text(run_id or new_lf_id("graph_canary_run"), "run_id")
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            existing = con.execute(
                "SELECT * FROM canary_runs WHERE run_id=?", (rid,)
            ).fetchone()
            if existing:
                if (
                    str(existing["connector"]) != BITRIX_GRAPH_CANARY_CONNECTOR
                    or str(existing["created_by"]) != actor
                ):
                    raise IdempotencyConflict("graph canary run id has another identity")
                return rid
            con.execute(
                """INSERT INTO canary_runs(
                       run_id,connector,state,created_by,created_at_utc
                   ) VALUES(?,?,?,?,?)""",
                (rid, BITRIX_GRAPH_CANARY_CONNECTOR, "DRAFT", actor, now),
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_run_created",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer=_PRODUCER,
                idempotency_key=f"graph-canary-run:{rid}",
                payload={"connector": BITRIX_GRAPH_CANARY_CONNECTOR},
                actor=actor,
            )
        return rid

    def create_cap_one_approval(
        self,
        run_id: str,
        *,
        approver: str,
        evidence_ref: str,
        approval_id: str = "",
    ) -> str:
        rid = _required_text(run_id, "run_id")
        actor = _required_text(approver, "approver")
        evidence = _required_text(evidence_ref, "evidence_ref")
        aid = _required_text(
            approval_id or new_lf_id("graph_canary_approval"), "approval_id"
        )
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, rid)
            if str(run["state"]) != "DRAFT":
                raise CanaryApprovalRequired("cap-one approval requires a DRAFT run")
            existing = con.execute(
                "SELECT * FROM canary_approvals WHERE approval_id=?", (aid,)
            ).fetchone()
            if existing:
                if (
                    str(existing["run_id"]),
                    int(existing["approval_sequence"]),
                    int(existing["cumulative_cap"]),
                    str(existing["approver"]),
                    str(existing["evidence_ref"]),
                    str(existing["checkpoint_event_id"]),
                ) != (rid, 1, 1, actor, evidence, ""):
                    raise IdempotencyConflict("approval replay changed immutable content")
                return aid
            if con.execute(
                "SELECT 1 FROM canary_approvals WHERE run_id=?", (rid,)
            ).fetchone():
                raise CanaryApprovalRequired("graph canary admits one cap-one approval only")
            con.execute(
                """INSERT INTO canary_approvals(
                       approval_id,run_id,approval_sequence,cumulative_cap,approver,
                       evidence_ref,checkpoint_event_id,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (aid, rid, 1, 1, actor, evidence, "", now),
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_cap_one_approved",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer=_PRODUCER,
                idempotency_key=f"graph-canary-approval:{aid}",
                payload={
                    "approval_id": aid,
                    "approval_sequence": 1,
                    "cumulative_cap": 1,
                },
                evidence_ref=evidence,
                actor=actor,
            )
        return aid

    def record_cap_one_completion_checkpoint(
        self, run_id: str, *, actor: str, evidence_ref: str
    ) -> str:
        """Seal a stopped, fully SENT cap-one graph as 1->5 lineage proof."""

        rid = _required_text(run_id, "run_id")
        principal = _required_text(actor, "actor")
        evidence = _required_text(evidence_ref, "evidence_ref")
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, rid)
            if str(run["state"]) != "STOPPED" or not str(
                run["stopped_at_utc"] or ""
            ):
                raise CanaryScopeMismatch(
                    "cap-one completion checkpoint requires an irreversible STOP"
                )
            approval = self._exact_approval_tx(con, rid, expected_cap=1)
            operations = self._assert_exact_bound_graph_tx(con, run_id=rid)
            original_binding = con.execute(
                """SELECT member_id FROM canary_operation_bindings
                   WHERE run_id=? LIMIT 1""",
                (rid,),
            ).fetchone()
            proof = []
            remote_types = ("company", "contact", "deal", "activity")
            for operation, remote_type in zip(
                operations, remote_types, strict=True
            ):
                remote_id = str(operation["remote_entity_id"] or "")
                if (
                    str(operation["state"]) != "SENT"
                    or str(operation["remote_entity_type"]) != remote_type
                    or not remote_id.isascii()
                    or not remote_id.isdigit()
                    or int(remote_id) < 1
                    or str(operation["updated_at_utc"]) > str(run["stopped_at_utc"])
                ):
                    raise CanaryScopeMismatch(
                        "checkpoint requires four positive SENT receipts before STOP"
                    )
                if remote_type != "activity" and not con.execute(
                    """SELECT 1 FROM crm_mappings
                       WHERE lf_entity_type=? AND lf_entity_id=?
                         AND remote_entity_type=? AND remote_entity_id=?
                         AND state='ACTIVE'""",
                    (
                        operation["lf_entity_type"],
                        operation["lf_entity_id"],
                        remote_type,
                        remote_id,
                    ),
                ).fetchone():
                    raise CanaryScopeMismatch(
                        "checkpoint requires exact ACTIVE graph mappings"
                    )
                proof.append(
                    {
                        "operation_id": str(operation["operation_id"]),
                        "operation_type": str(operation["operation_type"]),
                        "payload_hash": str(operation["payload_hash"]),
                        "remote_entity_type": remote_type,
                        "remote_entity_id": remote_id,
                        "state": "SENT",
                    }
                )
            cutover = con.execute(
                """SELECT payload_json,payload_hash,evidence_ref,event_id
                   FROM events WHERE producer=? AND idempotency_key=?""",
                (_PRODUCER, f"graph-canary-cutover:{rid}"),
            ).fetchone()
            stopped = con.execute(
                """SELECT event_id,payload_hash,evidence_ref
                   FROM events WHERE producer=? AND idempotency_key=?""",
                (_PRODUCER, f"graph-canary-stop:{rid}"),
            ).fetchone()
            if not cutover or not stopped:
                raise GraphCanaryEvidenceError(
                    "cap-one cutover and STOP evidence must both exist"
                )
            try:
                cutover_payload = json.loads(str(cutover["payload_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise GraphCanaryEvidenceError(
                    "cap-one cutover evidence payload is invalid"
                ) from exc
            if (
                not isinstance(cutover_payload, dict)
                or cutover_payload.get("approval_id") != approval["approval_id"]
                or cutover_payload.get("external_writers_enabled") is not True
                or not isinstance(cutover_payload.get("sealed_input_hashes"), list)
                or not str(cutover_payload.get("credential_evidence_hash", ""))
            ):
                raise GraphCanaryEvidenceError(
                    "cap-one cutover evidence is incomplete"
                )
            checkpoint_payload = {
                "approval_id": str(approval["approval_id"]),
                "cumulative_cap": 1,
                "member_id": str(original_binding["member_id"]),
                "cutover_event_id": str(cutover["event_id"]),
                "cutover_payload_hash": str(cutover["payload_hash"]),
                "cutover_seal_hash": str(
                    cutover_payload.get("cutover_seal_hash", "")
                ),
                "credential_evidence_hash": str(
                    cutover_payload["credential_evidence_hash"]
                ),
                "sealed_input_hashes": cutover_payload["sealed_input_hashes"],
                "stop_event_id": str(stopped["event_id"]),
                "stop_payload_hash": str(stopped["payload_hash"]),
                "operations": proof,
            }
            event, _ = self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_cap_one_completed",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer=_PRODUCER,
                idempotency_key=f"graph-canary-cap-one-completed:{rid}",
                payload=checkpoint_payload,
                evidence_ref=evidence,
                actor=principal,
            )
            return str(event["event_id"])

    def create_cap_five_expansion(
        self,
        *,
        run_id: str,
        checkpoint_event_id: str,
        approver: str,
        approval_evidence_ref: str,
        approval_id: str = "",
    ) -> tuple[str, str]:
        """Advance the same stopped cap-one run to a sealed cap-five DRAFT."""

        rid = _required_text(run_id, "run_id")
        checkpoint = _required_text(checkpoint_event_id, "checkpoint_event_id")
        owner = _required_text(approver, "approver")
        evidence = _required_text(
            approval_evidence_ref, "approval_evidence_ref"
        )
        aid = _required_text(
            approval_id or new_lf_id("graph_canary_expansion_approval"),
            "approval_id",
        )
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            checkpoint_payload = self._cap_one_checkpoint_tx(
                con, rid, checkpoint
            )
            run = self._run_tx(con, rid)
            existing_approval = con.execute(
                "SELECT * FROM canary_approvals WHERE approval_id=?", (aid,)
            ).fetchone()
            existing_cap_five = con.execute(
                """SELECT * FROM canary_approvals
                   WHERE run_id=? AND cumulative_cap=5""",
                (rid,),
            ).fetchone()
            if existing_approval or existing_cap_five:
                existing = existing_approval or existing_cap_five
                if (
                    str(existing["approval_id"]) != aid
                    or str(existing["run_id"]) != rid
                    or int(existing["approval_sequence"]) != 2
                    or int(existing["cumulative_cap"]) != 5
                    or str(existing["approver"]) != owner
                    or str(existing["evidence_ref"]) != evidence
                    or str(existing["checkpoint_event_id"]) != checkpoint
                    or str(run["state"]) != "DRAFT"
                ):
                    raise IdempotencyConflict(
                        "cap-five expansion replay changed immutable lineage"
                    )
                return rid, aid
            if str(run["state"]) != "STOPPED":
                raise CanaryControlError(
                    "cap-five approval requires the same completed STOPPED run"
                )
            con.execute(
                """INSERT INTO canary_approvals(
                       approval_id,run_id,approval_sequence,cumulative_cap,
                       approver,evidence_ref,checkpoint_event_id,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (aid, rid, 2, 5, owner, evidence, checkpoint, now),
            )
            con.execute(
                "UPDATE canary_runs SET state='DRAFT' WHERE run_id=? AND state='STOPPED'",
                (rid,),
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_cap_five_approved",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer=_PRODUCER,
                idempotency_key=f"graph-canary-cap-five:{aid}",
                payload={
                    "approval_id": aid,
                    "approval_sequence": 2,
                    "cumulative_cap": 5,
                    "original_run_id": rid,
                    "checkpoint_event_id": checkpoint,
                    "checkpoint_payload_hash": payload_hash(checkpoint_payload),
                },
                evidence_ref=evidence,
                actor=owner,
            )
        return rid, aid

    def arm_scope_member(
        self,
        run_id: str,
        *,
        mailbox: str,
        campaign_id: str,
        contact_address: str,
        canonical_thread: str,
        lf_opportunity_id: str,
        armed_by: str,
        evidence_ref: str,
        member_id: str = "",
    ) -> str:
        rid = _required_text(run_id, "run_id")
        box = canonical_mailbox(mailbox)
        campaign = canonical_campaign_id(campaign_id)
        contact = normalize_email(contact_address)
        thread = canonical_outbound_thread(canonical_thread)
        opportunity_id = _required_text(lf_opportunity_id, "lf_opportunity_id")
        actor = _required_text(armed_by, "armed_by")
        evidence = _required_text(evidence_ref, "evidence_ref")
        mid = _required_text(
            member_id or new_lf_id("graph_canary_member"), "member_id"
        )
        if not box or not campaign or not contact:
            raise ValueError("exact mailbox, campaign, and contact are required")
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, rid)
            if str(run["state"]) != "DRAFT":
                raise CanaryControlError("scope can only be armed on a DRAFT run")
            approval = self._approval_tx(con, rid)
            member_limit = int(approval["cumulative_cap"])
            if not con.execute(
                "SELECT 1 FROM opportunities WHERE lf_opportunity_id=?",
                (opportunity_id,),
            ).fetchone():
                raise KeyError("scope requires an existing opportunity")
            existing = con.execute(
                "SELECT * FROM canary_scope_members WHERE member_id=?", (mid,)
            ).fetchone()
            identity = (rid, box, campaign, contact, thread, opportunity_id)
            if existing:
                if tuple(
                    str(existing[key])
                    for key in (
                        "run_id",
                        "mailbox",
                        "campaign_id",
                        "contact_address",
                        "canonical_outbound_thread",
                        "lf_opportunity_id",
                    )
                ) != identity:
                    raise IdempotencyConflict("scope replay changed exact identity")
                return mid
            member_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM canary_scope_members WHERE run_id=?", (rid,)
                ).fetchone()[0]
            )
            if member_count >= member_limit:
                raise CanaryCapacityExceeded(
                    "graph canary scope exceeds its immutable cumulative cap"
                )
            con.execute(
                """INSERT INTO canary_scope_members(
                       member_id,run_id,mailbox,campaign_id,contact_address,
                       canonical_outbound_thread,lf_opportunity_id,armed_by,
                       evidence_ref,state,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    mid,
                    rid,
                    box,
                    campaign,
                    contact,
                    thread,
                    opportunity_id,
                    actor,
                    evidence,
                    "ARMED",
                    now,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_scope_armed",
                aggregate_type="canary_member",
                aggregate_id=mid,
                producer=_PRODUCER,
                idempotency_key=f"graph-canary-scope:{mid}",
                payload={"run_id": rid, "lf_opportunity_id": opportunity_id},
                evidence_ref=evidence,
                actor=actor,
            )
        return mid

    def bind_graph(
        self,
        run_id: str,
        *,
        member_id: str,
        interaction_id: str,
        operation_ids: Iterable[str],
        actor: str,
    ) -> bool:
        """Atomically bind the exact staged four-operation graph."""

        rid = _required_text(run_id, "run_id")
        mid = _required_text(member_id, "member_id")
        interaction = _required_text(interaction_id, "interaction_id")
        principal = _required_text(actor, "actor")
        operation_tuple = tuple(
            _required_text(value, "operation_id") for value in operation_ids
        )
        if len(operation_tuple) != 4 or len(set(operation_tuple)) != 4:
            raise CanaryScopeMismatch("exactly four distinct graph operations are required")
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, rid)
            if str(run["state"]) != "DRAFT":
                raise CanaryControlError("graph binding requires a DRAFT run")
            approval = self._approval_tx(con, rid)
            member = self._member_tx(con, rid, mid)
            observed = con.execute(
                """SELECT lf_opportunity_id,address,thread_id
                   FROM interactions WHERE lf_interaction_id=?""",
                (interaction,),
            ).fetchone()
            if not observed or (
                str(observed["lf_opportunity_id"] or "")
                != str(member["lf_opportunity_id"])
                or normalize_email(observed["address"])
                != normalize_email(member["contact_address"])
                or canonical_outbound_thread(observed["thread_id"])
                != str(member["canonical_outbound_thread"])
            ):
                raise CanaryScopeMismatch(
                    "interaction does not prove the exact armed scope member"
                )
            rows = []
            for operation_id, expected_type in zip(
                operation_tuple, GRAPH_OPERATION_ORDER, strict=True
            ):
                row = con.execute(
                    "SELECT * FROM crm_outbox WHERE operation_id=?", (operation_id,)
                ).fetchone()
                if not row or str(row["operation_type"]) != expected_type:
                    raise CanaryScopeMismatch(
                        "operation ids are not the exact ordered CRM graph"
                    )
                if str(row["state"]) != "PENDING":
                    raise CanaryScopeMismatch("graph binding requires PENDING operations")
                self.graph_outbox._validate_operation_tx(
                    con, row, require_sent=False
                )
                rows.append(row)
            if str(rows[-1]["lf_entity_id"]) != str(member["lf_opportunity_id"]):
                raise CanaryScopeMismatch("graph belongs to another opportunity")
            existing = con.execute(
                """SELECT * FROM canary_operation_bindings
                   WHERE operation_id IN (?,?,?,?) ORDER BY operation_type""",
                operation_tuple,
            ).fetchall()
            if existing:
                if len(existing) != 4:
                    raise IdempotencyConflict("graph has an incomplete immutable binding")
                by_type = {str(row["operation_type"]): row for row in existing}
                if set(by_type) != set(GRAPH_OPERATION_ORDER) or any(
                    str(by_type[operation_type]["operation_id"])
                    != operation_tuple[index]
                    or str(by_type[operation_type]["run_id"]) != rid
                    or str(by_type[operation_type]["member_id"]) != mid
                    or str(by_type[operation_type]["approval_id"])
                    != str(approval["approval_id"])
                    or str(by_type[operation_type]["interaction_id"]) != interaction
                    for index, operation_type in enumerate(GRAPH_OPERATION_ORDER)
                ):
                    raise IdempotencyConflict("graph operations have another canary binding")
                return False
            member_limit = int(approval["cumulative_cap"])
            used_members = int(
                con.execute(
                    """SELECT COUNT(DISTINCT member_id)
                       FROM canary_operation_bindings WHERE run_id=?""",
                    (rid,),
                ).fetchone()[0]
            )
            if used_members >= member_limit:
                raise CanaryCapacityExceeded(
                    "graph run has consumed its immutable member capacity"
                )
            for operation_id, operation_type in zip(
                operation_tuple, GRAPH_OPERATION_ORDER, strict=True
            ):
                con.execute(
                    """INSERT INTO canary_operation_bindings(
                           operation_id,run_id,member_id,approval_id,operation_type,
                           interaction_id,created_at_utc
                       ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        operation_id,
                        rid,
                        mid,
                        approval["approval_id"],
                        operation_type,
                        interaction,
                        now,
                    ),
                )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_graph_bound",
                aggregate_type="canary_member",
                aggregate_id=mid,
                producer=_PRODUCER,
                idempotency_key=f"graph-canary-bound:{rid}:{mid}:{interaction}",
                payload={
                    "approval_id": str(approval["approval_id"]),
                    "cumulative_cap": int(approval["cumulative_cap"]),
                    "interaction_id": interaction,
                    "operations": [
                        {
                            "operation_id": operation_id,
                            "operation_type": operation_type,
                        }
                        for operation_id, operation_type in zip(
                            operation_tuple, GRAPH_OPERATION_ORDER, strict=True
                        )
                    ],
                },
                actor=principal,
            )
        return True

    def activate_cutover(
        self, evidence: GraphCanaryCutoverEvidence, *, actor: str
    ) -> bool:
        """Atomically activate the exact sealed cap-one run and writer gate."""

        principal = _required_text(actor, "actor")
        self._assert_sealed_evidence(evidence)
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, evidence.run_id)
            if str(run["state"]) == "STOPPED":
                raise CanaryControlError("stopped graph canary cannot be reactivated")
            approval = self._exact_approval_tx(con, evidence.run_id)
            if (
                str(approval["approval_id"]) != evidence.approval_id
                or str(approval["evidence_ref"])
                != evidence.owner_approval_evidence_ref
            ):
                raise GraphCanaryEvidenceError(
                    "sealed owner approval does not match immutable approval"
                )
            self._assert_exact_bound_graph_tx(
                con,
                run_id=evidence.run_id,
                member_id=evidence.member_id,
                interaction_id=evidence.interaction_id,
                operation_ids=evidence.operation_ids,
                operation_payload_hashes=evidence.operation_payload_hashes,
            )
            prior = con.execute(
                """SELECT payload_hash,evidence_ref FROM events
                   WHERE producer=? AND idempotency_key=?""",
                (_PRODUCER, f"graph-canary-cutover:{evidence.run_id}"),
            ).fetchone()
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            event_payload = {
                "approval_id": evidence.approval_id,
                "member_id": evidence.member_id,
                "interaction_id": evidence.interaction_id,
                "operation_ids": list(evidence.operation_ids),
                "operation_payload_hashes": list(evidence.operation_payload_hashes),
                "sealed_input_hashes": [
                    list(item) for item in evidence.sealed_input_hashes
                ],
                "credential_evidence_hash": payload_hash(
                    _credential_payload(evidence.credential)
                ),
                "cutover_seal_hash": evidence.seal_hash,
                "external_writers_enabled": True,
            }
            if str(run["state"]) == "ACTIVE":
                if (
                    not prior
                    or str(prior["payload_hash"]) != payload_hash(event_payload)
                    or str(prior["evidence_ref"]) != evidence.cutover_evidence_ref
                    or not writer
                    or str(writer[0]) != "1"
                ):
                    raise IdempotencyConflict("active cutover replay changed sealed state")
                return False
            if str(run["state"]) != "DRAFT" or not writer or str(writer[0]) != "0":
                raise CanaryControlError("cutover requires one DRAFT run and writers off")
            other_active = con.execute(
                """SELECT 1 FROM canary_runs
                   WHERE state='ACTIVE' AND run_id<>?""",
                (evidence.run_id,),
            ).fetchone()
            if other_active:
                raise CanaryControlError("another canary run is active")
            unrelated_work = con.execute(
                """SELECT 1 FROM crm_outbox o
                   WHERE o.state IN ('PENDING','RETRY','LEASED','UNCERTAIN')
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=o.operation_id AND b.run_id=?
                     ) LIMIT 1""",
                (evidence.run_id,),
            ).fetchone()
            if unrelated_work:
                raise CanaryCapacityExceeded(
                    "writer cutover would expose CRM work outside the cap-one graph"
                )
            con.execute(
                """UPDATE canary_runs SET state='ACTIVE',activated_at_utc=?
                   WHERE run_id=? AND state='DRAFT'""",
                (now, evidence.run_id),
            )
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_cutover_activated",
                aggregate_type="canary_run",
                aggregate_id=evidence.run_id,
                producer=_PRODUCER,
                idempotency_key=f"graph-canary-cutover:{evidence.run_id}",
                payload=event_payload,
                evidence_ref=evidence.cutover_evidence_ref,
                actor=principal,
            )
        return True

    def activate_expansion_cutover(
        self, evidence: GraphCanaryExpansionCutoverEvidence, *, actor: str
    ) -> bool:
        """Activate one linked cap-five run containing at most four new graphs."""

        principal = _required_text(actor, "actor")
        self._assert_expansion_evidence(evidence)
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, evidence.run_id)
            if str(run["state"]) == "STOPPED":
                raise CanaryControlError("stopped expansion cannot be reactivated")
            approval = self._exact_approval_tx(
                con, evidence.run_id, expected_cap=5
            )
            if (
                str(approval["approval_id"]) != evidence.approval_id
                or str(approval["checkpoint_event_id"])
                != evidence.checkpoint_event_id
            ):
                raise GraphCanaryEvidenceError(
                    "expansion approval does not match sealed checkpoint lineage"
                )
            checkpoint_event = con.execute(
                """SELECT aggregate_id FROM events WHERE event_id=?""",
                (evidence.checkpoint_event_id,),
            ).fetchone()
            if not checkpoint_event:
                raise GraphCanaryEvidenceError("expansion checkpoint disappeared")
            checkpoint = self._cap_one_checkpoint_tx(
                con,
                str(checkpoint_event["aggregate_id"]),
                evidence.checkpoint_event_id,
            )
            credential_hash = payload_hash(
                _credential_payload(evidence.credential)
            )
            predecessor_credential_hash = str(
                checkpoint["credential_evidence_hash"]
            )
            if credential_hash == predecessor_credential_hash:
                raise GraphCanaryEvidenceError(
                    "expansion credential evidence must differ from cap-one"
                )
            try:
                checkpoint_inputs = tuple(
                    sorted(
                        (str(item[0]), str(item[1]))
                        for item in checkpoint["sealed_input_hashes"]
                    )
                )
            except (TypeError, ValueError, IndexError) as exc:
                raise GraphCanaryEvidenceError(
                    "checkpoint input bindings are invalid"
                ) from exc
            database_members = con.execute(
                """SELECT member_id FROM canary_scope_members
                   WHERE run_id=? AND member_id<>?""",
                (evidence.run_id, str(checkpoint["member_id"])),
            ).fetchall()
            durable_member_ids = {str(row[0]) for row in database_members}
            sealed_member_ids = {member.member_id for member in evidence.members}
            if (
                len(database_members) != len(evidence.members)
                or durable_member_ids != sealed_member_ids
            ):
                raise CanaryScopeMismatch(
                    "sealed expansion member set differs from durable scope"
                )
            cohort_hash, candidate_bindings = self._expansion_input_contract(
                evidence.members, checkpoint_inputs
            )
            all_operation_ids: set[str] = set()
            for member in evidence.members:
                self._assert_member_bound_graph_tx(
                    con,
                    run_id=evidence.run_id,
                    member_id=member.member_id,
                    interaction_id=member.interaction_id,
                    operation_ids=member.operation_ids,
                    operation_payload_hashes=member.operation_payload_hashes,
                    dependency_operation_ids=member.dependency_operation_ids,
                )
                if all_operation_ids.intersection(member.operation_ids):
                    raise GraphCanaryEvidenceError(
                        "expansion graphs cannot share an operation"
                    )
                all_operation_ids.update(member.operation_ids)
            prior = con.execute(
                """SELECT payload_hash,evidence_ref FROM events
                   WHERE producer=? AND idempotency_key=?""",
                (_PRODUCER, f"graph-canary-expansion-cutover:{evidence.run_id}"),
            ).fetchone()
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            event_payload = {
                "approval_id": evidence.approval_id,
                "checkpoint_event_id": evidence.checkpoint_event_id,
                "member_seal_hashes": [
                    member.seal_hash for member in evidence.members
                ],
                "expansion_cohort_hash": cohort_hash,
                "expansion_candidates": candidate_bindings,
                "predecessor_credential_evidence_hash": (
                    predecessor_credential_hash
                ),
                "expansion_credential_evidence_hash": credential_hash,
                "credential_isolation_evidence_ref": (
                    evidence.credential_isolation_evidence_ref
                ),
                "cutover_seal_hash": evidence.seal_hash,
                "cumulative_cap": 5,
                "additional_member_count": len(evidence.members),
                "external_writers_enabled": True,
            }
            if str(run["state"]) == "ACTIVE":
                if (
                    not prior
                    or str(prior["payload_hash"]) != payload_hash(event_payload)
                    or str(prior["evidence_ref"]) != evidence.cutover_evidence_ref
                    or not writer
                    or str(writer[0]) != "1"
                ):
                    raise IdempotencyConflict(
                        "active expansion replay changed sealed state"
                    )
                return False
            if str(run["state"]) != "DRAFT" or not writer or str(writer[0]) != "0":
                raise CanaryControlError(
                    "expansion cutover requires DRAFT state and writers off"
                )
            if con.execute(
                "SELECT 1 FROM canary_runs WHERE state='ACTIVE' AND run_id<>?",
                (evidence.run_id,),
            ).fetchone():
                raise CanaryControlError("another canary run is active")
            if con.execute(
                """SELECT 1 FROM crm_outbox o
                   WHERE o.state IN ('PENDING','RETRY','LEASED','UNCERTAIN')
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=o.operation_id AND b.run_id=?
                     ) LIMIT 1""",
                (evidence.run_id,),
            ).fetchone():
                raise CanaryCapacityExceeded(
                    "expansion cutover would expose unrelated CRM work"
                )
            con.execute(
                """UPDATE canary_runs SET state='ACTIVE',activated_at_utc=?
                   WHERE run_id=? AND state='DRAFT'""",
                (now, evidence.run_id),
            )
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_expansion_activated",
                aggregate_type="canary_run",
                aggregate_id=evidence.run_id,
                producer=_PRODUCER,
                idempotency_key=(
                    f"graph-canary-expansion-cutover:{evidence.run_id}"
                ),
                payload=event_payload,
                evidence_ref=evidence.cutover_evidence_ref,
                actor=principal,
            )
        return True

    def acquire_writer_lease(
        self, run_id: str, *, owner_id: str, lease_seconds: int = 120
    ) -> GraphCanaryWriterLease:
        rid = _required_text(run_id, "run_id")
        owner = _required_text(owner_id, "owner_id")
        now = utc_now()
        until = _future(lease_seconds)
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            self._active_run_tx(con, rid)
            self._assert_active_bound_run_tx(con, run_id=rid)
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            if not writer or str(writer[0]) != "1":
                raise CanaryStaleLease("writer gate is closed")
            con.execute(
                "INSERT OR IGNORE INTO connector_writer_leases(connector) VALUES(?)",
                (BITRIX_GRAPH_CANARY_CONNECTOR,),
            )
            current = con.execute(
                "SELECT * FROM connector_writer_leases WHERE connector=?",
                (BITRIX_GRAPH_CANARY_CONNECTOR,),
            ).fetchone()
            active = bool(
                current["owner_id"]
                and current["lease_until_utc"]
                and str(current["lease_until_utc"]) > now
            )
            if active and (
                str(current["run_id"]) != rid
                or str(current["owner_id"]) != owner
            ):
                raise CanaryLeaseUnavailable("graph writer lease is already owned")
            fence = int(current["fence_token"]) + 1
            con.execute(
                """UPDATE connector_writer_leases
                   SET run_id=?,owner_id=?,fence_token=?,lease_until_utc=?,
                       acquired_at_utc=?,updated_at_utc=? WHERE connector=?""",
                (
                    rid,
                    owner,
                    fence,
                    until,
                    now,
                    now,
                    BITRIX_GRAPH_CANARY_CONNECTOR,
                ),
            )
        return GraphCanaryWriterLease(
            BITRIX_GRAPH_CANARY_CONNECTOR, rid, owner, fence, until
        )

    def claim_next_graph_operation(
        self,
        lease: GraphCanaryWriterLease,
        *,
        operation_lease_seconds: int = 120,
    ) -> GraphCanaryDispatchPermit | None:
        """Move only the next eligible bound PENDING operation to UNCERTAIN."""

        now = utc_now()
        until = _future(operation_lease_seconds)
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            self._assert_writer_lease_tx(con, lease, now)
            rows = self._assert_active_bound_run_tx(
                con, run_id=lease.run_id
            )
            selected = None
            for index, row in enumerate(rows):
                state = str(row["state"])
                if state == "SENT":
                    continue
                if state != "PENDING":
                    return None
                if any(str(rows[prior]["state"]) != "SENT" for prior in range(index)):
                    return None
                if str(row["next_attempt_at_utc"] or "") > now:
                    return None
                if (
                    str(row["lease_until_utc"] or "")
                    and str(row["lease_until_utc"]) > now
                ):
                    return None
                dependencies = self.graph_outbox._validate_operation_tx(
                    con, row, require_sent=True
                )
                selected = row
                break
            if selected is None:
                return None
            operation_type = str(selected["operation_type"])
            action = f"CREATE:{operation_type}"
            token = f"graph-canary:{action}:{new_lf_id('graph_dispatch')}"
            changed = con.execute(
                """UPDATE crm_outbox
                   SET state='UNCERTAIN',attempt_count=attempt_count+1,
                       leased_by=?,lease_token=?,lease_until_utc=?,updated_at_utc=?
                   WHERE operation_id=? AND operation_type=? AND state='PENDING'
                     AND (lease_until_utc='' OR lease_until_utc<=?)""",
                (
                    lease.owner_id,
                    token,
                    until,
                    now,
                    selected["operation_id"],
                    operation_type,
                    now,
                ),
            )
            if changed.rowcount != 1:
                return None
            binding = con.execute(
                """SELECT run_id,member_id,approval_id
                   FROM canary_operation_bindings WHERE operation_id=?""",
                (selected["operation_id"],),
            ).fetchone()
            return GraphCanaryDispatchPermit(
                BITRIX_GRAPH_CANARY_CONNECTOR,
                str(binding["run_id"]),
                str(binding["member_id"]),
                str(binding["approval_id"]),
                str(selected["operation_id"]),
                operation_type,
                action,
                str(selected["payload_hash"]),
                str(selected["correlation_token"]),
                int(lease.fence_token),
                token,
                tuple(sorted(dependencies.items())),
            )

    def assert_dispatch_permit_tx(
        self,
        con: Any,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        *,
        operation_id: str,
    ) -> None:
        """Assert one CREATE permit inside the caller's existing transaction."""

        self._assert_schema17_tx(con)
        operation = _required_text(operation_id, "operation_id")
        if (
            not isinstance(permit, GraphCanaryDispatchPermit)
            or not isinstance(lease, GraphCanaryWriterLease)
            or permit.connector != BITRIX_GRAPH_CANARY_CONNECTOR
            or lease.connector != BITRIX_GRAPH_CANARY_CONNECTOR
            or permit.operation_id != operation
            or permit.run_id != lease.run_id
            or int(permit.fence_token) != int(lease.fence_token)
            or permit.action != f"CREATE:{permit.operation_type}"
            or permit.operation_type not in GRAPH_OPERATION_ORDER
            or not permit.operation_lease_token.startswith(
                f"graph-canary:{permit.action}:lf_graph_dispatch_"
            )
        ):
            raise CanaryStaleLease("permit is not action-bound to this operation")
        now = utc_now()
        self._assert_writer_lease_tx(con, lease, now)
        row = con.execute(
            """SELECT o.*,b.run_id,b.member_id,b.approval_id,
                      b.operation_type AS binding_operation_type,b.interaction_id
               FROM crm_outbox o JOIN canary_operation_bindings b
                 ON b.operation_id=o.operation_id
               WHERE o.operation_id=?""",
            (operation,),
        ).fetchone()
        if (
            not row
            or str(row["state"]) != "UNCERTAIN"
            or str(row["operation_type"]) != permit.operation_type
            or str(row["binding_operation_type"]) != permit.operation_type
            or str(row["run_id"]) != permit.run_id
            or str(row["member_id"]) != permit.member_id
            or str(row["approval_id"]) != permit.approval_id
            or str(row["payload_hash"]) != permit.payload_hash
            or str(row["correlation_token"]) != permit.correlation_token
            or str(row["leased_by"]) != lease.owner_id
            or str(row["lease_token"]) != permit.operation_lease_token
            or not str(row["lease_until_utc"] or "")
            or str(row["lease_until_utc"]) <= now
        ):
            raise CanaryStaleLease("permit no longer proves the bound operation")
        dependencies = self.graph_outbox._validate_operation_tx(
            con, row, require_sent=True
        )
        if tuple(sorted(dependencies.items())) != permit.dependency_remote_ids:
            raise GraphInvariantError("permit dependency identities changed")

    def mark_sent(
        self,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        readback: CrmGraphReadback,
        *,
        actor: str,
        _transaction: Any | None = None,
    ) -> None:
        """Durably commit one exact, readback-proved remote create."""

        principal = _required_text(actor, "actor")
        now = utc_now()
        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction(min_schema_version=17)
        )
        with transaction as con:
            self.assert_dispatch_permit_tx(
                con, permit, lease, operation_id=permit.operation_id
            )
            current = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?",
                (permit.operation_id,),
            ).fetchone()
            operation = dict(current)
            operation["_dependency_remote_ids"] = dict(
                permit.dependency_remote_ids
            )
            verified = self.graph_outbox._verify_readback(operation, readback)
            remote_id = str(verified.remote_id)
            remote_type = {
                COMPANY_CREATE: "company",
                CONTACT_CREATE: "contact",
                DEAL_CREATE: "deal",
                ACTIVITY_CREATE: "activity",
            }[permit.operation_type]
            duplicate = con.execute(
                """SELECT operation_id FROM crm_outbox
                   WHERE operation_id<>? AND remote_entity_type=?
                     AND remote_entity_id=? AND state='SENT'""",
                (permit.operation_id, remote_type, remote_id),
            ).fetchone()
            if duplicate:
                raise MappingConflict(
                    "remote CRM identity is already owned by another operation"
                )
            if remote_type != "activity":
                lf_type = str(current["lf_entity_type"])
                lf_id = str(current["lf_entity_id"])
                local = con.execute(
                    """SELECT remote_entity_type,remote_entity_id,state
                       FROM crm_mappings
                       WHERE lf_entity_type=? AND lf_entity_id=?""",
                    (lf_type, lf_id),
                ).fetchone()
                if local and (
                    str(local["remote_entity_type"]),
                    str(local["remote_entity_id"]),
                    str(local["state"]),
                ) != (remote_type, remote_id, "ACTIVE"):
                    raise MappingConflict("local entity maps to another CRM identity")
                remote = con.execute(
                    """SELECT lf_entity_type,lf_entity_id,state
                       FROM crm_mappings
                       WHERE remote_entity_type=? AND remote_entity_id=?""",
                    (remote_type, remote_id),
                ).fetchone()
                if remote and (
                    str(remote["lf_entity_type"]),
                    str(remote["lf_entity_id"]),
                    str(remote["state"]),
                ) != (lf_type, lf_id, "ACTIVE"):
                    raise MappingConflict("remote entity maps to another LF identity")
                if not local:
                    con.execute(
                        """INSERT INTO crm_mappings(
                               lf_entity_type,lf_entity_id,remote_entity_type,
                               remote_entity_id,state,last_readback_at_utc,created_at_utc
                           ) VALUES(?,?,?,?,?,?,?)""",
                        (
                            lf_type,
                            lf_id,
                            remote_type,
                            remote_id,
                            "ACTIVE",
                            now,
                            now,
                        ),
                    )
                else:
                    con.execute(
                        """UPDATE crm_mappings SET last_readback_at_utc=?
                           WHERE lf_entity_type=? AND lf_entity_id=?""",
                        (now, lf_type, lf_id),
                    )
            changed = con.execute(
                """UPDATE crm_outbox
                   SET state='SENT',remote_entity_type=?,remote_entity_id=?,
                       lease_until_utc='',leased_by='',lease_token='',
                       next_attempt_at_utc='',last_error_class='',last_error_hash='',
                       suspect_remote_entity_type='',suspect_remote_entity_id='',
                       updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN' AND lease_token=?""",
                (
                    remote_type,
                    remote_id,
                    now,
                    permit.operation_id,
                    permit.operation_lease_token,
                ),
            )
            if changed.rowcount != 1:
                raise CanaryStaleLease("operation lease changed before SENT commit")
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_operation_sent",
                aggregate_type=str(current["lf_entity_type"]),
                aggregate_id=str(current["lf_entity_id"]),
                producer=_PRODUCER,
                idempotency_key=(
                    f"graph-canary-sent:{permit.operation_id}:{remote_type}:{remote_id}"
                ),
                payload={
                    "run_id": permit.run_id,
                    "operation_id": permit.operation_id,
                    "operation_type": permit.operation_type,
                    "remote_entity_type": remote_type,
                    "remote_entity_id": remote_id,
                },
                actor=principal,
            )

    def mark_sent_tx(
        self,
        con: Any,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        readback: CrmGraphReadback,
        *,
        actor: str,
    ) -> None:
        """Commit SENT inside the transaction that guarded the external call."""

        self.mark_sent(
            permit,
            lease,
            readback,
            actor=actor,
            _transaction=con,
        )

    def mark_uncertain(
        self,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        *,
        error_class: str,
        actor: str,
    ) -> None:
        """Persist an ambiguous outcome without making it eligible to recreate."""

        self._mark_terminal_dispatch_state(
            permit,
            lease,
            state="UNCERTAIN",
            error_class=error_class,
            actor=actor,
        )

    def mark_uncertain_tx(
        self,
        con: Any,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        *,
        error_class: str,
        actor: str,
    ) -> None:
        self._mark_terminal_dispatch_state(
            permit,
            lease,
            state="UNCERTAIN",
            error_class=error_class,
            actor=actor,
            _transaction=con,
        )

    def mark_review(
        self,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        *,
        error_class: str,
        actor: str,
    ) -> None:
        """Quarantine a proven mismatch without losing its immutable binding."""

        self._mark_terminal_dispatch_state(
            permit,
            lease,
            state="REVIEW",
            error_class=error_class,
            actor=actor,
        )

    def mark_review_tx(
        self,
        con: Any,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        *,
        error_class: str,
        actor: str,
    ) -> None:
        self._mark_terminal_dispatch_state(
            permit,
            lease,
            state="REVIEW",
            error_class=error_class,
            actor=actor,
            _transaction=con,
        )

    def reconcile_stopped_operation(
        self,
        run_id: str,
        *,
        operation_id: str,
        readback: CrmGraphReadback,
        actor: str,
        evidence_ref: str,
    ) -> None:
        """Commit exact read-only reconciliation while every writer is off."""

        rid = _required_text(run_id, "run_id")
        operation = _required_text(operation_id, "operation_id")
        principal = _required_text(actor, "actor")
        evidence = _required_text(evidence_ref, "evidence_ref")
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, rid)
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            if str(run["state"]) != "STOPPED" or not writer or str(writer[0]) != "0":
                raise CanaryControlError(
                    "read-only reconciliation requires a stopped writer-off run"
                )
            rows = self._assert_exact_bound_graph_tx(con, run_id=rid)
            selected = next(
                (row for row in rows if str(row["operation_id"]) == operation), None
            )
            if selected is None or str(selected["state"]) not in {"REVIEW", "UNCERTAIN"}:
                raise CanaryScopeMismatch(
                    "reconciliation target is not an exact ambiguous bound operation"
                )
            index = GRAPH_OPERATION_ORDER.index(str(selected["operation_type"]))
            if any(str(rows[prior]["state"]) != "SENT" for prior in range(index)):
                raise GraphInvariantError("reconciliation dependency is not SENT")
            dependencies = self.graph_outbox._validate_operation_tx(
                con, selected, require_sent=True
            )
            envelope = dict(selected)
            envelope["_dependency_remote_ids"] = dependencies
            verified = self.graph_outbox._verify_readback(envelope, readback)
            remote_type = {
                COMPANY_CREATE: "company",
                CONTACT_CREATE: "contact",
                DEAL_CREATE: "deal",
                ACTIVITY_CREATE: "activity",
            }[str(selected["operation_type"])]
            remote_id = str(verified.remote_id)
            duplicate = con.execute(
                """SELECT operation_id FROM crm_outbox
                   WHERE operation_id<>? AND remote_entity_type=?
                     AND remote_entity_id=? AND state='SENT'""",
                (operation, remote_type, remote_id),
            ).fetchone()
            if duplicate:
                raise MappingConflict(
                    "reconciled CRM identity belongs to another operation"
                )
            if remote_type != "activity":
                lf_type = str(selected["lf_entity_type"])
                lf_id = str(selected["lf_entity_id"])
                local = con.execute(
                    """SELECT remote_entity_type,remote_entity_id,state
                       FROM crm_mappings WHERE lf_entity_type=? AND lf_entity_id=?""",
                    (lf_type, lf_id),
                ).fetchone()
                remote = con.execute(
                    """SELECT lf_entity_type,lf_entity_id,state FROM crm_mappings
                       WHERE remote_entity_type=? AND remote_entity_id=?""",
                    (remote_type, remote_id),
                ).fetchone()
                if local and (
                    str(local["remote_entity_type"]),
                    str(local["remote_entity_id"]),
                    str(local["state"]),
                ) != (remote_type, remote_id, "ACTIVE"):
                    raise MappingConflict("local entity maps to another CRM identity")
                if remote and (
                    str(remote["lf_entity_type"]),
                    str(remote["lf_entity_id"]),
                    str(remote["state"]),
                ) != (lf_type, lf_id, "ACTIVE"):
                    raise MappingConflict("remote entity maps to another LF identity")
                if not local:
                    con.execute(
                        """INSERT INTO crm_mappings(
                               lf_entity_type,lf_entity_id,remote_entity_type,
                               remote_entity_id,state,last_readback_at_utc,created_at_utc
                           ) VALUES(?,?,?,?,?,?,?)""",
                        (lf_type, lf_id, remote_type, remote_id, "ACTIVE", now, now),
                    )
            changed = con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type=?,
                       remote_entity_id=?,lease_until_utc='',leased_by='',lease_token='',
                       next_attempt_at_utc='',last_error_class='',last_error_hash='',
                       suspect_remote_entity_type='',suspect_remote_entity_id='',
                       updated_at_utc=? WHERE operation_id=? AND state IN ('REVIEW','UNCERTAIN')""",
                (remote_type, remote_id, now, operation),
            )
            if changed.rowcount != 1:
                raise CanaryStaleLease("reconciliation target changed before commit")
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_operation_reconciled_sent",
                aggregate_type=str(selected["lf_entity_type"]),
                aggregate_id=str(selected["lf_entity_id"]),
                producer=_PRODUCER,
                idempotency_key=(
                    f"graph-canary-reconciled:{operation}:{remote_type}:{remote_id}"
                ),
                payload={
                    "run_id": rid,
                    "operation_id": operation,
                    "operation_type": str(selected["operation_type"]),
                    "remote_entity_type": remote_type,
                    "remote_entity_id": remote_id,
                    "external_call": "read_only_exact_correlation",
                },
                evidence_ref=evidence,
                actor=principal,
            )

    def resume_stopped_run(
        self,
        evidence: GraphCanaryCutoverEvidence,
        *,
        actor: str,
        recovery_approval_ref: str,
    ) -> None:
        """Resume only the same recovered cap-one graph under a fresh fence."""

        principal = _required_text(actor, "actor")
        recovery = _required_text(recovery_approval_ref, "recovery_approval_ref")
        self._assert_sealed_evidence(evidence)
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, evidence.run_id)
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            if str(run["state"]) != "STOPPED" or not writer or str(writer[0]) != "0":
                raise CanaryControlError("recovery resume requires STOPPED and writers off")
            approval = self._exact_approval_tx(con, evidence.run_id)
            if (
                str(approval["approval_id"]) != evidence.approval_id
                or str(approval["evidence_ref"]) != evidence.owner_approval_evidence_ref
            ):
                raise GraphCanaryEvidenceError("recovery approval lineage changed")
            rows = self._assert_exact_bound_graph_tx(
                con,
                run_id=evidence.run_id,
                member_id=evidence.member_id,
                interaction_id=evidence.interaction_id,
                operation_ids=evidence.operation_ids,
                operation_payload_hashes=evidence.operation_payload_hashes,
            )
            states = tuple(str(row["state"]) for row in rows)
            sent = sum(state == "SENT" for state in states)
            if (
                sent < 1
                or sent >= 4
                or states != ("SENT",) * sent + ("PENDING",) * (4 - sent)
                or not con.execute(
                    """SELECT 1 FROM events WHERE producer=?
                       AND event_type='bitrix_graph_canary_operation_reconciled_sent'
                       AND json_extract(payload_json,'$.run_id')=?""",
                    (_PRODUCER, evidence.run_id),
                ).fetchone()
            ):
                raise CanaryControlError(
                    "recovery resume requires a reconciled SENT prefix and PENDING suffix"
                )
            other = con.execute(
                """SELECT 1 FROM canary_runs WHERE connector=? AND state='ACTIVE'
                   AND run_id<>?""",
                (BITRIX_GRAPH_CANARY_CONNECTOR, evidence.run_id),
            ).fetchone()
            if other:
                raise CanaryControlError("another graph canary is active")
            con.execute(
                "UPDATE canary_runs SET state='ACTIVE',activated_at_utc=? WHERE run_id=?",
                (now, evidence.run_id),
            )
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_recovery_resumed",
                aggregate_type="canary_run",
                aggregate_id=evidence.run_id,
                producer=_PRODUCER,
                idempotency_key=(
                    f"graph-canary-recovery-resume:{evidence.run_id}:{sent}"
                ),
                payload={
                    "sent_prefix_count": sent,
                    "remaining_count": 4 - sent,
                    "cutover_seal_hash": evidence.seal_hash,
                    "external_writers_enabled": True,
                },
                evidence_ref=recovery,
                actor=principal,
            )

    def _mark_terminal_dispatch_state(
        self,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        *,
        state: str,
        error_class: str,
        actor: str,
        _transaction: Any | None = None,
    ) -> None:
        principal = _required_text(actor, "actor")
        failure = _required_text(error_class, "error_class")
        if state not in {"UNCERTAIN", "REVIEW"}:
            raise ValueError("unsupported graph dispatch state")
        if len(failure) > 128 or any(
            not (character.isalnum() or character in "_.-") for character in failure
        ):
            raise ValueError("error_class must be a safe class identifier")
        now = utc_now()
        error_digest = payload_hash(
            {
                "operation_id": permit.operation_id,
                "operation_type": permit.operation_type,
                "error_class": failure,
                "state": state,
            }
        )
        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction(min_schema_version=17)
        )
        with transaction as con:
            self.assert_dispatch_permit_tx(
                con, permit, lease, operation_id=permit.operation_id
            )
            current = con.execute(
                "SELECT lf_entity_type,lf_entity_id FROM crm_outbox WHERE operation_id=?",
                (permit.operation_id,),
            ).fetchone()
            changed = con.execute(
                """UPDATE crm_outbox
                   SET state=?,lease_until_utc='',leased_by='',lease_token='',
                       next_attempt_at_utc='',last_error_class=?,last_error_hash=?,
                       updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN' AND lease_token=?""",
                (
                    state,
                    failure,
                    error_digest,
                    now,
                    permit.operation_id,
                    permit.operation_lease_token,
                ),
            )
            if changed.rowcount != 1:
                raise CanaryStaleLease("operation lease changed before state commit")
            self.store._append_event_tx(
                con,
                event_type=f"bitrix_graph_canary_operation_{state.lower()}",
                aggregate_type=str(current["lf_entity_type"]),
                aggregate_id=str(current["lf_entity_id"]),
                producer=_PRODUCER,
                idempotency_key=(
                    f"graph-canary-state:{permit.operation_id}:"
                    f"{permit.operation_lease_token}:{state}"
                ),
                payload={
                    "run_id": permit.run_id,
                    "operation_id": permit.operation_id,
                    "operation_type": permit.operation_type,
                    "state": state,
                    "error_class": failure,
                },
                actor=principal,
            )

    def stop_run(
        self, run_id: str, *, actor: str, reason: str, evidence_ref: str
    ) -> bool:
        """Close writers and revoke the fence; uncertain rows remain durable."""

        rid = _required_text(run_id, "run_id")
        principal = _required_text(actor, "actor")
        why = _required_text(reason, "reason")
        evidence = _required_text(evidence_ref, "evidence_ref")
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_schema17_tx(con)
            run = self._run_tx(con, rid)
            if str(run["state"]) == "STOPPED":
                prior = con.execute(
                    """SELECT evidence_ref,payload_hash FROM events
                       WHERE producer=? AND aggregate_id=?
                         AND event_type='bitrix_graph_canary_stopped'
                         AND evidence_ref=? AND payload_hash=? LIMIT 1""",
                    (
                        _PRODUCER,
                        rid,
                        evidence,
                        payload_hash(
                            {"reason": why, "external_writers_enabled": False}
                        ),
                    ),
                ).fetchone()
                expected = payload_hash(
                    {"reason": why, "external_writers_enabled": False}
                )
                if (
                    str(run["stop_reason"]) != why
                    or not prior
                    or str(prior["evidence_ref"]) != evidence
                    or str(prior["payload_hash"]) != expected
                ):
                    raise IdempotencyConflict("stop replay changed immutable evidence")
                return False
            prior_stop_count = int(
                con.execute(
                    """SELECT COUNT(*) FROM events WHERE producer=? AND aggregate_id=?
                       AND event_type='bitrix_graph_canary_stopped'""",
                    (_PRODUCER, rid),
                ).fetchone()[0]
            )
            con.execute(
                """UPDATE canary_runs
                   SET state='STOPPED',stopped_at_utc=?,stop_reason=?
                   WHERE run_id=?""",
                (now, why, rid),
            )
            con.execute(
                "UPDATE schema_meta SET value='0' WHERE key='external_writers_enabled'"
            )
            con.execute(
                """UPDATE connector_writer_leases
                   SET run_id='',owner_id='',lease_until_utc='',
                       fence_token=fence_token+1,updated_at_utc=?
                   WHERE connector=? AND run_id=?""",
                (now, BITRIX_GRAPH_CANARY_CONNECTOR, rid),
            )
            self.store._append_event_tx(
                con,
                event_type="bitrix_graph_canary_stopped",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer=_PRODUCER,
                idempotency_key=(
                    f"graph-canary-stop:{rid}"
                    if prior_stop_count == 0
                    else f"graph-canary-stop:{rid}:{prior_stop_count + 1}"
                ),
                payload={"reason": why, "external_writers_enabled": False},
                evidence_ref=evidence,
                actor=principal,
            )
        return True

    def _assert_sealed_evidence(
        self, evidence: GraphCanaryCutoverEvidence
    ) -> None:
        if not isinstance(evidence, GraphCanaryCutoverEvidence):
            raise GraphCanaryEvidenceError("sealed cutover evidence is required")
        credential = evidence.credential
        if (
            not isinstance(credential, GraphCanaryCredentialEvidence)
            or tuple(credential.granted_scopes) != ("crm",)
            or not credential.owner_accepted_existing_credential
            or not str(credential.credential_fingerprint).strip()
            or not str(credential.evidence_ref).strip()
            or len(evidence.operation_ids) != 4
            or len(set(evidence.operation_ids)) != 4
            or len(evidence.operation_payload_hashes) != 4
            or any(
                _safe_hash(item) != item
                for item in evidence.operation_payload_hashes
            )
            or not evidence.sealed_input_hashes
            or len({name for name, _ in evidence.sealed_input_hashes})
            != len(evidence.sealed_input_hashes)
            or any(
                not str(name).strip() or _safe_hash(digest) != digest
                for name, digest in evidence.sealed_input_hashes
            )
        ):
            raise GraphCanaryEvidenceError(
                "credential must be owner-accepted and exact crm-only"
            )
        fields = {
            "run_id": evidence.run_id,
            "member_id": evidence.member_id,
            "approval_id": evidence.approval_id,
            "interaction_id": evidence.interaction_id,
            "operation_ids": list(evidence.operation_ids),
            "operation_payload_hashes": list(evidence.operation_payload_hashes),
            "sealed_input_hashes": [
                list(item) for item in evidence.sealed_input_hashes
            ],
            "owner_approval_evidence_ref": evidence.owner_approval_evidence_ref,
            "cutover_evidence_ref": evidence.cutover_evidence_ref,
            "credential": _credential_payload(credential),
        }
        if payload_hash(fields) != evidence.seal_hash:
            raise GraphCanaryEvidenceError("cutover evidence seal does not verify")

    def _assert_expansion_evidence(
        self, evidence: GraphCanaryExpansionCutoverEvidence
    ) -> None:
        if not isinstance(evidence, GraphCanaryExpansionCutoverEvidence):
            raise GraphCanaryEvidenceError("sealed expansion evidence is required")
        if not 1 <= len(evidence.members) <= 4 or len(
            {member.member_id for member in evidence.members}
        ) != len(evidence.members):
            raise GraphCanaryEvidenceError(
                "expansion must contain one to four distinct members"
            )
        credential = evidence.credential
        if (
            not isinstance(credential, GraphCanaryCredentialEvidence)
            or tuple(credential.granted_scopes) != ("crm",)
            or credential.owner_accepted_existing_credential is not False
            or not str(credential.credential_fingerprint).strip()
            or not str(credential.evidence_ref).strip()
            or not str(evidence.credential_isolation_evidence_ref).strip()
        ):
            raise GraphCanaryEvidenceError(
                "expansion requires a new isolated exact crm-only credential"
            )
        for member in evidence.members:
            if not isinstance(member, GraphCanaryMemberCutoverEvidence):
                raise GraphCanaryEvidenceError("expansion member evidence is invalid")
            fields = {
                "member_id": member.member_id,
                "interaction_id": member.interaction_id,
                "operation_ids": list(member.operation_ids),
                "operation_payload_hashes": list(member.operation_payload_hashes),
                "dependency_operation_ids": list(member.dependency_operation_ids),
                "sealed_input_hashes": [
                    list(item) for item in member.sealed_input_hashes
                ],
            }
            if (
                len(member.operation_ids) != 4
                or len(set(member.operation_ids)) != 4
                or len(member.operation_payload_hashes) != 4
                or member.dependency_operation_ids
                != (
                    "",
                    member.operation_ids[0],
                    member.operation_ids[1],
                    member.operation_ids[2],
                )
                or payload_hash(fields) != member.seal_hash
            ):
                raise GraphCanaryEvidenceError("expansion member seal does not verify")
        fields = {
            "run_id": evidence.run_id,
            "approval_id": evidence.approval_id,
            "checkpoint_event_id": evidence.checkpoint_event_id,
            "member_seal_hashes": [
                member.seal_hash for member in evidence.members
            ],
            "cutover_evidence_ref": evidence.cutover_evidence_ref,
            "credential_isolation_evidence_ref": (
                evidence.credential_isolation_evidence_ref
            ),
            "credential": _credential_payload(credential),
        }
        if payload_hash(fields) != evidence.seal_hash:
            raise GraphCanaryEvidenceError("expansion cutover seal does not verify")

    @staticmethod
    def _expansion_input_contract(
        members: tuple[GraphCanaryMemberCutoverEvidence, ...],
        checkpoint_inputs: tuple[tuple[str, str], ...],
    ) -> tuple[str, list[dict[str, str | int]]]:
        baseline = dict(checkpoint_inputs)
        if (
            not baseline
            or len(baseline) != len(checkpoint_inputs)
            or any(name.startswith("expansion_") for name in baseline)
        ):
            raise GraphCanaryEvidenceError(
                "cap-one baseline input namespace is invalid"
            )
        cohort_hash = ""
        candidate_hashes: set[str] = set()
        bindings: list[dict[str, str | int]] = []
        for ordinal, member in enumerate(members, start=2):
            inputs = dict(member.sealed_input_hashes)
            candidate_name = f"expansion_candidate_{ordinal}"
            expected_names = set(baseline) | {
                "expansion_cohort",
                candidate_name,
            }
            if (
                len(inputs) != len(member.sealed_input_hashes)
                or set(inputs) != expected_names
                or any(inputs.get(name) != digest for name, digest in baseline.items())
            ):
                raise GraphCanaryEvidenceError(
                    "member must extend the unchanged baseline with exact expansion inputs"
                )
            observed_cohort = str(inputs["expansion_cohort"])
            candidate_hash = str(inputs[candidate_name])
            if not cohort_hash:
                cohort_hash = observed_cohort
            elif cohort_hash != observed_cohort:
                raise GraphCanaryEvidenceError(
                    "all expansion members must bind the same cohort"
                )
            if candidate_hash in candidate_hashes:
                raise GraphCanaryEvidenceError(
                    "expansion candidate hashes must be distinct per member"
                )
            candidate_hashes.add(candidate_hash)
            bindings.append(
                {
                    "ordinal": ordinal,
                    "member_id": member.member_id,
                    "candidate_name": candidate_name,
                    "candidate_hash": candidate_hash,
                    "member_seal_hash": member.seal_hash,
                }
            )
        if not cohort_hash:
            raise GraphCanaryEvidenceError("expansion cohort binding is required")
        return cohort_hash, bindings

    def _run_tx(self, con: Any, run_id: str) -> Any:
        run = con.execute(
            "SELECT * FROM canary_runs WHERE run_id=?", (run_id,)
        ).fetchone()
        if not run or str(run["connector"]) != BITRIX_GRAPH_CANARY_CONNECTOR:
            raise KeyError("graph canary run does not exist")
        return run

    def _active_run_tx(self, con: Any, run_id: str) -> Any:
        run = self._run_tx(con, run_id)
        if str(run["state"]) != "ACTIVE":
            raise CanaryControlError("graph canary run is not active")
        return run

    @staticmethod
    def _approval_tx(con: Any, run_id: str) -> Any:
        rows = con.execute(
            """SELECT * FROM canary_approvals WHERE run_id=?
               ORDER BY approval_sequence""",
            (run_id,),
        ).fetchall()
        if not rows:
            raise CanaryApprovalRequired("immutable graph canary approval is required")
        if len(rows) == 1:
            valid = (
                int(rows[0]["approval_sequence"]) == 1
                and int(rows[0]["cumulative_cap"]) == 1
                and not str(rows[0]["checkpoint_event_id"] or "")
            )
        elif len(rows) == 2:
            valid = (
                int(rows[0]["approval_sequence"]) == 1
                and int(rows[0]["cumulative_cap"]) == 1
                and not str(rows[0]["checkpoint_event_id"] or "")
                and int(rows[1]["approval_sequence"]) == 2
                and int(rows[1]["cumulative_cap"]) == 5
                and bool(str(rows[1]["checkpoint_event_id"] or ""))
            )
        else:
            valid = False
        if not valid:
            raise CanaryApprovalRequired(
                "approval lineage must be immutable cap-one then optional cap-five"
            )
        return rows[-1]

    @classmethod
    def _exact_approval_tx(
        cls, con: Any, run_id: str, *, expected_cap: int = 1
    ) -> Any:
        approval = cls._approval_tx(con, run_id)
        if int(approval["cumulative_cap"]) != int(expected_cap):
            raise CanaryApprovalRequired(
                f"exact cumulative cap {int(expected_cap)} approval is required"
            )
        return approval

    @staticmethod
    def _exact_member_tx(con: Any, run_id: str, member_id: str = "") -> Any:
        rows = con.execute(
            "SELECT * FROM canary_scope_members WHERE run_id=?", (run_id,)
        ).fetchall()
        if len(rows) != 1 or str(rows[0]["state"]) != "ARMED":
            raise CanaryScopeMismatch("exactly one armed scope member is required")
        if member_id and str(rows[0]["member_id"]) != member_id:
            raise CanaryScopeMismatch("sealed scope member changed")
        return rows[0]

    @staticmethod
    def _member_tx(con: Any, run_id: str, member_id: str) -> Any:
        member = con.execute(
            """SELECT * FROM canary_scope_members
               WHERE run_id=? AND member_id=? AND state='ARMED'""",
            (run_id, member_id),
        ).fetchone()
        if not member:
            raise CanaryScopeMismatch("armed scope member does not exist in this run")
        return member

    def _assert_exact_bound_graph_tx(
        self,
        con: Any,
        *,
        run_id: str,
        member_id: str = "",
        interaction_id: str = "",
        operation_ids: tuple[str, ...] = (),
        operation_payload_hashes: tuple[str, ...] = (),
    ) -> list[Any]:
        approval = self._exact_approval_tx(con, run_id)
        member = self._exact_member_tx(con, run_id, member_id)
        bindings = con.execute(
            """SELECT * FROM canary_operation_bindings
               WHERE run_id=? ORDER BY CASE operation_type
                   WHEN ? THEN 1 WHEN ? THEN 2 WHEN ? THEN 3 WHEN ? THEN 4 ELSE 5 END""",
            (run_id, *GRAPH_OPERATION_ORDER),
        ).fetchall()
        if (
            len(bindings) != 4
            or tuple(str(row["operation_type"]) for row in bindings)
            != GRAPH_OPERATION_ORDER
            or len({str(row["member_id"]) for row in bindings}) != 1
            or any(
                str(row["member_id"]) != str(member["member_id"])
                or str(row["approval_id"]) != str(approval["approval_id"])
                for row in bindings
            )
        ):
            raise CanaryScopeMismatch("exact four-operation binding set changed")
        bound_interactions = {str(row["interaction_id"]) for row in bindings}
        if len(bound_interactions) != 1 or (
            interaction_id and bound_interactions != {interaction_id}
        ):
            raise CanaryScopeMismatch("graph binding interaction changed")
        bound_ids = tuple(str(row["operation_id"]) for row in bindings)
        if operation_ids and bound_ids != tuple(operation_ids):
            raise CanaryScopeMismatch("sealed operation order changed")
        operations = []
        for binding in bindings:
            operation = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?",
                (binding["operation_id"],),
            ).fetchone()
            if not operation:
                raise GraphInvariantError("bound CRM graph operation disappeared")
            self.graph_outbox._validate_operation_tx(
                con, operation, require_sent=False
            )
            operations.append(operation)
        if operation_payload_hashes and tuple(
            str(row["payload_hash"]) for row in operations
        ) != tuple(operation_payload_hashes):
            raise GraphCanaryEvidenceError("sealed operation payload hashes changed")
        return operations

    def _cap_one_checkpoint_tx(
        self, con: Any, run_id: str, checkpoint_event_id: str
    ) -> dict[str, Any]:
        event = con.execute(
            """SELECT * FROM events WHERE event_id=? AND producer=?
               AND event_type='bitrix_graph_canary_cap_one_completed'
               AND aggregate_type='canary_run' AND aggregate_id=?""",
            (checkpoint_event_id, _PRODUCER, run_id),
        ).fetchone()
        if not event or not str(event["evidence_ref"] or ""):
            raise GraphCanaryEvidenceError(
                "immutable cap-one completion checkpoint is missing"
            )
        try:
            body = json.loads(str(event["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GraphCanaryEvidenceError(
                "cap-one completion checkpoint payload is invalid"
            ) from exc
        if (
            not isinstance(body, dict)
            or body.get("cumulative_cap") != 1
            or not str(body.get("approval_id", ""))
            or not str(body.get("member_id", ""))
            or not str(body.get("cutover_event_id", ""))
            or not str(body.get("stop_event_id", ""))
            or not str(body.get("credential_evidence_hash", ""))
            or not isinstance(body.get("sealed_input_hashes"), list)
            or not isinstance(body.get("operations"), list)
            or len(body["operations"]) != 4
        ):
            raise GraphCanaryEvidenceError(
                "cap-one completion checkpoint is incomplete"
            )
        approval = con.execute(
            """SELECT * FROM canary_approvals
               WHERE approval_id=? AND run_id=?""",
            (body["approval_id"], run_id),
        ).fetchone()
        if (
            not approval
            or int(approval["approval_sequence"]) != 1
            or int(approval["cumulative_cap"]) != 1
            or str(approval["checkpoint_event_id"] or "")
        ):
            raise GraphCanaryEvidenceError("original cap-one approval changed")
        cutover = con.execute(
            "SELECT payload_hash FROM events WHERE event_id=?",
            (body["cutover_event_id"],),
        ).fetchone()
        stop = con.execute(
            "SELECT payload_hash FROM events WHERE event_id=?",
            (body["stop_event_id"],),
        ).fetchone()
        if (
            not cutover
            or str(cutover[0]) != str(body.get("cutover_payload_hash", ""))
            or not stop
            or str(stop[0]) != str(body.get("stop_payload_hash", ""))
        ):
            raise GraphCanaryEvidenceError(
                "cap-one cutover or STOP evidence changed"
            )
        current = con.execute(
            """SELECT o.operation_id,o.operation_type,o.payload_hash,o.state,
                      o.remote_entity_type,o.remote_entity_id
               FROM canary_operation_bindings b JOIN crm_outbox o
                 ON o.operation_id=b.operation_id
               WHERE b.run_id=? AND b.member_id=?
               ORDER BY CASE o.operation_type
                   WHEN ? THEN 1 WHEN ? THEN 2 WHEN ? THEN 3 WHEN ? THEN 4 ELSE 5 END""",
            (run_id, body["member_id"], *GRAPH_OPERATION_ORDER),
        ).fetchall()
        current_proof = [
            {
                "operation_id": str(row["operation_id"]),
                "operation_type": str(row["operation_type"]),
                "payload_hash": str(row["payload_hash"]),
                "remote_entity_type": str(row["remote_entity_type"]),
                "remote_entity_id": str(row["remote_entity_id"]),
                "state": str(row["state"]),
            }
            for row in current
        ]
        if current_proof != body["operations"] or any(
            not item["remote_entity_id"].isascii()
            or not item["remote_entity_id"].isdigit()
            or int(item["remote_entity_id"]) < 1
            or item["state"] != "SENT"
            for item in current_proof
        ):
            raise GraphCanaryEvidenceError(
                "completed cap-one graph no longer matches its checkpoint"
            )
        return body

    def _assert_member_bound_graph_tx(
        self,
        con: Any,
        *,
        run_id: str,
        member_id: str,
        interaction_id: str = "",
        operation_ids: tuple[str, ...] = (),
        operation_payload_hashes: tuple[str, ...] = (),
        dependency_operation_ids: tuple[str, ...] = (),
    ) -> list[Any]:
        member = self._member_tx(con, run_id, member_id)
        bindings = con.execute(
            """SELECT * FROM canary_operation_bindings
               WHERE run_id=? AND member_id=?
               ORDER BY CASE operation_type
                   WHEN ? THEN 1 WHEN ? THEN 2 WHEN ? THEN 3 WHEN ? THEN 4 ELSE 5 END""",
            (run_id, member_id, *GRAPH_OPERATION_ORDER),
        ).fetchall()
        if (
            len(bindings) != 4
            or tuple(str(row["operation_type"]) for row in bindings)
            != GRAPH_OPERATION_ORDER
            or len({str(row["approval_id"]) for row in bindings}) != 1
        ):
            raise CanaryScopeMismatch("member does not own one exact graph binding")
        approval = con.execute(
            "SELECT cumulative_cap,run_id FROM canary_approvals WHERE approval_id=?",
            (bindings[0]["approval_id"],),
        ).fetchone()
        if (
            not approval
            or str(approval["run_id"]) != run_id
            or int(approval["cumulative_cap"]) not in {1, 5}
        ):
            raise CanaryApprovalRequired("member binding approval lineage changed")
        interactions = {str(row["interaction_id"]) for row in bindings}
        if len(interactions) != 1 or (
            interaction_id and interactions != {interaction_id}
        ):
            raise CanaryScopeMismatch("member graph interaction changed")
        bound_interaction = next(iter(interactions))
        observed = con.execute(
            """SELECT lf_opportunity_id,address,thread_id FROM interactions
               WHERE lf_interaction_id=?""",
            (bound_interaction,),
        ).fetchone()
        if not observed or (
            str(observed["lf_opportunity_id"] or "")
            != str(member["lf_opportunity_id"])
            or normalize_email(observed["address"])
            != normalize_email(member["contact_address"])
            or canonical_outbound_thread(observed["thread_id"])
            != str(member["canonical_outbound_thread"])
        ):
            raise CanaryScopeMismatch("member interaction no longer proves exact scope")
        bound_ids = tuple(str(row["operation_id"]) for row in bindings)
        if operation_ids and bound_ids != tuple(operation_ids):
            raise CanaryScopeMismatch("member operation identity changed")
        operations = []
        for binding in bindings:
            operation = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?",
                (binding["operation_id"],),
            ).fetchone()
            if not operation:
                raise GraphInvariantError("bound member operation disappeared")
            self.graph_outbox._validate_operation_tx(
                con, operation, require_sent=False
            )
            operations.append(operation)
        if operation_payload_hashes and tuple(
            str(row["payload_hash"]) for row in operations
        ) != tuple(operation_payload_hashes):
            raise GraphCanaryEvidenceError("member payload hashes changed")
        if dependency_operation_ids and tuple(
            str(row["dependency_operation_id"] or "") for row in operations
        ) != tuple(dependency_operation_ids):
            raise GraphCanaryEvidenceError("member dependency lineage changed")
        if str(operations[-1]["lf_entity_id"]) != str(member["lf_opportunity_id"]):
            raise CanaryScopeMismatch("member graph belongs to another opportunity")
        return operations

    def _assert_active_bound_run_tx(self, con: Any, *, run_id: str) -> list[Any]:
        approval = self._approval_tx(con, run_id)
        cap = int(approval["cumulative_cap"])
        if cap == 1:
            return self._assert_exact_bound_graph_tx(con, run_id=run_id)
        checkpoint_event = con.execute(
            "SELECT aggregate_id FROM events WHERE event_id=?",
            (approval["checkpoint_event_id"],),
        ).fetchone()
        if not checkpoint_event:
            raise GraphCanaryEvidenceError("cap-five checkpoint disappeared")
        checkpoint = self._cap_one_checkpoint_tx(
            con,
            str(checkpoint_event["aggregate_id"]),
            str(approval["checkpoint_event_id"]),
        )
        cutover = con.execute(
            """SELECT payload_json,payload_hash FROM events
               WHERE producer=? AND idempotency_key=?""",
            (_PRODUCER, f"graph-canary-expansion-cutover:{run_id}"),
        ).fetchone()
        if not cutover:
            raise GraphCanaryEvidenceError(
                "active cap-five run has no immutable expansion order"
            )
        try:
            cutover_payload = json.loads(str(cutover["payload_json"]))
            candidates = cutover_payload["expansion_candidates"]
            if (
                not isinstance(cutover_payload, dict)
                or payload_hash(cutover_payload) != str(cutover["payload_hash"])
                or type(candidates) is not list
                or not 1 <= len(candidates) <= 4
            ):
                raise ValueError
            ordered_expansion_ids = tuple(
                _required_text(item["member_id"], "expansion member_id")
                for item in candidates
            )
            expected_ordinals = tuple(range(2, 2 + len(candidates)))
            if (
                len(set(ordered_expansion_ids)) != len(ordered_expansion_ids)
                or tuple(item.get("ordinal") for item in candidates)
                != expected_ordinals
                or tuple(item.get("candidate_name") for item in candidates)
                != tuple(
                    f"expansion_candidate_{ordinal}"
                    for ordinal in expected_ordinals
                )
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise GraphCanaryEvidenceError(
                "immutable expansion member order is invalid"
            ) from None
        durable_members = {
            str(row[0])
            for row in con.execute(
                "SELECT member_id FROM canary_scope_members WHERE run_id=?",
                (run_id,),
            ).fetchall()
        }
        ordered_member_ids = (
            str(checkpoint["member_id"]),
            *ordered_expansion_ids,
        )
        if (
            not 2 <= len(ordered_member_ids) <= 5
            or durable_members != set(ordered_member_ids)
        ):
            raise CanaryCapacityExceeded(
                "cap-five run must contain original plus one to four members"
            )
        operations: list[Any] = []
        for member_id in ordered_member_ids:
            member_operations = self._assert_member_bound_graph_tx(
                con, run_id=run_id, member_id=member_id
            )
            binding_cap = int(
                con.execute(
                    """SELECT a.cumulative_cap FROM canary_operation_bindings b
                       JOIN canary_approvals a ON a.approval_id=b.approval_id
                       WHERE b.run_id=? AND b.member_id=? LIMIT 1""",
                    (run_id, member_id),
                ).fetchone()[0]
            )
            expected_cap = (
                1 if member_id == str(checkpoint["member_id"]) else 5
            )
            if binding_cap != expected_cap:
                raise CanaryApprovalRequired(
                    "member graph is bound to the wrong cumulative approval"
                )
            operations.extend(member_operations)
        return operations

    def _assert_writer_lease_tx(
        self, con: Any, lease: GraphCanaryWriterLease, now: str
    ) -> None:
        if (
            not isinstance(lease, GraphCanaryWriterLease)
            or lease.connector != BITRIX_GRAPH_CANARY_CONNECTOR
        ):
            raise CanaryStaleLease("graph writer lease identity is invalid")
        run = con.execute(
            """SELECT state,connector FROM canary_runs WHERE run_id=?""",
            (lease.run_id,),
        ).fetchone()
        current = con.execute(
            "SELECT * FROM connector_writer_leases WHERE connector=?",
            (BITRIX_GRAPH_CANARY_CONNECTOR,),
        ).fetchone()
        writer = con.execute(
            "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
        ).fetchone()
        if (
            not run
            or str(run["connector"]) != BITRIX_GRAPH_CANARY_CONNECTOR
            or str(run["state"]) != "ACTIVE"
            or not current
            or str(current["run_id"]) != lease.run_id
            or str(current["owner_id"]) != lease.owner_id
            or int(current["fence_token"]) != int(lease.fence_token)
            or not str(current["lease_until_utc"] or "")
            or str(current["lease_until_utc"]) <= now
            or not writer
            or str(writer[0]) != "1"
        ):
            raise CanaryStaleLease("graph writer lease or writer gate is stale")


__all__ = [
    "BITRIX_GRAPH_CANARY_CONNECTOR",
    "GRAPH_OPERATION_ORDER",
    "BitrixGraphCanaryControl",
    "GraphCanaryCredentialEvidence",
    "GraphCanaryCutoverEvidence",
    "GraphCanaryDispatchPermit",
    "GraphCanaryEvidenceError",
    "GraphCanaryExpansionCutoverEvidence",
    "GraphCanaryMemberCutoverEvidence",
    "GraphCanaryWriterLease",
]
