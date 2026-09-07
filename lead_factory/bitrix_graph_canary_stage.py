"""Seal one synthetic cap-one CRM graph in a disposable schema17 store."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import re
from typing import Iterable

from .bitrix_graph_canary_control import (
    BitrixGraphCanaryControl,
    GraphCanaryCredentialEvidence,
    GraphCanaryCutoverEvidence,
)
from .crm_graph_outbox import CrmGraphOutbox, CrmGraphStageResult
from .ids import canonical_json, normalize_email, payload_hash, utc_now
from .store import FactoryStore


_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/<>@+-]{0,511}$")
_SAFE_THREAD = re.compile(r"^<[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,509}>$")


@dataclass(frozen=True, slots=True)
class GraphCanaryCandidate:
    candidate_id: str
    mailbox: str
    campaign_id: str
    canonical_thread: str
    contact_address: str
    company_title: str
    company_inn: str
    contact_name: str
    contact_post: str
    project_title: str
    deal_title: str
    product_key: str
    activity_subject: str
    activity_description: str
    activity_deadline_utc: str
    lf_source_id: str
    reviewer_ref: str

    def seal_hash(self) -> str:
        _validate_candidate(self)
        return payload_hash(asdict(self))


@dataclass(frozen=True, slots=True)
class PreparedGraphCanary:
    run_id: str
    approval_id: str
    member_id: str
    interaction_id: str
    stage: CrmGraphStageResult
    candidate_hash: str
    cutover_evidence: GraphCanaryCutoverEvidence


@dataclass(frozen=True, slots=True)
class StagedGraphCanaryMember:
    interaction_id: str
    lf_opportunity_id: str
    stage: CrmGraphStageResult
    candidate_hash: str


def _text(value: object, label: str, *, maximum: int = 8192) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _validate_candidate(value: GraphCanaryCandidate) -> None:
    if type(value) is not GraphCanaryCandidate:
        raise TypeError("exact graph canary candidate is required")
    for field, rendered in asdict(value).items():
        _text(rendered, field)
    if (
        not _SAFE_ID.fullmatch(value.candidate_id)
        or not _SAFE_ID.fullmatch(value.mailbox)
        or not _SAFE_ID.fullmatch(value.campaign_id)
        or not _SAFE_THREAD.fullmatch(value.canonical_thread)
        or not _SAFE_ID.fullmatch(value.lf_source_id)
        or not _SAFE_ID.fullmatch(value.reviewer_ref)
        or normalize_email(value.contact_address) != value.contact_address
        or not value.contact_address.endswith(".example")
        or not value.company_inn.isascii()
        or not value.company_inn.isdigit()
        or len(value.company_inn) not in {10, 12}
        or not _UTC_SECONDS.fullmatch(value.activity_deadline_utc)
    ):
        raise ValueError("graph canary candidate identity is invalid")
    try:
        datetime.fromisoformat(value.activity_deadline_utc.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("graph canary Activity deadline is invalid") from None


def prepare_graph_canary(
    control: BitrixGraphCanaryControl,
    candidate: GraphCanaryCandidate,
    *,
    mapping_manifest_hash: str,
    owner_approval_evidence_ref: str,
    cutover_evidence_ref: str,
    credential: GraphCanaryCredentialEvidence,
    sealed_input_hashes: Iterable[tuple[str, str]],
    actor: str,
) -> PreparedGraphCanary:
    """Create and bind the exact local graph without enabling a writer."""
    if not isinstance(control, BitrixGraphCanaryControl):
        raise TypeError("durable graph canary control is required")
    staged = stage_graph_canary_member(
        control.store,
        candidate,
        mapping_manifest_hash=mapping_manifest_hash,
        actor=actor,
    )
    candidate_hash = staged.candidate_hash
    stage = staged.stage
    interaction_id = staged.interaction_id
    opportunity_id = staged.lf_opportunity_id
    run_id = control.create_run(
        created_by=actor, run_id="lf_graph_canary_run_" + candidate_hash[:32]
    )
    approval_id = control.create_cap_one_approval(
        run_id,
        approver=actor,
        evidence_ref=owner_approval_evidence_ref,
        approval_id="lf_graph_canary_approval_" + candidate_hash[:32],
    )
    member_id = control.arm_scope_member(
        run_id,
        mailbox=candidate.mailbox,
        campaign_id=candidate.campaign_id,
        contact_address=candidate.contact_address,
        canonical_thread=candidate.canonical_thread,
        lf_opportunity_id=opportunity_id,
        armed_by=actor,
        evidence_ref="candidate-hash:" + candidate_hash,
        member_id="lf_graph_canary_member_" + candidate_hash[:32],
    )
    operation_ids = (
        stage.company_operation_id,
        stage.contact_operation_id,
        stage.deal_operation_id,
        stage.activity_operation_id,
    )
    control.bind_graph(
        run_id,
        member_id=member_id,
        interaction_id=interaction_id,
        operation_ids=operation_ids,
        actor=actor,
    )
    con = control.store.connect()
    try:
        command_hashes = tuple(
            str(
                con.execute(
                    "SELECT payload_hash FROM crm_outbox WHERE operation_id=?", (item,)
                ).fetchone()[0]
            )
            for item in operation_ids
        )
    finally:
        con.close()
    inputs = tuple(sealed_input_hashes) + (("canary_candidate", candidate_hash),)
    evidence = GraphCanaryCutoverEvidence.seal(
        run_id=run_id,
        member_id=member_id,
        approval_id=approval_id,
        interaction_id=interaction_id,
        operation_ids=operation_ids,
        operation_payload_hashes=command_hashes,
        sealed_input_hashes=inputs,
        owner_approval_evidence_ref=owner_approval_evidence_ref,
        cutover_evidence_ref=cutover_evidence_ref,
        credential=credential,
    )
    if canonical_json(asdict(candidate)) == "":  # pragma: no cover - type guard
        raise AssertionError("candidate serialization disappeared")
    return PreparedGraphCanary(
        run_id,
        approval_id,
        member_id,
        interaction_id,
        stage,
        candidate_hash,
        evidence,
    )


def stage_graph_canary_member(
    store: FactoryStore,
    candidate: GraphCanaryCandidate,
    *,
    mapping_manifest_hash: str,
    actor: str,
) -> StagedGraphCanaryMember:
    """Idempotently stage one exact member without creating authority or a run."""
    if type(store) is not FactoryStore:
        raise TypeError("disposable schema17 store is required")
    _validate_candidate(candidate)
    candidate_hash = candidate.seal_hash()
    company, _ = store.create_company(
        name=candidate.company_title, inn=candidate.company_inn
    )
    contact, _ = store.create_contact(
        lf_company_id=company["lf_company_id"],
        email=candidate.contact_address,
        name=candidate.contact_name,
    )
    project, _ = store.create_project(
        lf_company_id=company["lf_company_id"],
        source=candidate.lf_source_id,
        external_key=candidate.candidate_id + ":project",
        title=candidate.project_title,
    )
    opportunity, _ = store.create_opportunity(
        lf_company_id=company["lf_company_id"],
        lf_contact_id=contact["lf_contact_id"],
        lf_project_id=project["lf_project_id"],
        source=candidate.lf_source_id,
        external_key=candidate.candidate_id + ":opportunity",
    )
    event, _ = store.append_event(
        event_type="bitrix_graph_canary_candidate_sealed",
        aggregate_type="opportunity",
        aggregate_id=opportunity["lf_opportunity_id"],
        producer="bitrix_graph_canary_stage",
        idempotency_key="bitrix-graph-canary-candidate:" + candidate_hash,
        payload={"candidate_hash": candidate_hash, "reviewer_ref": candidate.reviewer_ref},
        actor=actor,
    )
    stage = CrmGraphOutbox(store).stage_graph(
        company_id=company["lf_company_id"],
        contact_id=contact["lf_contact_id"],
        project_id=project["lf_project_id"],
        opportunity_id=opportunity["lf_opportunity_id"],
        external_event_id=event["event_id"],
        company_payload={
            "TITLE": candidate.company_title,
            "UF_CRM_LF_COMPANY_ID": company["lf_company_id"],
            "UF_CRM_LF_INN": candidate.company_inn,
        },
        contact_payload={
            "NAME": candidate.contact_name,
            "EMAIL": candidate.contact_address,
            "POST": candidate.contact_post,
            "UF_CRM_LF_CONTACT_ID": contact["lf_contact_id"],
        },
        deal_payload={
            "TITLE": candidate.deal_title,
            "UF_CRM_LF_PROJECT_ID": project["lf_project_id"],
            "UF_CRM_LF_PRODUCT_KEY": candidate.product_key,
        },
        activity_payload={
            "SUBJECT": candidate.activity_subject,
            "DESCRIPTION": candidate.activity_description,
            "DEADLINE": candidate.activity_deadline_utc,
            "UF_CRM_LF_OPPORTUNITY_ID": opportunity["lf_opportunity_id"],
        },
        mapping_manifest_hash=mapping_manifest_hash,
        lf_source_id=candidate.lf_source_id,
    )
    interaction_id = "lf_interaction_" + candidate_hash[:32]
    now = utc_now()
    with store.transaction(min_schema_version=17) as con:
        con.execute(
            """INSERT OR IGNORE INTO interactions(
                   lf_interaction_id,lf_opportunity_id,lf_contact_id,
                   source_event_id,dedupe_key,channel,direction,classification,
                   thread_id,address,received_at_utc,created_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                interaction_id,
                opportunity["lf_opportunity_id"],
                contact["lf_contact_id"],
                event["event_id"],
                "bitrix-graph-canary-interaction:" + candidate_hash,
                "manual",
                "INBOUND",
                "HUMAN_REPLY",
                candidate.canonical_thread,
                candidate.contact_address,
                now,
                now,
            ),
        )
        existing = con.execute(
            """SELECT lf_opportunity_id,lf_contact_id,source_event_id,dedupe_key,
                      channel,direction,classification,thread_id,address
                 FROM interactions WHERE lf_interaction_id=?""",
            (interaction_id,),
        ).fetchone()
        if not existing or tuple(existing) != (
            opportunity["lf_opportunity_id"],
            contact["lf_contact_id"],
            event["event_id"],
            "bitrix-graph-canary-interaction:" + candidate_hash,
            "manual",
            "INBOUND",
            "HUMAN_REPLY",
            candidate.canonical_thread,
            candidate.contact_address,
        ):
            raise ValueError("graph canary interaction replay changed")
    return StagedGraphCanaryMember(
        interaction_id,
        opportunity["lf_opportunity_id"],
        stage,
        candidate_hash,
    )


__all__ = [
    "GraphCanaryCandidate",
    "PreparedGraphCanary",
    "StagedGraphCanaryMember",
    "prepare_graph_canary",
    "stage_graph_canary_member",
]
