"""Fail-closed, transport-neutral CRM graph outbox.

The legacy CRM outbox creates a Bitrix Lead for one LF opportunity.  This
module deliberately does *not* extend that path.  It stages the production
commercial graph instead::

    Company -> Contact -> Deal -> Activity

Only the existing ``crm_outbox`` and ``crm_mappings`` tables are used.  A
future network adapter must implement :class:`CrmGraphTransport`; this module
does not import an HTTP client, credentials, or provider configuration.

Every create is put in ``UNCERTAIN`` before the adapter call.  Only an explicit
``RetryableRemoteError`` means the provider rejected the request before it
could create anything and is therefore safe to retry.  All other lost or
untyped outcomes require correlation readback and are never blindly created a
second time.

Schema note
-----------
``companies``, ``contacts`` and ``opportunities`` have exact local identities,
so their remote Company/Contact/Deal mappings are durable.  There is no local
Activity entity/table.  Consequently the Activity remote id is retained on
its immutable outbox operation and is not inserted into ``crm_mappings``.  A
provider adapter still has to prove the Activity's exact Deal owner and
correlation marker before the operation may become ``SENT``.
"""

from __future__ import annotations

import json
import math
import re
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from .crm_outbox import (
    AmbiguousRemoteError,
    CrmOperationResult,
    CrmOutbox,
    ExternalWritersDisabled,
    MappingConflict,
    PermanentRemoteError,
    RetryableRemoteError,
    StaleLease,
)
from .ids import canonical_json, new_lf_id, payload_hash, utc_now
from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .store import FactoryStore, IdempotencyConflict


COMPANY_CREATE = "BITRIX_COMPANY_CREATE"
CONTACT_CREATE = "BITRIX_CONTACT_CREATE"
DEAL_CREATE = "BITRIX_DEAL_CREATE"
ACTIVITY_CREATE = "BITRIX_DEAL_ACTIVITY_CREATE"

_OPERATION_ORDER = (COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE, ACTIVITY_CREATE)
_REMOTE_TYPE = {
    COMPANY_CREATE: "company",
    CONTACT_CREATE: "contact",
    DEAL_CREATE: "deal",
    ACTIVITY_CREATE: "activity",
}
_LOCAL_TYPE = {
    COMPANY_CREATE: "company",
    CONTACT_CREATE: "contact",
    DEAL_CREATE: "opportunity",
    ACTIVITY_CREATE: "opportunity",
}
_RESERVED_RELATIONSHIP_FIELDS = {
    COMPANY_CREATE: frozenset(),
    CONTACT_CREATE: frozenset({"COMPANY_ID", "COMPANY_IDS"}),
    DEAL_CREATE: frozenset(
        {"COMPANY_ID", "COMPANY_IDS", "CONTACT_ID", "CONTACT_IDS", "CONTACTS"}
    ),
    ACTIVITY_CREATE: frozenset(
        {"OWNER", "OWNER_ID", "OWNER_TYPE", "OWNER_TYPE_ID", "DEAL_ID", "BINDINGS"}
    ),
}
_ASCII_REMOTE_ID = re.compile(r"^[1-9][0-9]*$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CONTEXT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")


class GraphInvariantError(RuntimeError):
    """The persisted LF graph or dependency chain is no longer exact."""


class GraphReadbackMismatch(AmbiguousRemoteError):
    """A create/readback returned evidence for another identity or parent."""

    def __init__(self, message: str, *, remote_id: str = "", remote_type: str = ""):
        super().__init__(message)
        self.remote_id = str(remote_id or "").strip()
        self.remote_entity_type = str(remote_type or "").strip().lower()


class GraphStopRequested(RuntimeError):
    """The runtime stop callback closed before the next remote create."""


class SafeReconciliationUnsupported(RuntimeError):
    """The adapter cannot perform an exact immutable correlation lookup."""


class CanaryOperationBound(RuntimeError):
    """A sealed canary, not a generic worker, owns this CRM operation."""


@dataclass(frozen=True, slots=True)
class CrmGraphStageResult:
    company_operation_id: str
    contact_operation_id: str
    deal_operation_id: str
    activity_operation_id: str
    created_operation_ids: tuple[str, ...]

    @property
    def created(self) -> bool:
        return bool(self.created_operation_ids)


@dataclass(frozen=True, slots=True, repr=False)
class CrmGraphCreateRequest:
    operation_id: str
    operation_type: str
    remote_entity_type: str
    correlation_token: str
    payload: dict[str, Any]
    dependency_remote_ids: tuple[tuple[str, str], ...]
    lf_entity_type: str = ""
    lf_entity_id: str = ""
    source_event_id: str = ""
    idempotency_key: str = ""
    command_payload_hash: str = ""
    mapping_manifest_hash: str = ""
    lf_source_id: str = ""
    graph_identity_ids: tuple[tuple[str, str], ...] = ()

    def __repr__(self) -> str:
        """Never expose provider payloads, correlation tokens, or remote ids."""

        return "<CrmGraphCreateRequest redacted>"

    def dependency_id(self, remote_entity_type: str) -> str:
        wanted = str(remote_entity_type or "").strip().lower()
        return dict(self.dependency_remote_ids).get(wanted, "")


@dataclass(frozen=True, slots=True, repr=False)
class CrmGraphReadback:
    """Typed proof returned only after provider readback.

    Parent ids are deliberately explicit rather than an untyped payload.  A
    Contact must point at the exact Company, a Deal at the exact Company and
    Contact, and an Activity at the exact Deal.
    """

    remote_entity_type: str
    remote_id: str
    correlation_token: str
    readback_verified: bool
    company_remote_id: str = ""
    contact_remote_id: str = ""
    deal_remote_id: str = ""

    def __repr__(self) -> str:
        """Never expose correlation tokens or remote CRM identifiers."""

        return "<CrmGraphReadback redacted>"


class CrmGraphTransport(Protocol):
    """Boundary implemented by a future Bitrix adapter (or an offline fake)."""

    def create_entity(self, request: CrmGraphCreateRequest) -> CrmGraphReadback: ...

    def find_by_correlation(
        self, remote_entity_type: str, correlation_token: str
    ) -> CrmGraphReadback | None: ...


def _future(seconds: int) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=max(1, int(seconds)))
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def _remote_id(value: object) -> str:
    if isinstance(value, bool):
        return ""
    if type(value) is int:
        result = str(value)
    elif type(value) is str:
        result = value
    else:
        return ""
    return result if _ASCII_REMOTE_ID.fullmatch(result) else ""


class CrmGraphOutbox:
    """Atomically stage and safely execute one commercial CRM graph."""

    def __init__(self, store: FactoryStore, *, max_reconcile_attempts: int = 6):
        self.store = store
        self.max_reconcile_attempts = max(1, int(max_reconcile_attempts))

    # ------------------------------------------------------------------
    # Local graph staging
    # ------------------------------------------------------------------
    @staticmethod
    def _required_id(value: object, field: str) -> str:
        result = str(value or "").strip()
        if not result:
            raise ValueError(f"{field} is required")
        return result

    @staticmethod
    def _assert_strict_json(
        value: object, *, error_type: type[Exception] = ValueError
    ) -> None:
        """Reject Python JSON extensions such as NaN and Infinity."""

        if value is None or isinstance(value, (str, bool, int)):
            return
        if isinstance(value, float):
            if not math.isfinite(value):
                raise error_type("CRM payload contains a non-finite number")
            return
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise error_type("CRM payload keys must be strings")
                CrmGraphOutbox._assert_strict_json(child, error_type=error_type)
            return
        if isinstance(value, (list, tuple)):
            for child in value:
                CrmGraphOutbox._assert_strict_json(child, error_type=error_type)
            return
        raise error_type("CRM payload contains a non-JSON value")

    @staticmethod
    def _assert_no_relationship_fields(
        operation_type: str, value: object, *, error_type: type[Exception] = ValueError
    ) -> None:
        forbidden = _RESERVED_RELATIONSHIP_FIELDS.get(operation_type)
        if forbidden is None:
            raise error_type("unknown CRM graph operation type")

        def visit(node: object) -> None:
            if isinstance(node, dict):
                for raw_key, child in node.items():
                    if not isinstance(raw_key, str) or not raw_key.strip():
                        raise error_type("CRM payload keys must be non-empty strings")
                    key = raw_key.strip().upper()
                    if key in forbidden or (
                        operation_type == ACTIVITY_CREATE and key.startswith("OWNER_")
                    ):
                        raise error_type(
                            f"{key} is provider relationship data owned by the graph"
                        )
                    visit(child)
            elif isinstance(node, (list, tuple)):
                for child in node:
                    visit(child)

        visit(value)

    @classmethod
    def _payload(
        cls,
        value: dict[str, Any] | None,
        field: str,
        operation_type: str,
    ) -> dict[str, Any]:
        if not isinstance(value, dict) or not value:
            raise ValueError(f"{field} must be a non-empty object")
        if any(
            isinstance(key, str) and key.strip().lower().startswith("_lf_")
            for key in value
        ):
            raise ValueError(f"{field} contains reserved LF metadata")
        cls._assert_strict_json(value)
        cls._assert_no_relationship_fields(operation_type, value)
        return dict(value)

    @staticmethod
    def _assert_exact_graph_tx(
        con: Any,
        *,
        company_id: str,
        contact_id: str,
        project_id: str,
        opportunity_id: str,
    ) -> None:
        company = con.execute(
            "SELECT lf_company_id FROM companies WHERE lf_company_id=?", (company_id,)
        ).fetchone()
        contact = con.execute(
            "SELECT lf_company_id FROM contacts WHERE lf_contact_id=?", (contact_id,)
        ).fetchone()
        project = con.execute(
            "SELECT lf_company_id FROM projects WHERE lf_project_id=?", (project_id,)
        ).fetchone()
        opportunity = con.execute(
            """SELECT lf_company_id,lf_contact_id,lf_project_id
               FROM opportunities WHERE lf_opportunity_id=?""",
            (opportunity_id,),
        ).fetchone()
        if not company:
            raise KeyError(f"unknown company {company_id}")
        if not contact:
            raise KeyError(f"unknown contact {contact_id}")
        if not project:
            raise KeyError(f"unknown project {project_id}")
        if not opportunity:
            raise KeyError(f"unknown opportunity {opportunity_id}")
        if str(contact[0]) != company_id:
            raise GraphInvariantError("contact belongs to another company")
        if str(project[0]) != company_id:
            raise GraphInvariantError("project belongs to another company")
        if (
            str(opportunity[0]) != company_id
            or str(opportunity[1] or "") != contact_id
            or str(opportunity[2] or "") != project_id
        ):
            raise GraphInvariantError(
                "opportunity company/contact/project graph is not exact"
            )

    @staticmethod
    def _assert_no_lead_path_tx(con: Any, opportunity_id: str) -> None:
        mapping = con.execute(
            """SELECT remote_entity_type FROM crm_mappings
               WHERE lf_entity_type='opportunity' AND lf_entity_id=?""",
            (opportunity_id,),
        ).fetchone()
        if mapping and str(mapping[0]).lower() == "lead":
            raise IdempotencyConflict(
                "opportunity is already mapped to a CRM Lead; Deal graph is forbidden"
            )
        lead_operation = con.execute(
            """SELECT operation_id FROM crm_outbox
               WHERE operation_type='BITRIX_LEAD_CREATE'
                 AND lf_entity_type='opportunity' AND lf_entity_id=?""",
            (opportunity_id,),
        ).fetchone()
        if lead_operation:
            raise IdempotencyConflict(
                "opportunity already has a direct Lead create operation"
            )

    @staticmethod
    def _metadata(
        operation_type: str,
        *,
        company_id: str,
        contact_id: str,
        project_id: str,
        opportunity_id: str,
        mapping_manifest_hash: str = "",
        lf_source_id: str = "",
    ) -> dict[str, str]:
        if operation_type == COMPANY_CREATE:
            result = {"company_id": company_id}
        elif operation_type == CONTACT_CREATE:
            result = {"company_id": company_id, "contact_id": contact_id}
        else:
            result = {
                "company_id": company_id,
                "contact_id": contact_id,
                "project_id": project_id,
                "opportunity_id": opportunity_id,
            }
        if mapping_manifest_hash:
            result["mapping_manifest_hash"] = mapping_manifest_hash
        if lf_source_id and operation_type in {DEAL_CREATE, ACTIVITY_CREATE}:
            result["lf_source_id"] = lf_source_id
        return result

    @staticmethod
    def _derived_identity(
        operation_type: str, lf_entity_type: str, lf_entity_id: str
    ) -> tuple[str, str]:
        idempotency_key = (
            f"crm-graph-v1:{operation_type}:{lf_entity_type}:{lf_entity_id}"
        )
        correlation_token = "lf_graph_v1_" + payload_hash(
            {
                "operation_type": operation_type,
                "lf_entity_type": lf_entity_type,
                "lf_entity_id": lf_entity_id,
            }
        )[:40]
        return idempotency_key, correlation_token

    @classmethod
    def _assert_operation_envelope(cls, operation: dict[str, Any] | Any) -> dict[str, Any]:
        """Verify the immutable command envelope before it can reach transport."""

        operation_type = str(operation["operation_type"] or "")
        if operation_type not in _OPERATION_ORDER:
            raise GraphInvariantError("unknown CRM graph operation type")
        lf_entity_type = str(operation["lf_entity_type"] or "")
        lf_entity_id = str(operation["lf_entity_id"] or "")
        if lf_entity_type != _LOCAL_TYPE[operation_type] or not lf_entity_id:
            raise GraphInvariantError("CRM graph local operation identity is invalid")
        expected_key, expected_token = cls._derived_identity(
            operation_type, lf_entity_type, lf_entity_id
        )
        if (
            str(operation["idempotency_key"] or "") != expected_key
            or str(operation["correlation_token"] or "") != expected_token
            or not str(operation["external_event_id"] or "").strip()
        ):
            raise GraphInvariantError(
                "CRM graph idempotency or correlation identity was modified"
            )
        raw = str(operation["payload_json"] or "")
        try:
            body = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GraphInvariantError("CRM graph payload is invalid") from exc
        if not isinstance(body, dict):
            raise GraphInvariantError("CRM graph payload must be an object")
        cls._assert_strict_json(body, error_type=GraphInvariantError)
        try:
            canonical = canonical_json(body)
            digest = payload_hash(body)
        except (TypeError, ValueError) as exc:
            raise GraphInvariantError("CRM graph payload is not canonicalizable") from exc
        if canonical != raw or digest != str(operation["payload_hash"] or ""):
            raise GraphInvariantError("CRM graph payload hash or canonical JSON changed")
        if str(body.get("_lf_correlation_token", "")) != expected_token:
            raise GraphInvariantError("CRM graph payload correlation marker changed")
        reserved = {
            str(key).strip().lower()
            for key in body
            if isinstance(key, str) and str(key).strip().lower().startswith("_lf_")
        }
        if reserved != {"_lf_correlation_token", "_lf_graph_v1"}:
            raise GraphInvariantError("CRM graph payload has unknown LF metadata")
        public_payload = {
            key: value for key, value in body.items() if not str(key).startswith("_lf_")
        }
        cls._assert_no_relationship_fields(
            operation_type, public_payload, error_type=GraphInvariantError
        )
        return body

    @staticmethod
    def _stage_anchor_payload(operation: dict[str, Any] | Any) -> dict[str, Any]:
        """Build a non-secret digest anchored in the append-only Event Store."""

        operation_type = str(operation["operation_type"] or "")
        command = {
            "anchor_version": 1,
            "operation_id": str(operation["operation_id"] or ""),
            "operation_type": operation_type,
            "lf_entity_type": str(operation["lf_entity_type"] or ""),
            "lf_entity_id": str(operation["lf_entity_id"] or ""),
            "dependency_operation_id": str(
                operation["dependency_operation_id"] or ""
            ),
            "external_event_id": str(operation["external_event_id"] or ""),
            "correlation_token": str(operation["correlation_token"] or ""),
            "idempotency_key": str(operation["idempotency_key"] or ""),
            "payload_json": str(operation["payload_json"] or ""),
            "payload_hash": str(operation["payload_hash"] or ""),
            "created_at_utc": str(operation["created_at_utc"] or ""),
        }
        return {
            "anchor_version": 1,
            "operation_id": command["operation_id"],
            "operation_type": operation_type,
            "remote_entity_type": _REMOTE_TYPE.get(operation_type, ""),
            "dependency_operation_id": command["dependency_operation_id"],
            "correlation_token": command["correlation_token"],
            "outbox_idempotency_key": command["idempotency_key"],
            "command_payload_hash": command["payload_hash"],
            "command_hash": payload_hash(command),
        }

    @classmethod
    def _assert_stage_anchor_tx(
        cls, con: Any, operation: dict[str, Any] | Any
    ) -> None:
        """Require one exact immutable stage event for the current outbox row."""

        operation_id = str(operation["operation_id"] or "")
        rows = con.execute(
            """SELECT * FROM events
               WHERE producer='crm_graph_outbox' AND idempotency_key=?""",
            (f"crm-graph-stage:{operation_id}",),
        ).fetchall()
        if len(rows) != 1:
            raise GraphInvariantError(
                "exact immutable CRM graph stage anchor is required"
            )
        event = rows[0]
        if (
            str(event["event_type"]) != "crm_graph_operation_staged"
            or str(event["aggregate_type"]) != str(operation["lf_entity_type"])
            or str(event["aggregate_id"]) != str(operation["lf_entity_id"])
            or str(event["causation_id"] or "")
            != str(operation["external_event_id"] or "")
        ):
            raise GraphInvariantError("CRM graph stage anchor identity changed")
        raw = str(event["payload_json"] or "")
        try:
            anchored = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GraphInvariantError("CRM graph stage anchor payload is invalid") from exc
        cls._assert_strict_json(anchored, error_type=GraphInvariantError)
        if (
            not isinstance(anchored, dict)
            or canonical_json(anchored) != raw
            or payload_hash(anchored) != str(event["payload_hash"] or "")
            or anchored != cls._stage_anchor_payload(operation)
        ):
            raise GraphInvariantError(
                "CRM graph command differs from its immutable stage anchor"
            )

    def _stage_operation_tx(
        self,
        con: Any,
        *,
        operation_type: str,
        lf_entity_id: str,
        dependency_operation_id: str,
        external_event_id: str,
        payload: dict[str, Any],
        metadata: dict[str, str],
    ) -> tuple[str, bool]:
        lf_entity_type = _LOCAL_TYPE[operation_type]
        idempotency_key, correlation_token = self._derived_identity(
            operation_type, lf_entity_type, lf_entity_id
        )
        body = dict(payload)
        body["_lf_correlation_token"] = correlation_token
        body["_lf_graph_v1"] = dict(metadata)
        digest = payload_hash(body)

        by_key = con.execute(
            "SELECT * FROM crm_outbox WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        by_entity = con.execute(
            """SELECT * FROM crm_outbox
               WHERE operation_type=? AND lf_entity_type=? AND lf_entity_id=?""",
            (operation_type, lf_entity_type, lf_entity_id),
        ).fetchone()
        if by_key or by_entity:
            if by_key and by_entity and str(by_key["operation_id"]) != str(
                by_entity["operation_id"]
            ):
                raise IdempotencyConflict("CRM graph operation identity is ambiguous")
            existing = by_key or by_entity
            self._assert_operation_envelope(existing)
            self._assert_stage_anchor_tx(con, existing)
            causation_changed = (
                operation_type in {DEAL_CREATE, ACTIVITY_CREATE}
                and str(existing["external_event_id"] or "") != external_event_id
            )
            if (
                str(existing["operation_type"]) != operation_type
                or str(existing["lf_entity_type"]) != lf_entity_type
                or str(existing["lf_entity_id"]) != lf_entity_id
                or str(existing["dependency_operation_id"] or "")
                != dependency_operation_id
                or str(existing["correlation_token"]) != correlation_token
                or str(existing["payload_hash"]) != digest
                or causation_changed
            ):
                raise IdempotencyConflict(
                    f"CRM graph operation for {lf_entity_type} has different immutable data"
                )
            return str(existing["operation_id"]), False

        local_mapping = con.execute(
            """SELECT remote_entity_type,remote_entity_id,state FROM crm_mappings
               WHERE lf_entity_type=? AND lf_entity_id=?""",
            (lf_entity_type, lf_entity_id),
        ).fetchone()
        if local_mapping:
            raise IdempotencyConflict(
                f"{lf_entity_type} already has a CRM mapping without this graph operation"
            )

        operation_id = new_lf_id("crm_operation")
        now = utc_now()
        con.execute(
            """INSERT INTO crm_outbox(
                   operation_id,operation_type,lf_entity_type,lf_entity_id,
                   dependency_operation_id,external_event_id,correlation_token,
                   idempotency_key,payload_json,payload_hash,state,
                   created_at_utc,updated_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                operation_id,
                operation_type,
                lf_entity_type,
                lf_entity_id,
                dependency_operation_id,
                external_event_id,
                correlation_token,
                idempotency_key,
                canonical_json(body),
                digest,
                "PENDING",
                now,
                now,
            ),
        )
        staged = con.execute(
            "SELECT * FROM crm_outbox WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if not staged:
            raise GraphInvariantError("CRM graph operation staging disappeared")
        anchor_payload = self._stage_anchor_payload(staged)
        self.store._append_event_tx(
            con,
            event_type="crm_graph_operation_staged",
            aggregate_type=lf_entity_type,
            aggregate_id=lf_entity_id,
            producer="crm_graph_outbox",
            idempotency_key=f"crm-graph-stage:{operation_id}",
            payload=anchor_payload,
            actor="integration_worker",
            causation_id=external_event_id,
        )
        self._assert_stage_anchor_tx(con, staged)
        return operation_id, True

    def stage_graph(
        self,
        *,
        company_id: str,
        contact_id: str,
        project_id: str,
        opportunity_id: str,
        external_event_id: str,
        company_payload: dict[str, Any],
        contact_payload: dict[str, Any],
        deal_payload: dict[str, Any],
        activity_payload: dict[str, Any],
        mapping_manifest_hash: str = "",
        lf_source_id: str = "",
        _transaction: Any | None = None,
    ) -> CrmGraphStageResult:
        """Stage all four creates atomically and idempotently.

        Reusing an already staged Company or Contact for another exact graph is
        supported.  Pre-existing remote mappings without their original graph
        operation are rejected because the current schema cannot prove their
        create/readback lineage as a dependency.

        When ``_transaction`` is supplied, its caller exclusively owns commit,
        rollback, and connection lifetime for the graph and its event anchors.
        """

        company_id = self._required_id(company_id, "company_id")
        contact_id = self._required_id(contact_id, "contact_id")
        project_id = self._required_id(project_id, "project_id")
        opportunity_id = self._required_id(opportunity_id, "opportunity_id")
        external_event_id = self._required_id(external_event_id, "external_event_id")
        if mapping_manifest_hash:
            if (
                type(mapping_manifest_hash) is not str
                or not _HEX64.fullmatch(mapping_manifest_hash)
            ):
                raise ValueError("mapping_manifest_hash must be a lowercase SHA-256")
        if lf_source_id:
            if type(lf_source_id) is not str or not _SAFE_CONTEXT_ID.fullmatch(
                lf_source_id
            ):
                raise ValueError("lf_source_id must be an exact safe identifier")
        payloads = {
            COMPANY_CREATE: self._payload(
                company_payload, "company_payload", COMPANY_CREATE
            ),
            CONTACT_CREATE: self._payload(
                contact_payload, "contact_payload", CONTACT_CREATE
            ),
            DEAL_CREATE: self._payload(deal_payload, "deal_payload", DEAL_CREATE),
            ACTIVITY_CREATE: self._payload(
                activity_payload, "activity_payload", ACTIVITY_CREATE
            ),
        }
        self.store.init()
        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction()
        )
        with transaction as con:
            if _transaction is not None:
                self.store._probe_schema(con)
            self._assert_exact_graph_tx(
                con,
                company_id=company_id,
                contact_id=contact_id,
                project_id=project_id,
                opportunity_id=opportunity_id,
            )
            self._assert_no_lead_path_tx(con, opportunity_id)
            created: list[str] = []

            company_operation_id, was_created = self._stage_operation_tx(
                con,
                operation_type=COMPANY_CREATE,
                lf_entity_id=company_id,
                dependency_operation_id="",
                external_event_id=external_event_id,
                payload=payloads[COMPANY_CREATE],
                metadata=self._metadata(
                    COMPANY_CREATE,
                    company_id=company_id,
                    contact_id=contact_id,
                    project_id=project_id,
                    opportunity_id=opportunity_id,
                    mapping_manifest_hash=mapping_manifest_hash,
                    lf_source_id=lf_source_id,
                ),
            )
            if was_created:
                created.append(company_operation_id)
            contact_operation_id, was_created = self._stage_operation_tx(
                con,
                operation_type=CONTACT_CREATE,
                lf_entity_id=contact_id,
                dependency_operation_id=company_operation_id,
                external_event_id=external_event_id,
                payload=payloads[CONTACT_CREATE],
                metadata=self._metadata(
                    CONTACT_CREATE,
                    company_id=company_id,
                    contact_id=contact_id,
                    project_id=project_id,
                    opportunity_id=opportunity_id,
                    mapping_manifest_hash=mapping_manifest_hash,
                    lf_source_id=lf_source_id,
                ),
            )
            if was_created:
                created.append(contact_operation_id)
            deal_operation_id, was_created = self._stage_operation_tx(
                con,
                operation_type=DEAL_CREATE,
                lf_entity_id=opportunity_id,
                dependency_operation_id=contact_operation_id,
                external_event_id=external_event_id,
                payload=payloads[DEAL_CREATE],
                metadata=self._metadata(
                    DEAL_CREATE,
                    company_id=company_id,
                    contact_id=contact_id,
                    project_id=project_id,
                    opportunity_id=opportunity_id,
                    mapping_manifest_hash=mapping_manifest_hash,
                    lf_source_id=lf_source_id,
                ),
            )
            if was_created:
                created.append(deal_operation_id)
            activity_operation_id, was_created = self._stage_operation_tx(
                con,
                operation_type=ACTIVITY_CREATE,
                lf_entity_id=opportunity_id,
                dependency_operation_id=deal_operation_id,
                external_event_id=external_event_id,
                payload=payloads[ACTIVITY_CREATE],
                metadata=self._metadata(
                    ACTIVITY_CREATE,
                    company_id=company_id,
                    contact_id=contact_id,
                    project_id=project_id,
                    opportunity_id=opportunity_id,
                    mapping_manifest_hash=mapping_manifest_hash,
                    lf_source_id=lf_source_id,
                ),
            )
            if was_created:
                created.append(activity_operation_id)
            return CrmGraphStageResult(
                company_operation_id,
                contact_operation_id,
                deal_operation_id,
                activity_operation_id,
                tuple(created),
            )

    # ------------------------------------------------------------------
    # Dependency and lease validation
    # ------------------------------------------------------------------
    @classmethod
    def _parse_metadata(cls, operation: dict[str, Any] | Any) -> dict[str, str]:
        body = cls._assert_operation_envelope(operation)
        metadata = body.get("_lf_graph_v1")
        if not isinstance(metadata, dict):
            raise GraphInvariantError("CRM graph metadata is missing")
        if any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or value != value.strip()
            or not value
            for key, value in metadata.items()
        ):
            raise GraphInvariantError("CRM graph metadata is not canonical")
        result = dict(metadata)
        operation_type = str(operation["operation_type"])
        required = {"company_id"}
        if operation_type == CONTACT_CREATE:
            required.add("contact_id")
        elif operation_type in {DEAL_CREATE, ACTIVITY_CREATE}:
            required.update({"contact_id", "project_id", "opportunity_id"})
        optional = {"mapping_manifest_hash", "lf_source_id"}
        if not required.issubset(result) or not set(result).issubset(required | optional):
            raise GraphInvariantError("CRM graph metadata fields changed")
        manifest_hash = result.get("mapping_manifest_hash", "")
        if manifest_hash and not _HEX64.fullmatch(manifest_hash):
            raise GraphInvariantError("CRM graph mapping manifest hash changed")
        if operation_type in {COMPANY_CREATE, CONTACT_CREATE} and "lf_source_id" in result:
            raise GraphInvariantError("CRM graph source context changed")
        return result

    @staticmethod
    def _exact_mapping_tx(
        con: Any, *, lf_type: str, lf_id: str, remote_type: str, remote_id: str
    ) -> bool:
        row = con.execute(
            """SELECT state FROM crm_mappings
               WHERE lf_entity_type=? AND lf_entity_id=?
                 AND remote_entity_type=? AND remote_entity_id=?""",
            (lf_type, lf_id, remote_type, remote_id),
        ).fetchone()
        return bool(row and str(row[0]) == "ACTIVE")

    def _dependency_ids_tx(
        self, con: Any, operation: dict[str, Any] | Any, *, require_sent: bool
    ) -> dict[str, str]:
        operation_type = str(operation["operation_type"])
        metadata = self._parse_metadata(operation)
        company_id = metadata["company_id"]
        if operation_type == COMPANY_CREATE:
            if str(operation["dependency_operation_id"] or ""):
                raise GraphInvariantError("Company create cannot have a dependency")
            return {}

        dependency = con.execute(
            "SELECT * FROM crm_outbox WHERE operation_id=?",
            (str(operation["dependency_operation_id"] or ""),),
        ).fetchone()
        if not dependency:
            raise GraphInvariantError("CRM graph dependency operation is missing")
        dependency_metadata = self._parse_metadata(dependency)
        for context_key in ("mapping_manifest_hash",):
            if dependency_metadata.get(context_key, "") != metadata.get(
                context_key, ""
            ):
                raise GraphInvariantError("CRM graph mapping context changed")
        if operation_type == ACTIVITY_CREATE and dependency_metadata.get(
            "lf_source_id", ""
        ) != metadata.get("lf_source_id", ""):
            raise GraphInvariantError("CRM graph source context changed")

        if operation_type == CONTACT_CREATE:
            expected = (COMPANY_CREATE, "company", company_id, "company")
            dependency_ids: dict[str, str] = {}
        elif operation_type == DEAL_CREATE:
            expected = (CONTACT_CREATE, "contact", metadata["contact_id"], "contact")
            dependency_ids = {}
        elif operation_type == ACTIVITY_CREATE:
            expected = (DEAL_CREATE, "opportunity", metadata["opportunity_id"], "deal")
            dependency_ids = {}
        else:
            raise GraphInvariantError("unknown CRM graph operation type")

        if (
            str(dependency["operation_type"]) != expected[0]
            or str(dependency["lf_entity_type"]) != expected[1]
            or str(dependency["lf_entity_id"]) != expected[2]
        ):
            raise GraphInvariantError("CRM graph dependency points at another identity")
        if require_sent:
            dependency_remote_id = _remote_id(dependency["remote_entity_id"])
            if (
                str(dependency["state"]) != "SENT"
                or str(dependency["remote_entity_type"]) != expected[3]
                or not dependency_remote_id
                or not self._exact_mapping_tx(
                    con,
                    lf_type=expected[1],
                    lf_id=expected[2],
                    remote_type=expected[3],
                    remote_id=dependency_remote_id,
                )
            ):
                raise GraphInvariantError("exact active dependency mapping is not ready")
            dependency_ids[expected[3]] = dependency_remote_id

        if operation_type in {DEAL_CREATE, ACTIVITY_CREATE}:
            contact_operation = (
                dependency
                if operation_type == DEAL_CREATE
                else con.execute(
                    "SELECT * FROM crm_outbox WHERE operation_id=?",
                    (str(dependency["dependency_operation_id"] or ""),),
                ).fetchone()
            )
            if not contact_operation or (
                str(contact_operation["operation_type"]) != CONTACT_CREATE
                or str(contact_operation["lf_entity_type"]) != "contact"
                or str(contact_operation["lf_entity_id"]) != metadata["contact_id"]
            ):
                raise GraphInvariantError("Deal graph has another Contact dependency")
            contact_metadata = self._parse_metadata(contact_operation)
            for context_key in ("mapping_manifest_hash",):
                if contact_metadata.get(context_key, "") != metadata.get(
                    context_key, ""
                ):
                    raise GraphInvariantError("CRM graph mapping context changed")
            company_operation = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?",
                (str(contact_operation["dependency_operation_id"] or ""),),
            ).fetchone()
            if not company_operation or (
                str(company_operation["operation_type"]) != COMPANY_CREATE
                or str(company_operation["lf_entity_type"]) != "company"
                or str(company_operation["lf_entity_id"]) != company_id
            ):
                raise GraphInvariantError("Contact graph has another Company dependency")
            company_metadata = self._parse_metadata(company_operation)
            for context_key in ("mapping_manifest_hash",):
                if company_metadata.get(context_key, "") != metadata.get(
                    context_key, ""
                ):
                    raise GraphInvariantError("CRM graph mapping context changed")
            if require_sent:
                company_remote_id = _remote_id(company_operation["remote_entity_id"])
                contact_remote_id = _remote_id(contact_operation["remote_entity_id"])
                if (
                    str(company_operation["state"]) != "SENT"
                    or str(company_operation["remote_entity_type"]) != "company"
                    or not company_remote_id
                    or not self._exact_mapping_tx(
                        con,
                        lf_type="company",
                        lf_id=company_id,
                        remote_type="company",
                        remote_id=company_remote_id,
                    )
                    or str(contact_operation["state"]) != "SENT"
                    or str(contact_operation["remote_entity_type"]) != "contact"
                    or not contact_remote_id
                    or not self._exact_mapping_tx(
                        con,
                        lf_type="contact",
                        lf_id=metadata["contact_id"],
                        remote_type="contact",
                        remote_id=contact_remote_id,
                    )
                ):
                    raise GraphInvariantError("exact Company/Contact mappings are not ready")
                dependency_ids.update(
                    {"company": company_remote_id, "contact": contact_remote_id}
                )
        return dependency_ids

    def _validate_operation_tx(
        self, con: Any, operation: dict[str, Any] | Any, *, require_sent: bool
    ) -> dict[str, str]:
        operation_type = str(operation["operation_type"])
        if operation_type not in _OPERATION_ORDER:
            raise GraphInvariantError("operation is not part of the CRM graph")
        metadata = self._parse_metadata(operation)
        self._assert_stage_anchor_tx(con, operation)
        if operation_type == COMPANY_CREATE:
            if str(operation["lf_entity_type"]) != "company" or str(
                operation["lf_entity_id"]
            ) != metadata["company_id"]:
                raise GraphInvariantError("Company operation identity changed")
            if not con.execute(
                "SELECT 1 FROM companies WHERE lf_company_id=?",
                (metadata["company_id"],),
            ).fetchone():
                raise GraphInvariantError("Company disappeared from the LF graph")
        elif operation_type == CONTACT_CREATE:
            if str(operation["lf_entity_type"]) != "contact" or str(
                operation["lf_entity_id"]
            ) != metadata["contact_id"]:
                raise GraphInvariantError("Contact operation identity changed")
            contact = con.execute(
                "SELECT lf_company_id FROM contacts WHERE lf_contact_id=?",
                (metadata["contact_id"],),
            ).fetchone()
            if not contact or str(contact[0]) != metadata["company_id"]:
                raise GraphInvariantError("Contact moved to another Company")
        else:
            if str(operation["lf_entity_type"]) != "opportunity" or str(
                operation["lf_entity_id"]
            ) != metadata["opportunity_id"]:
                raise GraphInvariantError("Deal/Activity operation identity changed")
            self._assert_exact_graph_tx(
                con,
                company_id=metadata["company_id"],
                contact_id=metadata["contact_id"],
                project_id=metadata["project_id"],
                opportunity_id=metadata["opportunity_id"],
            )
            self._assert_no_lead_path_tx(con, metadata["opportunity_id"])
        return self._dependency_ids_tx(con, operation, require_sent=require_sent)

    @staticmethod
    def _writers_enabled_tx(con: Any) -> bool:
        return CrmOutbox._generic_writers_enabled_tx(con)

    def _writers_enabled(self) -> bool:
        self.store.init()
        con = self.store.connect()
        try:
            return self._writers_enabled_tx(con)
        finally:
            con.close()

    def _first_pending(self) -> dict[str, Any] | None:
        self.store.init()
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT o.* FROM crm_outbox o
                   WHERE o.operation_type IN (?,?,?,?) AND o.state='PENDING'
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=o.operation_id
                     )
                   ORDER BY CASE o.operation_type
                       WHEN ? THEN 1 WHEN ? THEN 2 WHEN ? THEN 3 ELSE 4 END,
                       o.created_at_utc,o.operation_id LIMIT 1""",
                (*_OPERATION_ORDER, *_OPERATION_ORDER[:3]),
            ).fetchone()
            return dict(row) if row else None
        finally:
            con.close()

    def claim_next(
        self, worker_id: str, *, lease_seconds: int = 120
    ) -> dict[str, Any] | None:
        worker = self._required_id(worker_id, "worker_id")
        if not self._writers_enabled():
            return None
        now = utc_now()
        lease_token = new_lf_id("lease")
        with self.store.transaction() as con:
            if not self._writers_enabled_tx(con):
                return None
            candidates = con.execute(
                """SELECT o.* FROM crm_outbox o
                   WHERE o.operation_type IN (?,?,?,?) AND o.state='PENDING'
                     AND (o.next_attempt_at_utc='' OR o.next_attempt_at_utc<=?)
                     AND (o.lease_until_utc='' OR o.lease_until_utc<=?)
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=o.operation_id
                     )
                   ORDER BY CASE o.operation_type
                       WHEN ? THEN 1 WHEN ? THEN 2 WHEN ? THEN 3 ELSE 4 END,
                       o.created_at_utc,o.operation_id""",
                (*_OPERATION_ORDER, now, now, *_OPERATION_ORDER[:3]),
            ).fetchall()
            for row in candidates:
                try:
                    dependency_ids = self._validate_operation_tx(
                        con, row, require_sent=True
                    )
                except (GraphInvariantError, IdempotencyConflict):
                    # A normal unsent parent is not claimable yet.  Persisted
                    # corruption is surfaced by process_next without a create.
                    continue
                changed = con.execute(
                    """UPDATE crm_outbox SET state='UNCERTAIN',
                           attempt_count=attempt_count+1,leased_by=?,lease_token=?,
                           lease_until_utc=?,updated_at_utc=?
                       WHERE operation_id=? AND state='PENDING'
                         AND (lease_until_utc='' OR lease_until_utc<=?)""",
                    (
                        worker,
                        lease_token,
                        _future(lease_seconds),
                        now,
                        row["operation_id"],
                        now,
                    ),
                )
                if changed.rowcount != 1:
                    continue
                claimed = con.execute(
                    "SELECT * FROM crm_outbox WHERE operation_id=?",
                    (row["operation_id"],),
                ).fetchone()
                if not claimed or str(claimed["state"]) != "UNCERTAIN":
                    return None
                result = dict(claimed)
                result["_dependency_remote_ids"] = dependency_ids
                return result
        return None

    # ------------------------------------------------------------------
    # Worker state transitions
    # ------------------------------------------------------------------
    def _review_unclaimed_tx(
        self,
        con: Any,
        operation: dict[str, Any] | Any,
        *,
        expected_state: str,
        error: Exception,
    ) -> CrmOperationResult:
        """Quarantine a corrupted unbound command without any provider call."""

        operation_id = str(operation["operation_id"])
        error_class = type(error).__name__
        target_state = (
            "CONFLICT_REVIEW" if isinstance(error, IdempotencyConflict) else "REVIEW"
        )
        error_hash = payload_hash({"type": error_class, "message": str(error)})
        now = utc_now()
        changed = con.execute(
            """UPDATE crm_outbox SET state=?,next_attempt_at_utc='',
                   lease_until_utc='',leased_by='',lease_token='',
                   last_error_class=?,last_error_hash=?,updated_at_utc=?
               WHERE operation_id=? AND state=?
                 AND NOT EXISTS(
                     SELECT 1 FROM canary_operation_bindings b
                     WHERE b.operation_id=crm_outbox.operation_id
                 )""",
            (
                target_state,
                error_class,
                error_hash,
                now,
                operation_id,
                expected_state,
            ),
        )
        if changed.rowcount != 1:
            bound = con.execute(
                "SELECT 1 FROM canary_operation_bindings WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            return CrmOperationResult(
                operation_id,
                "BLOCKED" if bound else "STALE",
                error_class="CanaryOperationBound" if bound else "StaleLease",
            )
        self.store._append_event_tx(
            con,
            event_type=f"crm_graph_operation_{target_state.lower()}",
            aggregate_type=str(operation["lf_entity_type"]),
            aggregate_id=str(operation["lf_entity_id"]),
            producer="crm_graph_outbox",
            idempotency_key=(
                f"crm-graph-preflight-review:{operation_id}:{expected_state}:"
                f"{error_hash}"
            ),
            payload={
                "operation_id": operation_id,
                "state": target_state,
                "error_class": error_class,
                "provider_called": False,
            },
            actor="integration_worker",
        )
        return CrmOperationResult(operation_id, target_state, error_class=error_class)

    def _review_unclaimed(
        self,
        operation: dict[str, Any],
        *,
        expected_state: str,
        error: Exception,
    ) -> CrmOperationResult:
        with self.store.transaction() as con:
            current = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?",
                (operation["operation_id"],),
            ).fetchone()
            if not current:
                return CrmOperationResult(
                    str(operation["operation_id"]), "STALE", error_class="StaleLease"
                )
            return self._review_unclaimed_tx(
                con, current, expected_state=expected_state, error=error
            )

    def _set_failure(
        self,
        operation: dict[str, Any],
        *,
        state: str,
        error: Exception,
        retry_after_seconds: int = 0,
    ) -> CrmOperationResult:
        operation_id = str(operation["operation_id"])
        error_class = type(error).__name__
        error_hash = payload_hash({"type": error_class, "message": str(error)})
        suspect_id = _remote_id(getattr(error, "remote_id", ""))
        suspect_type = str(
            getattr(error, "remote_entity_type", _REMOTE_TYPE[operation["operation_type"]])
            or _REMOTE_TYPE[operation["operation_type"]]
        ).strip().lower()
        now = utc_now()
        with self.store.transaction() as con:
            row = con.execute(
                """SELECT state,lease_token,lease_until_utc,attempt_count,
                          reconcile_count,suspect_remote_entity_type,
                          suspect_remote_entity_id,
                          EXISTS(
                              SELECT 1 FROM canary_operation_bindings b
                              WHERE b.operation_id=crm_outbox.operation_id
                          ) AS canary_bound
                   FROM crm_outbox WHERE operation_id=?""",
                (operation_id,),
            ).fetchone()
            if row and int(row["canary_bound"] or 0):
                # Binding ownership is immutable.  A generic worker must not
                # even clear its former lease or annotate a bound operation.
                return CrmOperationResult(
                    operation_id, "BLOCKED", error_class="CanaryOperationBound"
                )
            if (
                not row
                or str(row["state"]) != "UNCERTAIN"
                or str(row["lease_token"]) != str(operation.get("lease_token", ""))
                or not str(row["lease_until_utc"] or "")
                or str(row["lease_until_utc"]) < now
            ):
                return CrmOperationResult(operation_id, "STALE", error_class="StaleLease")
            effective_id = suspect_id or str(row["suspect_remote_entity_id"] or "")
            effective_type = (
                suspect_type if suspect_id else str(row["suspect_remote_entity_type"] or "")
            )
            changed = con.execute(
                """UPDATE crm_outbox SET state=?,next_attempt_at_utc=?,
                       lease_until_utc='',leased_by='',lease_token='',
                       last_error_class=?,last_error_hash=?,
                       suspect_remote_entity_type=?,suspect_remote_entity_id=?,
                       updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN' AND lease_token=?
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=crm_outbox.operation_id
                     )""",
                (
                    state,
                    _future(retry_after_seconds) if retry_after_seconds else "",
                    error_class,
                    error_hash,
                    effective_type,
                    effective_id,
                    now,
                    operation_id,
                    operation.get("lease_token", ""),
                ),
            )
            if changed.rowcount != 1:
                return CrmOperationResult(operation_id, "STALE", error_class="StaleLease")
            self.store._append_event_tx(
                con,
                event_type=f"crm_graph_operation_{state.lower()}",
                aggregate_type=str(operation["lf_entity_type"]),
                aggregate_id=str(operation["lf_entity_id"]),
                producer="crm_graph_outbox",
                idempotency_key=(
                    f"crm-graph-state:{operation_id}:{row['attempt_count']}:"
                    f"{row['reconcile_count']}:{state}"
                ),
                payload={
                    "operation_id": operation_id,
                    "state": state,
                    "error_class": error_class,
                },
                actor="integration_worker",
            )
        return CrmOperationResult(operation_id, state, error_class=error_class)

    def _release_without_create(
        self, operation: dict[str, Any], *, stopped: bool
    ) -> CrmOperationResult:
        error: Exception = (
            GraphStopRequested("CRM graph stop was requested")
            if stopped
            else ExternalWritersDisabled("external writers are disabled")
        )
        released = self._set_failure(operation, state="PENDING", error=error)
        if released.state == "STALE":
            return released
        return CrmOperationResult(
            released.operation_id,
            "STOPPED" if stopped else "BLOCKED",
            error_class=type(error).__name__,
        )

    def _pre_create_recheck(
        self,
        operation: dict[str, Any],
        *,
        stop_requested: Callable[[], bool] | None,
    ) -> CrmOperationResult | None:
        if stop_requested and stop_requested():
            return self._release_without_create(operation, stopped=True)
        now = utc_now()
        con = self.store.connect()
        try:
            current = con.execute(
                """SELECT o.*,
                          EXISTS(
                              SELECT 1 FROM canary_operation_bindings b
                              WHERE b.operation_id=o.operation_id
                          ) AS canary_bound
                   FROM crm_outbox o WHERE o.operation_id=?""",
                (operation["operation_id"],),
            ).fetchone()
            if current and int(current["canary_bound"] or 0):
                raise CanaryOperationBound(
                    "sealed canary owns the CRM graph operation"
                )
            if (
                not current
                or str(current["state"]) != "UNCERTAIN"
                or str(current["lease_token"]) != str(operation.get("lease_token", ""))
                or not str(current["lease_until_utc"] or "")
                or str(current["lease_until_utc"]) < now
            ):
                return CrmOperationResult(
                    str(operation["operation_id"]), "STALE", error_class="StaleLease"
                )
            if not self._writers_enabled_tx(con):
                writers_enabled = False
                dependency_ids: dict[str, str] = {}
            else:
                writers_enabled = True
                dependency_ids = self._validate_operation_tx(
                    con, current, require_sent=True
                )
        except (GraphInvariantError, IdempotencyConflict) as exc:
            return self._set_failure(operation, state="REVIEW", error=exc)
        finally:
            con.close()
        if not writers_enabled:
            return self._release_without_create(operation, stopped=False)
        if dependency_ids != dict(operation.get("_dependency_remote_ids", {})):
            return self._set_failure(
                operation,
                state="REVIEW",
                error=GraphInvariantError(
                    "dependency remote ids changed after the operation was claimed"
                ),
            )
        if stop_requested and stop_requested():
            return self._release_without_create(operation, stopped=True)
        return None

    @staticmethod
    def _request(operation: dict[str, Any]) -> CrmGraphCreateRequest:
        body = json.loads(str(operation["payload_json"]))
        public_payload = {
            key: value for key, value in body.items() if not str(key).startswith("_lf_")
        }
        metadata = CrmGraphOutbox._parse_metadata(operation)
        dependencies = tuple(
            sorted(dict(operation.get("_dependency_remote_ids", {})).items())
        )
        identity_ids = tuple(
            sorted(
                (key.removesuffix("_id"), value)
                for key, value in metadata.items()
                if key in {"company_id", "contact_id", "project_id", "opportunity_id"}
            )
        )
        return CrmGraphCreateRequest(
            operation_id=str(operation["operation_id"]),
            operation_type=str(operation["operation_type"]),
            remote_entity_type=_REMOTE_TYPE[str(operation["operation_type"])],
            correlation_token=str(operation["correlation_token"]),
            payload=public_payload,
            dependency_remote_ids=dependencies,
            lf_entity_type=str(operation["lf_entity_type"]),
            lf_entity_id=str(operation["lf_entity_id"]),
            source_event_id=str(operation["external_event_id"]),
            idempotency_key=str(operation["idempotency_key"]),
            command_payload_hash=str(operation["payload_hash"]),
            mapping_manifest_hash=metadata.get("mapping_manifest_hash", ""),
            lf_source_id=metadata.get("lf_source_id", ""),
            graph_identity_ids=identity_ids,
        )

    @staticmethod
    def _verify_readback(
        operation: dict[str, Any], value: object
    ) -> CrmGraphReadback:
        expected_type = _REMOTE_TYPE[str(operation["operation_type"])]
        candidate_id = _remote_id(
            value.remote_id if isinstance(value, CrmGraphReadback) else ""
        )
        if not isinstance(value, CrmGraphReadback):
            raise GraphReadbackMismatch(
                "adapter returned an untyped CRM graph receipt",
                remote_id=candidate_id,
                remote_type=expected_type,
            )
        if (
            value.readback_verified is not True
            or type(value.remote_entity_type) is not str
            or value.remote_entity_type != expected_type
            or not candidate_id
            or type(value.correlation_token) is not str
            or value.correlation_token != str(operation["correlation_token"])
        ):
            raise GraphReadbackMismatch(
                "CRM graph correlation readback does not match the create",
                remote_id=candidate_id,
                remote_type=expected_type,
            )
        dependencies = dict(operation.get("_dependency_remote_ids", {}))
        expected_parents = {
            COMPANY_CREATE: {
                "company_remote_id": "",
                "contact_remote_id": "",
                "deal_remote_id": "",
            },
            CONTACT_CREATE: {
                "company_remote_id": dependencies.get("company", ""),
                "contact_remote_id": "",
                "deal_remote_id": "",
            },
            DEAL_CREATE: {
                "company_remote_id": dependencies.get("company", ""),
                "contact_remote_id": dependencies.get("contact", ""),
                "deal_remote_id": "",
            },
            ACTIVITY_CREATE: {
                "company_remote_id": dependencies.get("company", ""),
                "contact_remote_id": dependencies.get("contact", ""),
                "deal_remote_id": dependencies.get("deal", ""),
            },
        }[str(operation["operation_type"])]
        if any(_remote_id(getattr(value, field, "")) != expected for field, expected in expected_parents.items()):
            raise GraphReadbackMismatch(
                "CRM graph readback points at another parent",
                remote_id=candidate_id,
                remote_type=expected_type,
            )
        return value

    def _mark_sent(
        self, operation: dict[str, Any], receipt: CrmGraphReadback
    ) -> CrmOperationResult:
        receipt = self._verify_readback(operation, receipt)
        remote_type = _REMOTE_TYPE[str(operation["operation_type"])]
        remote_id = _remote_id(receipt.remote_id)
        now = utc_now()
        with self.store.transaction() as con:
            current = con.execute(
                """SELECT o.*,
                          EXISTS(
                              SELECT 1 FROM canary_operation_bindings b
                              WHERE b.operation_id=o.operation_id
                          ) AS canary_bound
                   FROM crm_outbox o WHERE o.operation_id=?""",
                (operation["operation_id"],),
            ).fetchone()
            if current and int(current["canary_bound"] or 0):
                raise CanaryOperationBound(
                    "sealed canary owns the CRM graph operation"
                )
            if (
                not current
                or str(current["state"]) != "UNCERTAIN"
                or str(current["lease_token"]) != str(operation.get("lease_token", ""))
                or not str(current["lease_until_utc"] or "")
                or str(current["lease_until_utc"]) < now
            ):
                raise StaleLease("CRM graph operation lease is no longer owned")
            dependency_ids = self._validate_operation_tx(
                con, current, require_sent=True
            )
            if dependency_ids != dict(operation.get("_dependency_remote_ids", {})):
                raise GraphReadbackMismatch(
                    "CRM graph dependency changed before local commit",
                    remote_id=remote_id,
                    remote_type=remote_type,
                )

            # No two graph operations may claim the same remote record, even
            # for Activity where the base schema has no local mapping row.
            duplicate = con.execute(
                """SELECT operation_id FROM crm_outbox
                   WHERE operation_id<>? AND remote_entity_type=?
                     AND remote_entity_id=? AND state='SENT'""",
                (operation["operation_id"], remote_type, remote_id),
            ).fetchone()
            if duplicate:
                raise MappingConflict(
                    "remote CRM entity is already owned by another graph operation",
                    remote_id=remote_id,
                )

            if remote_type != "activity":
                lf_type = str(current["lf_entity_type"])
                lf_id = str(current["lf_entity_id"])
                local_mapping = con.execute(
                    """SELECT remote_entity_type,remote_entity_id,state
                       FROM crm_mappings WHERE lf_entity_type=? AND lf_entity_id=?""",
                    (lf_type, lf_id),
                ).fetchone()
                if local_mapping and (
                    str(local_mapping["remote_entity_type"]),
                    str(local_mapping["remote_entity_id"]),
                    str(local_mapping["state"]),
                ) != (remote_type, remote_id, "ACTIVE"):
                    raise MappingConflict(
                        "local LF entity already maps to another CRM identity",
                        remote_id=remote_id,
                    )
                remote_mapping = con.execute(
                    """SELECT lf_entity_type,lf_entity_id,state FROM crm_mappings
                       WHERE remote_entity_type=? AND remote_entity_id=?""",
                    (remote_type, remote_id),
                ).fetchone()
                if remote_mapping and (
                    str(remote_mapping["lf_entity_type"]),
                    str(remote_mapping["lf_entity_id"]),
                    str(remote_mapping["state"]),
                ) != (lf_type, lf_id, "ACTIVE"):
                    raise MappingConflict(
                        "remote CRM entity already maps to another LF identity",
                        remote_id=remote_id,
                    )
                if not local_mapping:
                    con.execute(
                        """INSERT INTO crm_mappings(
                               lf_entity_type,lf_entity_id,remote_entity_type,
                               remote_entity_id,state,last_readback_at_utc,created_at_utc
                           ) VALUES(?,?,?,?,?,?,?)""",
                        (lf_type, lf_id, remote_type, remote_id, "ACTIVE", now, now),
                    )
                else:
                    con.execute(
                        """UPDATE crm_mappings SET last_readback_at_utc=?
                           WHERE lf_entity_type=? AND lf_entity_id=?""",
                        (now, lf_type, lf_id),
                    )

            changed = con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type=?,
                       remote_entity_id=?,lease_until_utc='',leased_by='',lease_token='',
                       next_attempt_at_utc='',last_error_class='',last_error_hash='',
                       suspect_remote_entity_type='',suspect_remote_entity_id='',
                       updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN' AND lease_token=?""",
                (
                    remote_type,
                    remote_id,
                    now,
                    operation["operation_id"],
                    operation.get("lease_token", ""),
                ),
            )
            if changed.rowcount != 1:
                raise StaleLease("CRM graph lease changed before local commit")
            self.store._append_event_tx(
                con,
                event_type="crm_graph_operation_sent",
                aggregate_type=str(operation["lf_entity_type"]),
                aggregate_id=str(operation["lf_entity_id"]),
                producer="crm_graph_outbox",
                idempotency_key=(
                    f"crm-graph-sent:{operation['operation_id']}:{remote_type}:{remote_id}"
                ),
                payload={
                    "operation_id": operation["operation_id"],
                    "remote_entity_type": remote_type,
                    "remote_entity_id": remote_id,
                    "dependency_operation_id": operation["dependency_operation_id"],
                },
                actor="integration_worker",
            )
        return CrmOperationResult(str(operation["operation_id"]), "SENT", remote_id)

    def process_next(
        self,
        transport: CrmGraphTransport,
        *,
        worker_id: str,
        stop_requested: Callable[[], bool] | None = None,
        before_create_hook: Callable[[], None] | None = None,
        after_remote_hook: Callable[[], None] | None = None,
    ) -> CrmOperationResult | None:
        pending = self._first_pending()
        if not pending:
            return None
        if not self._writers_enabled():
            return CrmOperationResult(
                str(pending["operation_id"]),
                "BLOCKED",
                error_class="ExternalWritersDisabled",
            )
        operation = self.claim_next(worker_id)
        if not operation:
            # Distinguish an ordinary dependency wait from graph corruption.
            con = self.store.connect()
            invalid: Exception | None = None
            try:
                try:
                    self._validate_operation_tx(con, pending, require_sent=False)
                except (GraphInvariantError, IdempotencyConflict) as exc:
                    invalid = exc
            finally:
                con.close()
            if invalid is not None:
                return self._review_unclaimed(
                    pending, expected_state="PENDING", error=invalid
                )
            return CrmOperationResult(
                str(pending["operation_id"]),
                "WAITING_DEPENDENCY",
                error_class="DependencyNotReady",
            )
        verified: CrmGraphReadback | None = None
        try:
            if before_create_hook:
                before_create_hook()
            blocked = self._pre_create_recheck(
                operation, stop_requested=stop_requested
            )
            if blocked:
                return blocked
            request = self._request(operation)
            assert_external_allowed("bitrix.crm_graph.entity.create")
            receipt = transport.create_entity(request)
            verified = self._verify_readback(operation, receipt)
            if after_remote_hook:
                after_remote_hook()
            return self._mark_sent(operation, verified)
        except ExternalAuthorityError as exc:
            released = self._set_failure(operation, state="PENDING", error=exc)
            if released.state == "STALE":
                return released
            return CrmOperationResult(
                str(operation["operation_id"]),
                "BLOCKED",
                error_class=type(exc).__name__,
            )
        except RetryableRemoteError as exc:
            attempts = max(1, int(operation["attempt_count"]))
            return self._set_failure(
                operation,
                state="PENDING",
                error=exc,
                retry_after_seconds=min(3600, 30 * (2 ** min(attempts - 1, 6))),
            )
        except PermanentRemoteError as exc:
            return self._set_failure(operation, state="DEAD", error=exc)
        except (GraphReadbackMismatch, MappingConflict) as exc:
            return self._set_failure(operation, state="CONFLICT_REVIEW", error=exc)
        except (GraphInvariantError, IdempotencyConflict) as exc:
            mismatch = GraphReadbackMismatch(
                str(exc),
                remote_id=verified.remote_id if verified else "",
                remote_type=_REMOTE_TYPE[str(operation["operation_type"])],
            )
            return self._set_failure(
                operation, state="CONFLICT_REVIEW", error=mismatch
            )
        except StaleLease:
            return CrmOperationResult(
                str(operation["operation_id"]), "STALE", error_class="StaleLease"
            )
        except Exception as exc:
            # The adapter call might have succeeded.  Preserve UNCERTAIN and
            # allow only correlation reconciliation, never another create.
            return self._set_failure(operation, state="UNCERTAIN", error=exc)

    # ------------------------------------------------------------------
    # Ambiguous outcome reconciliation
    # ------------------------------------------------------------------
    def _first_uncertain_unbound(self) -> dict[str, Any] | None:
        """Return only work owned by the generic graph reconciler."""

        self.store.init()
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT o.* FROM crm_outbox o
                   WHERE o.operation_type IN (?,?,?,?) AND o.state='UNCERTAIN'
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=o.operation_id
                     )
                   ORDER BY o.updated_at_utc,o.operation_id LIMIT 1""",
                _OPERATION_ORDER,
            ).fetchone()
            return dict(row) if row else None
        finally:
            con.close()

    def _claim_reconcile(
        self, worker_id: str, *, lease_seconds: int = 120
    ) -> dict[str, Any] | CrmOperationResult | None:
        worker = self._required_id(worker_id, "worker_id")
        if not self._writers_enabled():
            return None
        now = utc_now()
        lease_token = new_lf_id("lease")
        with self.store.transaction() as con:
            # Reconciliation is externally read-only, but it is still an
            # external connector call.  The sealed canary and global writer
            # gates therefore apply exactly as they do to create workers.
            if not self._writers_enabled_tx(con):
                return None
            rows = con.execute(
                """SELECT o.* FROM crm_outbox o
                   WHERE o.operation_type IN (?,?,?,?) AND o.state='UNCERTAIN'
                     AND (o.next_attempt_at_utc='' OR o.next_attempt_at_utc<=?)
                     AND (o.lease_until_utc='' OR o.lease_until_utc<=?)
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=o.operation_id
                     )
                   ORDER BY o.updated_at_utc,o.operation_id""",
                (*_OPERATION_ORDER, now, now),
            ).fetchall()
            for row in rows:
                try:
                    dependencies = self._validate_operation_tx(
                        con, row, require_sent=True
                    )
                except (GraphInvariantError, IdempotencyConflict) as exc:
                    # An ambiguous remote outcome whose local dependency proof
                    # has disappeared cannot be looked up safely and must not
                    # remain UNCERTAIN forever at reconcile_count=0.
                    return self._review_unclaimed_tx(
                        con, row, expected_state="UNCERTAIN", error=exc
                    )
                changed = con.execute(
                    """UPDATE crm_outbox SET leased_by=?,lease_token=?,lease_until_utc=?,
                           reconcile_count=reconcile_count+1,updated_at_utc=?
                       WHERE operation_id=? AND state='UNCERTAIN'
                         AND (lease_until_utc='' OR lease_until_utc<=?)
                         AND NOT EXISTS(
                             SELECT 1 FROM canary_operation_bindings b
                             WHERE b.operation_id=crm_outbox.operation_id
                         )""",
                    (
                        worker,
                        lease_token,
                        _future(lease_seconds),
                        now,
                        row["operation_id"],
                        now,
                    ),
                )
                if changed.rowcount != 1:
                    continue
                claimed = con.execute(
                    """SELECT o.* FROM crm_outbox o WHERE o.operation_id=?
                         AND NOT EXISTS(
                             SELECT 1 FROM canary_operation_bindings b
                             WHERE b.operation_id=o.operation_id
                         )""",
                    (row["operation_id"],),
                ).fetchone()
                if not claimed or str(claimed["state"]) != "UNCERTAIN":
                    return None
                result = dict(claimed)
                result["_dependency_remote_ids"] = dependencies
                return result
        return None

    def _pre_reconcile_recheck(
        self, operation: dict[str, Any]
    ) -> CrmOperationResult | None:
        """Repeat all generic ownership gates immediately before lookup.

        A bound operation is never mutated by this method.  If a generic gate
        closes after claim, the unbound lease is released without recording a
        reconciliation attempt because no provider lookup occurred.
        """

        now = utc_now()
        with self.store.transaction() as con:
            current = con.execute(
                """SELECT o.*,
                          EXISTS(
                              SELECT 1 FROM canary_operation_bindings b
                              WHERE b.operation_id=o.operation_id
                          ) AS canary_bound
                   FROM crm_outbox o WHERE o.operation_id=?""",
                (operation["operation_id"],),
            ).fetchone()
            if current and int(current["canary_bound"] or 0):
                return CrmOperationResult(
                    str(operation["operation_id"]),
                    "BLOCKED",
                    error_class="CanaryOperationBound",
                )
            if (
                not current
                or str(current["state"]) != "UNCERTAIN"
                or str(current["lease_token"]) != str(operation.get("lease_token", ""))
                or not str(current["lease_until_utc"] or "")
                or str(current["lease_until_utc"]) < now
            ):
                return CrmOperationResult(
                    str(operation["operation_id"]), "STALE", error_class="StaleLease"
                )

            if not self._writers_enabled_tx(con):
                error_class = "ExternalWritersDisabled"
            else:
                try:
                    dependencies = self._validate_operation_tx(
                        con, current, require_sent=True
                    )
                except (GraphInvariantError, IdempotencyConflict) as exc:
                    return self._review_unclaimed_tx(
                        con, current, expected_state="UNCERTAIN", error=exc
                    )
                if dependencies != dict(operation.get("_dependency_remote_ids", {})):
                    return self._review_unclaimed_tx(
                        con,
                        current,
                        expected_state="UNCERTAIN",
                        error=GraphInvariantError(
                            "dependency remote ids changed after reconciliation claim"
                        ),
                    )
                return None

            released = con.execute(
                """UPDATE crm_outbox SET leased_by='',lease_token='',
                       lease_until_utc='',
                       reconcile_count=CASE
                           WHEN reconcile_count>0 THEN reconcile_count-1 ELSE 0 END,
                       updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN' AND lease_token=?
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=crm_outbox.operation_id
                     )""",
                (
                    now,
                    operation["operation_id"],
                    operation.get("lease_token", ""),
                ),
            )
            if released.rowcount != 1:
                # A binding won the race.  Do not clear or annotate its row.
                return CrmOperationResult(
                    str(operation["operation_id"]),
                    "BLOCKED",
                    error_class="CanaryOperationBound",
                )
            return CrmOperationResult(
                str(operation["operation_id"]), "BLOCKED", error_class=error_class
            )

    def _record_unresolved_reconciliation(
        self,
        operation: dict[str, Any],
        *,
        error: Exception,
        retry_after_seconds: int,
    ) -> CrmOperationResult:
        """Bound every provider lookup that cannot prove an exact outcome."""

        attempts = max(1, int(operation["reconcile_count"]))
        if attempts >= self.max_reconcile_attempts:
            return self._set_failure(operation, state="REVIEW", error=error)
        return self._set_failure(
            operation,
            state="UNCERTAIN",
            error=error,
            retry_after_seconds=retry_after_seconds,
        )

    def reconcile_next(
        self,
        transport: CrmGraphTransport,
        *,
        worker_id: str,
        before_find_hook: Callable[[], None] | None = None,
    ) -> CrmOperationResult | None:
        candidate = self._first_uncertain_unbound()
        if not candidate:
            return None
        if not self._writers_enabled():
            return CrmOperationResult(
                str(candidate["operation_id"]),
                "BLOCKED",
                error_class="ExternalWritersDisabled",
            )
        operation = self._claim_reconcile(worker_id)
        if not operation:
            return None
        if isinstance(operation, CrmOperationResult):
            return operation
        remote_type = _REMOTE_TYPE[str(operation["operation_type"])]
        verified: CrmGraphReadback | None = None
        try:
            if before_find_hook:
                before_find_hook()
            blocked = self._pre_reconcile_recheck(operation)
            if blocked:
                return blocked
            assert_external_allowed("bitrix.crm_graph.entity.reconcile")
            receipt = transport.find_by_correlation(
                remote_type, str(operation["correlation_token"])
            )
            if receipt is not None:
                verified = self._verify_readback(operation, receipt)
                return self._mark_sent(operation, verified)
            attempts = max(1, int(operation["reconcile_count"]))
            return self._record_unresolved_reconciliation(
                operation,
                error=AmbiguousRemoteError("correlation lookup returned no exact record"),
                retry_after_seconds=min(3600, 30 * (2 ** min(attempts - 1, 6))),
            )
        except ExternalAuthorityError as exc:
            released = self._set_failure(
                operation,
                state="UNCERTAIN",
                error=exc,
                retry_after_seconds=120,
            )
            if released.state == "STALE":
                return released
            return CrmOperationResult(
                str(operation["operation_id"]),
                "BLOCKED",
                error_class=type(exc).__name__,
            )
        except (GraphReadbackMismatch, MappingConflict) as exc:
            return self._set_failure(operation, state="CONFLICT_REVIEW", error=exc)
        except (GraphInvariantError, IdempotencyConflict) as exc:
            mismatch = GraphReadbackMismatch(
                str(exc),
                remote_id=verified.remote_id if verified else "",
                remote_type=remote_type,
            )
            return self._set_failure(
                operation, state="CONFLICT_REVIEW", error=mismatch
            )
        except SafeReconciliationUnsupported as exc:
            return self._set_failure(operation, state="REVIEW", error=exc)
        except PermanentRemoteError as exc:
            # A permanent read failure cannot prove that create failed.
            return self._set_failure(operation, state="REVIEW", error=exc)
        except StaleLease:
            return CrmOperationResult(
                str(operation["operation_id"]), "STALE", error_class="StaleLease"
            )
        except Exception as exc:
            # The provider lookup happened but did not prove either absence or
            # an exact correlated entity.  It consumes the same bounded budget
            # as an empty lookup; otherwise repeated timeouts stay UNCERTAIN
            # forever and silently bypass max_reconcile_attempts.
            return self._record_unresolved_reconciliation(
                operation,
                error=exc,
                retry_after_seconds=60,
            )


__all__ = [
    "ACTIVITY_CREATE",
    "CanaryOperationBound",
    "COMPANY_CREATE",
    "CONTACT_CREATE",
    "DEAL_CREATE",
    "CrmGraphCreateRequest",
    "CrmGraphOutbox",
    "CrmGraphReadback",
    "CrmGraphStageResult",
    "CrmGraphTransport",
    "GraphInvariantError",
    "GraphReadbackMismatch",
    "GraphStopRequested",
    "SafeReconciliationUnsupported",
]
