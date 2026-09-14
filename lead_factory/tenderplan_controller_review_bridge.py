"""Read-only closure preview for an exact TenderPlan controller batch.

The bridge reads existing controller and native ledgers, verifies their exact
receipt/item bindings, and projects only encrypted-card metadata plus local
decision heads.  It never decrypts a card, writes either ledger, contacts a
provider, releases controller WIP, or authorizes another source read.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Final, Mapping, NoReturn

from .source_discovery_control import (
    SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
    SOURCE_DISCOVERY_STATE_PATH,
    SourceDiscoveryControlError,
    _open_read_only,
    _rows,
    _snapshot,
    _source_lab_path_sha256,
    _state_path,
)
from .tenderplan_read_only_store import (
    TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256,
    TENDERPLAN_NO_DISPATCH_SCHEMA_FINGERPRINT_SHA256,
    TENDERPLAN_READ_ONLY_QUEUE_PATH,
    TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256,
    TenderPlanReadOnlyStoreError,
    _existing_store,
)


TENDERPLAN_CONTROLLER_REVIEW_BRIDGE_VERSION: Final = (
    "tenderplan-controller-review-closure-preview-v1"
)

_ATTEMPT_ID: Final = re.compile(r"sd_[0-9a-f]{32}\Z")
_AUTHORIZATION_ID: Final = re.compile(r"tpa_[0-9a-f]{32}\Z")
_HEX64: Final = re.compile(r"[0-9a-f]{64}\Z")
_HEX40: Final = re.compile(r"[0-9a-f]{40}\Z")
_PROPOSAL_ID: Final = re.compile(r"tpp_[0-9a-f]{32}\Z")
_UTC_MICROSECONDS: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_TERMINAL_DECISIONS: Final = ("KEEP", "DISMISS", "HOLD")
_ATTESTED_SCHEMA: Final = "tenderplan-attested-no-dispatch-proof-v1"
_ATTESTED_STATE: Final = "PROVEN_NO_DISPATCH_UNDER_ATTESTED_CLAIM_BEFORE_CREDENTIAL_PROTOCOL"
_ATTESTED_CLASSIFICATION: Final = "AUTHORIZED_ATTEMPT_FAILED_PRE_CREDENTIAL_PRE_PROVIDER"


class TenderPlanControllerReviewBridgeError(RuntimeError):
    """Sanitized failure without supplied paths or source content."""

    def __init__(self, code: str = "TENDERPLAN_REVIEW_CLOSURE_PREVIEW_FAILED") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanControllerReviewClosurePreview:
    """Digest-bound metadata proof that never changes production state."""

    version: str
    state: str
    attempt_id: str
    run_id: str
    controller_state: str
    native_state: str
    controller_file_sha256: str
    controller_attempt_sha256: str
    controller_snapshot_sha256: str
    binding_receipt_sha256: str
    native_store_identity_sha256: str
    native_path_sha256: str
    native_file_sha256: str
    native_schema_fingerprint_sha256: str
    operation_sha256: str
    receipt_record_sha256: str
    native_head_event_sha256: str
    intent_record_sha256: str
    request_sha256: str
    query_policy_sha256: str
    item_ids: tuple[str, ...]
    decision_heads: tuple[Mapping[str, object], ...]
    decision_counts: Mapping[str, int]
    unresolved_item_ids: tuple[str, ...]
    attested_no_dispatch_file_sha256: str
    attested_no_dispatch_record_sha256: str
    proof_sha256: str
    closure_written: bool = False
    controller_wip_released: bool = False
    production_apply_allowed: bool = False
    snapshot_atomic_across_stores: bool = False
    retry_eligible: bool = False
    launch_allowed: bool = False
    authorizes_live: bool = False
    controller_write_count: int = 0
    native_store_write_count: int = 0
    decrypt_count: int = 0
    credential_read_count: int = 0
    provider_request_count: int = 0
    provider_write_count: int = 0
    crm_write_count: int = 0
    message_count: int = 0
    schedule_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0

    def __repr__(self) -> str:
        return (
            "TenderPlanControllerReviewClosurePreview("
            f"state={self.state!r}, attempt_id={self.attempt_id!r}, "
            f"items={len(self.item_ids)}, effects=zero, production_apply_allowed=False)"
        )


def _fail(code: str = "TENDERPLAN_REVIEW_CLOSURE_PREVIEW_FAILED") -> NoReturn:
    raise TenderPlanControllerReviewBridgeError(code)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError:
        _fail("TENDERPLAN_REVIEW_CLOSURE_UNAVAILABLE")


def _regular_file_identity(path: Path) -> tuple[int, int]:
    try:
        status = path.lstat()
    except OSError:
        _fail("TENDERPLAN_REVIEW_CLOSURE_UNAVAILABLE")
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        _fail("TENDERPLAN_REVIEW_CLOSURE_PATH_INVALID")
    return status.st_dev, status.st_ino


def _assert_no_sidecars(path: Path) -> None:
    try:
        if any(
            path.with_name(path.name + suffix).exists() for suffix in ("-wal", "-shm", "-journal")
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")
    except OSError:
        _fail("TENDERPLAN_REVIEW_CLOSURE_UNAVAILABLE")


def _strict_object(value: object) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID")
    return value


def _has_exact_hashes(value: Mapping[str, object], keys: tuple[str, ...]) -> bool:
    return all(
        type(value.get(key)) is str and _HEX64.fullmatch(str(value[key])) is not None
        for key in keys
    )


def _is_exact_int(value: object, expected: int) -> bool:
    return type(value) is int and value == expected


def _valid_recorded_at(value: object) -> bool:
    if type(value) is not str or _UTC_MICROSECONDS.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def _read_attested_proof(path: Path, expected_sha256: str) -> dict[str, object]:
    if type(expected_sha256) is not str or _HEX64.fullmatch(expected_sha256) is None:
        _fail("TENDERPLAN_REVIEW_CLOSURE_INVALID")
    identity = _regular_file_identity(path)
    try:
        payload = path.read_bytes()
    except OSError:
        _fail("TENDERPLAN_REVIEW_CLOSURE_UNAVAILABLE")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID")
    if _regular_file_identity(path) != identity:
        _fail("TENDERPLAN_REVIEW_CLOSURE_STATE_CHANGED")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        proof = json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError):
        _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID")
    proof = _strict_object(proof)
    declared_record = proof.get("record_sha256")
    material = dict(proof)
    material.pop("record_sha256", None)
    if (
        type(declared_record) is not str
        or _HEX64.fullmatch(declared_record) is None
        or _digest(material) != declared_record
    ):
        _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID")
    return proof


def _reference_id(*, store_identity_sha256: str, item_id: str, encrypted_card_sha256: str) -> str:
    return "tprw_" + _digest(
        {
            "store_identity_sha256": store_identity_sha256,
            "item_id": item_id,
            "encrypted_card_sha256": encrypted_card_sha256,
        }
    )


def _controller_attempt_material(row: object) -> dict[str, object]:
    try:
        return {
            "sequence": int(row["sequence"]),
            "attempt_id": str(row["attempt_id"]),
            "source": str(row["source"]),
            "state": str(row["state"]),
            "started_at_utc": str(row["started_at_utc"]),
            "finished_at_utc": str(row["finished_at_utc"] or ""),
            "review_count": int(row["review_count"]),
            "tenderplan_binding_required": int(row["tenderplan_binding_required"]),
        }
    except (KeyError, TypeError, ValueError, IndexError):
        _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")


def _preview(
    *,
    state: str,
    attempt_id: str,
    run_id: str,
    controller_state: str,
    native_state: str,
    controller_file_sha256: str,
    controller_attempt_sha256: str,
    controller_snapshot_sha256: str,
    binding_receipt_sha256: str,
    native_store_identity_sha256: str,
    native_path_sha256: str,
    native_file_sha256: str,
    native_schema_fingerprint_sha256: str,
    operation_sha256: str,
    receipt_record_sha256: str,
    native_head_event_sha256: str,
    intent_record_sha256: str,
    request_sha256: str,
    query_policy_sha256: str,
    item_ids: tuple[str, ...],
    decision_heads: tuple[dict[str, object], ...],
    decision_counts: dict[str, int],
    unresolved_item_ids: tuple[str, ...],
    attested_no_dispatch_file_sha256: str = "",
    attested_no_dispatch_record_sha256: str = "",
) -> TenderPlanControllerReviewClosurePreview:
    common_hashes = (
        controller_file_sha256,
        controller_attempt_sha256,
        controller_snapshot_sha256,
        native_store_identity_sha256,
        native_path_sha256,
        native_file_sha256,
        native_schema_fingerprint_sha256,
        operation_sha256,
        native_head_event_sha256,
        intent_record_sha256,
        request_sha256,
        query_policy_sha256,
    )
    if any(_HEX64.fullmatch(value) is None for value in common_hashes):
        _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")
    if state in {"READY_TO_CLOSE", "BLOCKED_REVIEW_INCOMPLETE"}:
        if (
            _HEX64.fullmatch(binding_receipt_sha256) is None
            or _HEX64.fullmatch(receipt_record_sha256) is None
            or attested_no_dispatch_file_sha256
            or attested_no_dispatch_record_sha256
            or not item_ids
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")
    elif state == "NOT_APPLICABLE_FAILED_PRE_PROVIDER":
        if (
            binding_receipt_sha256
            or receipt_record_sha256
            or _HEX64.fullmatch(attested_no_dispatch_file_sha256) is None
            or _HEX64.fullmatch(attested_no_dispatch_record_sha256) is None
            or item_ids
            or decision_heads
            or unresolved_item_ids
            or any(decision_counts.values())
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")
    else:
        _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")
    gates = {
        "authorizes_live": False,
        "closure_written": False,
        "controller_wip_released": False,
        "launch_allowed": False,
        "production_apply_allowed": False,
        "retry_eligible": False,
        "snapshot_atomic_across_stores": False,
    }
    effects = {
        "contact_count": 0,
        "controller_write_count": 0,
        "credential_read_count": 0,
        "crm_write_count": 0,
        "decrypt_count": 0,
        "message_count": 0,
        "native_store_write_count": 0,
        "provider_request_count": 0,
        "provider_write_count": 0,
        "schedule_count": 0,
        "spend_minor": 0,
    }
    body = {
        "version": TENDERPLAN_CONTROLLER_REVIEW_BRIDGE_VERSION,
        "state": state,
        "attempt_id": attempt_id,
        "run_id": run_id,
        "controller_state": controller_state,
        "native_state": native_state,
        "controller_file_sha256": controller_file_sha256,
        "controller_attempt_sha256": controller_attempt_sha256,
        "controller_snapshot_sha256": controller_snapshot_sha256,
        "binding_receipt_sha256": binding_receipt_sha256,
        "native_store_identity_sha256": native_store_identity_sha256,
        "native_path_sha256": native_path_sha256,
        "native_file_sha256": native_file_sha256,
        "native_schema_fingerprint_sha256": native_schema_fingerprint_sha256,
        "operation_sha256": operation_sha256,
        "receipt_record_sha256": receipt_record_sha256,
        "native_head_event_sha256": native_head_event_sha256,
        "intent_record_sha256": intent_record_sha256,
        "request_sha256": request_sha256,
        "query_policy_sha256": query_policy_sha256,
        "item_ids": list(item_ids),
        "decision_heads": list(decision_heads),
        "decision_counts": decision_counts,
        "unresolved_item_ids": list(unresolved_item_ids),
        "attested_no_dispatch_file_sha256": attested_no_dispatch_file_sha256,
        "attested_no_dispatch_record_sha256": attested_no_dispatch_record_sha256,
        "gates": gates,
        "effects": effects,
    }
    proof_sha256 = _digest(body)
    return TenderPlanControllerReviewClosurePreview(
        version=TENDERPLAN_CONTROLLER_REVIEW_BRIDGE_VERSION,
        state=state,
        attempt_id=attempt_id,
        run_id=run_id,
        controller_state=controller_state,
        native_state=native_state,
        controller_file_sha256=controller_file_sha256,
        controller_attempt_sha256=controller_attempt_sha256,
        controller_snapshot_sha256=controller_snapshot_sha256,
        binding_receipt_sha256=binding_receipt_sha256,
        native_store_identity_sha256=native_store_identity_sha256,
        native_path_sha256=native_path_sha256,
        native_file_sha256=native_file_sha256,
        native_schema_fingerprint_sha256=native_schema_fingerprint_sha256,
        operation_sha256=operation_sha256,
        receipt_record_sha256=receipt_record_sha256,
        native_head_event_sha256=native_head_event_sha256,
        intent_record_sha256=intent_record_sha256,
        request_sha256=request_sha256,
        query_policy_sha256=query_policy_sha256,
        item_ids=item_ids,
        decision_heads=tuple(MappingProxyType(dict(item)) for item in decision_heads),
        decision_counts=MappingProxyType(dict(decision_counts)),
        unresolved_item_ids=unresolved_item_ids,
        attested_no_dispatch_file_sha256=attested_no_dispatch_file_sha256,
        attested_no_dispatch_record_sha256=attested_no_dispatch_record_sha256,
        proof_sha256=proof_sha256,
    )


def _ready_preview(
    *,
    attempt: dict[str, object],
    binding: dict[str, object],
    controller_file_sha256: str,
    controller_attempt_sha256: str,
    controller_snapshot_sha256: str,
    native_path: Path,
) -> TenderPlanControllerReviewClosurePreview:
    native_identity = _regular_file_identity(native_path)
    native_before = _file_sha256(native_path)
    _assert_no_sidecars(native_path)
    store = _existing_store(native_path)
    native_path_sha256 = _source_lab_path_sha256(store.path)
    run_id = str(binding["run_id"])
    item_ids = tuple(str(item) for item in binding["item_ids"])
    if (
        store.store_identity_sha256 != binding["native_store_identity_sha256"]
        or native_path_sha256 != binding["native_path_sha256"]
    ):
        _fail("TENDERPLAN_REVIEW_CLOSURE_BINDING_MISMATCH")

    with store._transaction(write=False) as connection:  # noqa: SLF001
        ready = store._ready_receipt(connection, run_id)  # noqa: SLF001
        operation = connection.execute(
            """SELECT operation_sha256,intent_record_sha256,intent_json
               FROM tenderplan_read_only_operations WHERE run_id=?""",
            (run_id,),
        ).fetchone()
        native_schema_fingerprint_sha256 = {
            1: TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256,
            2: TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256,
            3: TENDERPLAN_NO_DISPATCH_SCHEMA_FINGERPRINT_SHA256,
        }.get(int(connection.execute("PRAGMA user_version").fetchone()[0]))
        rows = connection.execute(
            """SELECT c.item_id,c.run_id,c.ordinal,c.encrypted_card_sha256,
                      d.decision_id,d.sequence AS decision_sequence,d.decision,
                      d.reason_code,d.decision_sha256
               FROM tenderplan_read_only_cards c
               LEFT JOIN tenderplan_read_only_decisions d
                 ON d.item_id=c.item_id
                AND d.sequence=(
                    SELECT MAX(x.sequence) FROM tenderplan_read_only_decisions x
                    WHERE x.item_id=c.item_id
                )
               WHERE c.run_id=? ORDER BY c.ordinal""",
            (run_id,),
        ).fetchall()
        if operation is None or native_schema_fingerprint_sha256 is None:
            _fail("TENDERPLAN_REVIEW_CLOSURE_BINDING_MISMATCH")
        intent = _strict_object(json.loads(str(operation["intent_json"])))
        if (
            ready.receipt_record_sha256 != binding["receipt_record_sha256"]
            or ready.event_sha256 != binding["event_sha256"]
            or ready.item_ids != item_ids
            or ready.card_count != binding["card_count"]
            or int(attempt["review_count"]) != ready.card_count
            or tuple(str(row["item_id"]) for row in rows) != item_ids
            or str(operation["intent_record_sha256"]) != binding["intent_record_sha256"]
            or intent.get("intent_record_sha256") != binding["intent_record_sha256"]
            or intent.get("request_sha256") != binding["request_sha256"]
            or intent.get("query_policy_sha256") != binding["query_policy_sha256"]
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_BINDING_MISMATCH")

        counts = {decision: 0 for decision in _TERMINAL_DECISIONS}
        counts["UNDECIDED"] = 0
        manifest: list[dict[str, object]] = []
        unresolved: list[str] = []
        for expected_ordinal, row in enumerate(rows, start=1):
            item_id = str(row["item_id"])
            decision = "UNDECIDED" if row["decision"] is None else str(row["decision"])
            if int(row["ordinal"]) != expected_ordinal or str(row["run_id"]) != run_id:
                _fail("TENDERPLAN_REVIEW_CLOSURE_BINDING_MISMATCH")
            if decision not in counts:
                _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")
            counts[decision] += 1
            if decision == "UNDECIDED":
                unresolved.append(item_id)
            encrypted_sha256 = str(row["encrypted_card_sha256"])
            manifest.append(
                {
                    "item_id": item_id,
                    "ordinal": expected_ordinal,
                    "run_id": run_id,
                    "encrypted_card_sha256": encrypted_sha256,
                    "reference_id": _reference_id(
                        store_identity_sha256=store.store_identity_sha256,
                        item_id=item_id,
                        encrypted_card_sha256=encrypted_sha256,
                    ),
                    "decision": decision,
                    "decision_id": ("" if row["decision_id"] is None else str(row["decision_id"])),
                    "decision_sequence": (
                        0 if row["decision_sequence"] is None else int(row["decision_sequence"])
                    ),
                    "decision_sha256": (
                        "" if row["decision_sha256"] is None else str(row["decision_sha256"])
                    ),
                    "reason_code": ("" if row["reason_code"] is None else str(row["reason_code"])),
                }
            )

    _assert_no_sidecars(native_path)
    if (
        _regular_file_identity(native_path) != native_identity
        or _file_sha256(native_path) != native_before
    ):
        _fail("TENDERPLAN_REVIEW_CLOSURE_STATE_CHANGED")
    return _preview(
        state=("READY_TO_CLOSE" if not unresolved else "BLOCKED_REVIEW_INCOMPLETE"),
        attempt_id=str(attempt["attempt_id"]),
        run_id=run_id,
        controller_state=str(attempt["state"]),
        native_state="READY_FOR_REVIEW",
        controller_file_sha256=controller_file_sha256,
        controller_attempt_sha256=controller_attempt_sha256,
        controller_snapshot_sha256=controller_snapshot_sha256,
        binding_receipt_sha256=str(binding["binding_receipt_sha256"]),
        native_store_identity_sha256=store.store_identity_sha256,
        native_path_sha256=native_path_sha256,
        native_file_sha256=native_before,
        native_schema_fingerprint_sha256=native_schema_fingerprint_sha256,
        operation_sha256=str(operation["operation_sha256"]),
        receipt_record_sha256=ready.receipt_record_sha256,
        native_head_event_sha256=ready.event_sha256,
        intent_record_sha256=str(binding["intent_record_sha256"]),
        request_sha256=str(binding["request_sha256"]),
        query_policy_sha256=str(binding["query_policy_sha256"]),
        item_ids=item_ids,
        decision_heads=tuple(manifest),
        decision_counts=counts,
        unresolved_item_ids=tuple(unresolved),
    )


def _failed_pre_provider_preview(
    *,
    attempt: dict[str, object],
    controller_file_sha256: str,
    controller_attempt_sha256: str,
    controller_snapshot: dict[str, object],
    native_path: Path,
    attested_proof_path: Path,
    expected_attested_proof_sha256: str,
) -> TenderPlanControllerReviewClosurePreview:
    proof = _read_attested_proof(attested_proof_path, expected_attested_proof_sha256)
    controller = _strict_object(proof.get("controller"))
    native = _strict_object(proof.get("native"))
    result = _strict_object(proof.get("result"))
    gates = _strict_object(proof.get("gates"))
    evidence = _strict_object(proof.get("evidence"))
    execution = _strict_object(proof.get("execution_provenance"))
    protocol = _strict_object(proof.get("claim_before_credential_protocol"))
    diagnostic = _strict_object(proof.get("corroborative_diagnostic"))
    local_fix = _strict_object(proof.get("local_fix"))
    controller_latest = _strict_object(controller_snapshot.get("latest"))
    controller_snapshot_sha256 = _digest(controller_snapshot)
    record_sha256 = str(proof["record_sha256"])
    run_id = str(proof.get("run_id"))
    native_identity = _regular_file_identity(native_path)
    native_before = _file_sha256(native_path)
    _assert_no_sidecars(native_path)
    store = _existing_store(native_path)
    native_path_sha256 = _source_lab_path_sha256(store.path)

    if (
        proof.get("schema") != _ATTESTED_SCHEMA
        or proof.get("proof_state") != _ATTESTED_STATE
        or not _valid_recorded_at(proof.get("recorded_at_utc"))
        or proof.get("attempt_id") != attempt["attempt_id"]
        or run_id != "tpri_" + str(attempt["attempt_id"])[3:]
        or controller.get("raw_state") != "UNCERTAIN"
        or controller_snapshot.get("gate") != "BLOCKED_UNCERTAIN"
        or controller_latest.get("attempt_id") != attempt["attempt_id"]
        or controller.get("raw_gate") != controller_snapshot.get("gate")
        or controller.get("file_sha256") != controller_file_sha256
        or controller.get("attempt_sha256") != controller_attempt_sha256
        or controller.get("snapshot_sha256") != controller_snapshot_sha256
        or not _is_exact_int(controller.get("binding_count"), 0)
        or not _is_exact_int(controller.get("reconciliation_count"), 0)
        or native.get("raw_state") != "UNCERTAIN"
        or native.get("file_sha256") != native_before
        or native.get("path_sha256") != native_path_sha256
        or native.get("store_identity_sha256") != store.store_identity_sha256
        or not _is_exact_int(native.get("event_count"), 2)
        or not _is_exact_int(native.get("dispatch_claim_count"), 0)
        or not _is_exact_int(native.get("card_count"), 0)
        or not _is_exact_int(native.get("decision_count"), 0)
        or result.get("classification") != _ATTESTED_CLASSIFICATION
        or not _is_exact_int(result.get("credential_read_count"), 0)
        or not _is_exact_int(result.get("provider_request_count"), 0)
        or not _is_exact_int(result.get("provider_write_count"), 0)
        or not _is_exact_int(result.get("card_count"), 0)
        or not _is_exact_int(result.get("decision_count"), 0)
        or result.get("provider_result") != "UNKNOWN"
        or result.get("import_result") != "ABSENT"
        or execution.get("authority_consumed") is not True
        or type(execution.get("source_commit")) is not str
        or _HEX40.fullmatch(str(execution["source_commit"])) is None
        or type(execution.get("proposal_id")) is not str
        or _PROPOSAL_ID.fullmatch(str(execution["proposal_id"])) is None
        or type(execution.get("authorization_id")) is not str
        or _AUTHORIZATION_ID.fullmatch(str(execution["authorization_id"])) is None
        or not _has_exact_hashes(
            execution,
            (
                "proposal_file_sha256",
                "proposal_record_sha256",
                "authority_file_sha256",
                "authority_record_sha256",
                "authorization_transcript_sha256",
                "consumption_marker_file_sha256",
                "consumption_marker_record_sha256",
                "terminal_file_sha256",
                "terminal_record_sha256",
                "runtime_manifest_sha256",
                "sealed_worker_bundle_sha256",
                "sealed_worker_embedded_manifest_sha256",
                "tenderplan_store_source_sha256",
                "tenderplan_transport_source_sha256",
                "source_discovery_control_source_sha256",
                "runner_sha256",
                "launcher_sha256",
            ),
        )
        or type(execution.get("sealed_worker_member_count")) is not int
        or int(execution["sealed_worker_member_count"]) <= 0
        or execution.get("terminal_raw_credential_read_count") is not None
        or execution.get("terminal_raw_provider_request_count") is not None
        or protocol.get("conclusion")
        != "COMMITTED_DISPATCH_CLAIM_PRECEDES_CREDENTIAL_AND_PROVIDER_ENTRY"
        or any(
            type(protocol.get(key)) is not int or int(protocol[key]) <= 0
            for key in (
                "claim_call_line",
                "provider_call_line",
                "dispatch_claim_append_line",
                "verified_intent_return_line",
                "transaction_yield_line",
                "transaction_commit_line",
            )
        )
        or type(protocol.get("credential_call_lines")) is not list
        or not protocol["credential_call_lines"]
        or any(type(line) is not int or line <= 0 for line in protocol["credential_call_lines"])
        or not (
            int(protocol["claim_call_line"])
            < min(int(line) for line in protocol["credential_call_lines"])
            < int(protocol["provider_call_line"])
        )
        or max(int(line) for line in protocol["credential_call_lines"])
        >= int(protocol["provider_call_line"])
        or int(protocol["dispatch_claim_append_line"])
        >= int(protocol["verified_intent_return_line"])
        or not (int(protocol["transaction_yield_line"]) < int(protocol["transaction_commit_line"]))
        or diagnostic.get("currently_present") is not True
        or diagnostic.get("diagnostic_code") != "WORKER_PRE_DISPATCH_VALIDATION"
        or diagnostic.get("observation_stage") != "WORKER_PRE_PROVIDER"
        or diagnostic.get("retry_eligible") is not False
        or diagnostic.get("used_as_authority") is not False
        or not _has_exact_hashes(
            diagnostic,
            ("current_file_sha256", "forensic_recorded_file_sha256"),
        )
        or diagnostic.get("current_file_sha256") != diagnostic.get("forensic_recorded_file_sha256")
        or type(local_fix.get("commit")) is not str
        or _HEX40.fullmatch(str(local_fix["commit"])) is None
        or local_fix.get("published") is not True
        or local_fix.get("authorizes_retry") is not False
        or not _has_exact_hashes(
            local_fix,
            ("test_source_sha256", "transport_source_sha256"),
        )
        or evidence.get("state_files_byte_identical_before_after") is not True
        or evidence.get("sqlite_sidecars_absent_before_after") is not True
        or evidence.get("diagnostic_observation_unchanged_during_proof") is not True
        or evidence.get("terminal_preserved") is not True
        or not _has_exact_hashes(evidence, ("post_run_forensic_sha256",))
        or any(
            gates.get(key) is not False
            for key in (
                "authority_verified_for_new_action",
                "authorizes_live",
                "changes_controller_gate",
                "changes_native_outcome",
                "changes_terminal_counts",
                "creates_proposal",
                "launch_allowed",
                "retry_eligible",
                "sidecar_used_as_authority",
            )
        )
    ):
        _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID")

    with store._transaction(write=False) as connection:  # noqa: SLF001
        native_schema_fingerprint_sha256 = {
            1: TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256,
            2: TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256,
        }.get(int(connection.execute("PRAGMA user_version").fetchone()[0]))
        operation = connection.execute(
            "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?", (run_id,)
        ).fetchone()
        events = connection.execute(
            "SELECT * FROM tenderplan_read_only_events WHERE run_id=? ORDER BY sequence",
            (run_id,),
        ).fetchall()
        card_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_cards WHERE run_id=?", (run_id,)
            ).fetchone()[0]
        )
        decision_count = int(
            connection.execute(
                """SELECT COUNT(*) FROM tenderplan_read_only_decisions d
                   INNER JOIN tenderplan_read_only_cards c ON c.item_id=d.item_id
                   WHERE c.run_id=?""",
                (run_id,),
            ).fetchone()[0]
        )
        if (
            operation is None
            or len(events) != 2
            or native_schema_fingerprint_sha256 is None
            or native.get("schema_fingerprint_sha256") != native_schema_fingerprint_sha256
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID")
        intent = _strict_object(json.loads(str(operation["intent_json"])))
        if (
            str(operation["operation_sha256"]) != native.get("operation_sha256")
            or str(operation["intent_record_sha256"]) != native.get("intent_record_sha256")
            or intent.get("request_sha256") != native.get("request_sha256")
            or intent.get("query_policy_sha256") != native.get("query_policy_sha256")
            or any(
                type(native.get(key)) is not int or native[key] != intent.get(key)
                for key in (
                    "maximum_records",
                    "maximum_response_bytes",
                    "request_count",
                    "write_count",
                    "spend_minor",
                )
            )
            or str(events[0]["event_type"]) != "INTENT_COMMITTED"
            or str(events[0]["state"]) != "INTENT"
            or str(events[0]["event_sha256"]) != native.get("intent_event_sha256")
            or str(events[1]["event_type"]) != "UNCERTAIN_COMMITTED"
            or str(events[1]["state"]) != "UNCERTAIN"
            or str(events[1]["event_sha256"]) != native.get("uncertain_event_sha256")
            or any(str(event["event_type"]) == "DISPATCH_CLAIMED_COMMITTED" for event in events)
            or card_count != 0
            or decision_count != 0
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID")

    _assert_no_sidecars(native_path)
    if (
        _regular_file_identity(native_path) != native_identity
        or _file_sha256(native_path) != native_before
    ):
        _fail("TENDERPLAN_REVIEW_CLOSURE_STATE_CHANGED")
    counts = {decision: 0 for decision in _TERMINAL_DECISIONS}
    counts["UNDECIDED"] = 0
    return _preview(
        state="NOT_APPLICABLE_FAILED_PRE_PROVIDER",
        attempt_id=str(attempt["attempt_id"]),
        run_id=run_id,
        controller_state=str(attempt["state"]),
        native_state="UNCERTAIN",
        controller_file_sha256=controller_file_sha256,
        controller_attempt_sha256=controller_attempt_sha256,
        controller_snapshot_sha256=controller_snapshot_sha256,
        binding_receipt_sha256="",
        native_store_identity_sha256=store.store_identity_sha256,
        native_path_sha256=native_path_sha256,
        native_file_sha256=native_before,
        native_schema_fingerprint_sha256=native_schema_fingerprint_sha256,
        operation_sha256=str(native["operation_sha256"]),
        receipt_record_sha256="",
        native_head_event_sha256=str(native["uncertain_event_sha256"]),
        intent_record_sha256=str(native["intent_record_sha256"]),
        request_sha256=str(native["request_sha256"]),
        query_policy_sha256=str(native["query_policy_sha256"]),
        item_ids=(),
        decision_heads=(),
        decision_counts=counts,
        unresolved_item_ids=(),
        attested_no_dispatch_file_sha256=expected_attested_proof_sha256,
        attested_no_dispatch_record_sha256=record_sha256,
    )


def inspect_tenderplan_controller_review_closure(
    attempt_id: str,
    *,
    state_path: str | Path = SOURCE_DISCOVERY_STATE_PATH,
    tenderplan_store_path: str | Path = TENDERPLAN_READ_ONLY_QUEUE_PATH,
    attested_no_dispatch_proof_path: str | Path | None = None,
    expected_attested_no_dispatch_proof_sha256: str | None = None,
) -> TenderPlanControllerReviewClosurePreview:
    """Preview exact batch closure without decrypting or changing either store.

    ``expected_attested_no_dispatch_proof_sha256`` is an exact trusted pin supplied
    by the caller from accepted evidence; the proof file cannot authorize itself.
    """

    if type(attempt_id) is not str or _ATTEMPT_ID.fullmatch(attempt_id) is None:
        _fail("TENDERPLAN_REVIEW_CLOSURE_INVALID")
    if (attested_no_dispatch_proof_path is None) != (
        expected_attested_no_dispatch_proof_sha256 is None
    ):
        _fail("TENDERPLAN_REVIEW_CLOSURE_INVALID")

    control_connection = None
    try:
        control_path = _state_path(state_path)
        native_path = _state_path(tenderplan_store_path)
        controller_identity = _regular_file_identity(control_path)
        controller_before = _file_sha256(control_path)
        _assert_no_sidecars(control_path)
        control_connection = _open_read_only(control_path)
        control_connection.execute("BEGIN")
        matches = [
            row
            for row in _rows(control_path, _connection=control_connection)
            if row["attempt_id"] == attempt_id
        ]
        if len(matches) != 1 or str(matches[0]["source"]) != "TENDERPLAN":
            _fail("TENDERPLAN_REVIEW_CLOSURE_NOT_FOUND")
        attempt = matches[0]
        attempt_row = control_connection.execute(
            "SELECT * FROM source_discovery_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if attempt_row is None:
            _fail("TENDERPLAN_REVIEW_CLOSURE_NOT_FOUND")
        attempt_material = _controller_attempt_material(attempt_row)
        if any(
            attempt_material[key] != attempt[key]
            for key in ("attempt_id", "source", "state", "review_count")
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED")
        controller_attempt_sha256 = _digest(attempt_material)
        controller_snapshot = _snapshot(
            control_path,
            SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
            _connection=control_connection,
        )
        controller_snapshot_sha256 = _digest(controller_snapshot)
        binding_count = int(
            control_connection.execute(
                "SELECT COUNT(*) FROM source_discovery_tenderplan_bindings WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()[0]
        )
        reconciliation_table = control_connection.execute(
            """SELECT 1 FROM sqlite_master WHERE type='table'
               AND name='source_discovery_tenderplan_failed_closed_reconciliations'"""
        ).fetchone()
        reconciliation_count = (
            int(
                control_connection.execute(
                    """SELECT COUNT(*)
                       FROM source_discovery_tenderplan_failed_closed_reconciliations
                       WHERE attempt_id=?""",
                    (attempt_id,),
                ).fetchone()[0]
            )
            if reconciliation_table is not None
            else 0
        )
        binding = attempt.get("tenderplan_binding")
        if (
            str(attempt["state"]) == "READY_FOR_REVIEW"
            and type(binding) is dict
            and attempt_material["tenderplan_binding_required"] == 1
            and binding_count == 1
            and reconciliation_count == 0
        ):
            if attested_no_dispatch_proof_path is not None:
                _fail("TENDERPLAN_REVIEW_CLOSURE_INVALID")
            preview = _ready_preview(
                attempt=attempt,
                binding=binding,
                controller_file_sha256=controller_before,
                controller_attempt_sha256=controller_attempt_sha256,
                controller_snapshot_sha256=controller_snapshot_sha256,
                native_path=native_path,
            )
        elif (
            str(attempt["state"]) == "UNCERTAIN"
            and binding is None
            and int(attempt_material["review_count"]) == 0
            and attempt_material["tenderplan_binding_required"] == 1
            and binding_count == 0
            and reconciliation_count == 0
        ):
            if (
                attested_no_dispatch_proof_path is None
                or expected_attested_no_dispatch_proof_sha256 is None
            ):
                _fail("TENDERPLAN_REVIEW_CLOSURE_PROOF_REQUIRED")
            preview = _failed_pre_provider_preview(
                attempt=attempt,
                controller_file_sha256=controller_before,
                controller_attempt_sha256=controller_attempt_sha256,
                controller_snapshot=controller_snapshot,
                native_path=native_path,
                attested_proof_path=_state_path(attested_no_dispatch_proof_path),
                expected_attested_proof_sha256=expected_attested_no_dispatch_proof_sha256,
            )
        else:
            _fail("TENDERPLAN_REVIEW_CLOSURE_NOT_APPLICABLE")
        _assert_no_sidecars(control_path)
        if (
            _regular_file_identity(control_path) != controller_identity
            or _file_sha256(control_path) != controller_before
        ):
            _fail("TENDERPLAN_REVIEW_CLOSURE_STATE_CHANGED")
        return preview
    except TenderPlanControllerReviewBridgeError:
        raise
    except (SourceDiscoveryControlError, TenderPlanReadOnlyStoreError):
        raise TenderPlanControllerReviewBridgeError(
            "TENDERPLAN_REVIEW_CLOSURE_INTEGRITY_FAILED"
        ) from None
    except Exception:
        raise TenderPlanControllerReviewBridgeError(
            "TENDERPLAN_REVIEW_CLOSURE_PREVIEW_FAILED"
        ) from None
    finally:
        if control_connection is not None:
            try:
                if control_connection.in_transaction:
                    control_connection.rollback()
            finally:
                control_connection.close()


__all__ = [
    "TENDERPLAN_CONTROLLER_REVIEW_BRIDGE_VERSION",
    "TenderPlanControllerReviewBridgeError",
    "TenderPlanControllerReviewClosurePreview",
    "inspect_tenderplan_controller_review_closure",
]
