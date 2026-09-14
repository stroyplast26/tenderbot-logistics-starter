"""Pinned acceptance of one independently reviewed pre-dispatch observation.

An input hash is not authority.  Only the source-reviewed acceptance registry
below can accept a proof.  These receipts grant no credential or network access.
No archive member is imported or executed by this verifier.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import zipfile


TENDERPLAN_NO_DISPATCH_ACCEPTANCE_ID = "tpnd_20260914_9ced15e3298344a1bc29078d7c42e42c_v1"
TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION = "PREPARE_LOCAL_TENDERPLAN_NO_DISPATCH_ADMISSION"
_ACCEPTED_NO_DISPATCH_EVIDENCE = {
    TENDERPLAN_NO_DISPATCH_ACCEPTANCE_ID: {
        "proof_file_sha256": "3b3b3efa7d7dfe5d73622ebf99ba998fa002d07e7554c6397ce78057d144b5f7",
        "proof_record_sha256": "42b7facd86fe089b174cab83da7d8e1ae4838cca3dba4befaf175087b8daad94",
        "attempt_id": "sd_9ced15e3298344a1bc29078d7c42e42c",
        "run_id": "tpri_9ced15e3298344a1bc29078d7c42e42c",
        "source_commit": "fa29dc613a843ed24f92e2940eae4bd1079e1b2f",
        "sealed_worker_bundle_sha256": "e2db4ce8f6ef6f924c991380970c2d8884d9dcb133c459006d6b861d9190ab9f",
        "runtime_manifest_sha256": "a9079a6991aa4e636e6865e56cc75ce9b78c8b49d161d010bab839caa24393a4",
        "tenderplan_transport_source_sha256": "3f620d944cfefb8014c3b7b6fc541f159783cffdd87775eee4b163d98eff6291",
        "tenderplan_store_source_sha256": "d6428ad47e567f34c2e32852b6be782d0e73404e31946bff6855374e3fd2f16b",
    }
}
PROVENANCE_PATH_KEYS = frozenset({
    "bundle", "runtime_manifest", "proposal", "authority", "consumption_marker",
    "terminal", "runner", "launcher",
})
_PROVENANCE_HASH_FIELDS = {
    "bundle": "sealed_worker_bundle_sha256",
    "runtime_manifest": "runtime_manifest_sha256",
    "proposal": "proposal_file_sha256",
    "authority": "authority_file_sha256",
    "consumption_marker": "consumption_marker_file_sha256",
    "terminal": "terminal_file_sha256",
    "runner": "runner_sha256",
    "launcher": "launcher_sha256",
}


class TenderPlanNoDispatchEvidenceError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("TENDERPLAN_NO_DISPATCH_EVIDENCE_INVALID")


def canonical_no_dispatch(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def no_dispatch_digest(value: object) -> str:
    return hashlib.sha256(canonical_no_dispatch(value)).hexdigest()


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TenderPlanNoDispatchEvidenceError
        result[key] = value
    return result


def _read_bytes(path: str | Path, *, maximum: int = 16 * 1024 * 1024) -> bytes:
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size > maximum or path.is_symlink()):
        raise TenderPlanNoDispatchEvidenceError
    payload = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) or len(payload) != before.st_size:
        raise TenderPlanNoDispatchEvidenceError
    return payload


def accepted_no_dispatch_evidence(acceptance_id: str) -> dict[str, str]:
    if type(acceptance_id) is not str or acceptance_id not in _ACCEPTED_NO_DISPATCH_EVIDENCE:
        raise TenderPlanNoDispatchEvidenceError
    return dict(_ACCEPTED_NO_DISPATCH_EVIDENCE[acceptance_id])


def _verified_proof(proof: object, acceptance_id: str) -> dict[str, object]:
    accepted = accepted_no_dispatch_evidence(acceptance_id)
    try:
        if type(proof) is not dict:
            raise ValueError
        body = dict(proof)
        record = body.pop("record_sha256")
        if record != accepted["proof_record_sha256"] or no_dispatch_digest(body) != record:
            raise ValueError
        execution = proof["execution_provenance"]
        native = proof["native"]
        result = proof["result"]
        if (
            proof["schema"] != "tenderplan-attested-no-dispatch-proof-v1"
            or proof["proof_state"] != "PROVEN_NO_DISPATCH_UNDER_ATTESTED_CLAIM_BEFORE_CREDENTIAL_PROTOCOL"
            or proof["attempt_id"] != accepted["attempt_id"]
            or proof["run_id"] != accepted["run_id"]
            or proof["run_id"] != "tpri_" + proof["attempt_id"][3:]
            or any(execution[key] != accepted[key] for key in (
                "source_commit", "sealed_worker_bundle_sha256", "runtime_manifest_sha256",
                "tenderplan_transport_source_sha256", "tenderplan_store_source_sha256",
            ))
            or native["raw_state"] != "UNCERTAIN"
            or type(native["event_count"]) is not int or native["event_count"] != 2
            or execution["authority_consumed"] is not True
            or execution["terminal_raw_credential_read_count"] is not None
            or execution["terminal_raw_provider_request_count"] is not None
            or proof["controller"]["raw_state"] != "UNCERTAIN"
            or proof["claim_before_credential_protocol"]["conclusion"]
            != "COMMITTED_DISPATCH_CLAIM_PRECEDES_CREDENTIAL_AND_PROVIDER_ENTRY"
            or any(type(native[key]) is not int or native[key] != 0 for key in (
                "dispatch_claim_count", "card_count", "decision_count"))
            or any(type(result[key]) is not int or result[key] != 0 for key in (
                "credential_read_count", "provider_request_count", "provider_write_count",
                "card_count", "decision_count"))
            or any(value is not False for value in proof["gates"].values())
        ):
            raise ValueError
        return dict(proof)
    except (KeyError, TypeError, ValueError):
        raise TenderPlanNoDispatchEvidenceError from None


def verify_accepted_execution_provenance(
    *, acceptance_id: str, proof_path: str | Path,
    provenance_paths: Mapping[str, str | Path],
) -> dict[str, object]:
    """Verify reviewed historical material, without executing a worker."""
    try:
        accepted = accepted_no_dispatch_evidence(acceptance_id)
        payload = _read_bytes(proof_path, maximum=131_072)
        if hashlib.sha256(payload).hexdigest() != accepted["proof_file_sha256"]:
            raise TenderPlanNoDispatchEvidenceError
        proof = _verified_proof(json.loads(payload, object_pairs_hook=_object_pairs), acceptance_id)
        if set(provenance_paths) != PROVENANCE_PATH_KEYS:
            raise TenderPlanNoDispatchEvidenceError
        materials = {key: _read_bytes(path) for key, path in provenance_paths.items()}
        execution = proof["execution_provenance"]
        for key, material in materials.items():
            if hashlib.sha256(material).hexdigest() != execution[_PROVENANCE_HASH_FIELDS[key]]:
                raise TenderPlanNoDispatchEvidenceError
        with zipfile.ZipFile(io.BytesIO(materials["bundle"])) as archive:
            names = archive.namelist()
            manifest_bytes = archive.read("__sealed_manifest__.json")
            if hashlib.sha256(manifest_bytes).hexdigest() != execution["sealed_worker_embedded_manifest_sha256"]:
                raise TenderPlanNoDispatchEvidenceError
            manifest = json.loads(manifest_bytes, object_pairs_hook=_object_pairs)
            files = manifest["files"]
            if (type(files) is not dict or len(names) != len(set(names))
                    or set(names) != set(files) | {"__sealed_manifest__.json"}
                    or len(files) != execution["sealed_worker_member_count"]
                    or sum(info.file_size for info in archive.infolist()) > 64 * 1024 * 1024):
                raise TenderPlanNoDispatchEvidenceError
            for name, expected in files.items():
                if (not re.fullmatch(r"[A-Za-z0-9_./-]+", name)
                        or name.startswith("/") or ".." in name.split("/")
                        or hashlib.sha256(archive.read(name)).hexdigest() != expected):
                    raise TenderPlanNoDispatchEvidenceError
            for name, field in {
                "lead_factory/tenderplan_read_only_store.py": "tenderplan_store_source_sha256",
                "lead_factory/tenderplan_read_only_transport.py": "tenderplan_transport_source_sha256",
                "lead_factory/source_discovery_control.py": "source_discovery_control_source_sha256",
            }.items():
                if files.get(name) != execution[field]:
                    raise TenderPlanNoDispatchEvidenceError
        return proof
    except (OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile, RuntimeError):
        raise TenderPlanNoDispatchEvidenceError from None


def admission_from_accepted_proof(
    proof: Mapping[str, object], *, acceptance_id: str,
) -> dict[str, object]:
    """Reconstruct the sole permissible receipt for an accepted proof.

The embedded proof permits later ledger validation after whole-file hashes
change. Its record digest must still match the independent source registry.
"""
    proof = _verified_proof(proof, acceptance_id)
    accepted = accepted_no_dispatch_evidence(acceptance_id)
    native = proof["native"]
    body = {
        "protocol": "tenderplan-no-dispatch-admission-v1",
        "acceptance_id": acceptance_id,
        "attempt_id": proof["attempt_id"], "run_id": proof["run_id"],
        "proof_file_sha256": accepted["proof_file_sha256"],
        "proof_record_sha256": accepted["proof_record_sha256"],
        "controller_attempt_sha256": proof["controller"]["attempt_sha256"],
        "controller_file_sha256": proof["controller"]["file_sha256"],
        "controller_snapshot_sha256": proof["controller"]["snapshot_sha256"],
        "native_store_identity_sha256": native["store_identity_sha256"],
        "native_path_sha256": native["path_sha256"],
        "native_file_sha256": native["file_sha256"],
        "native_schema_fingerprint_sha256": native["schema_fingerprint_sha256"],
        **{key: native[key] for key in (
            "operation_sha256", "intent_record_sha256", "request_sha256",
            "query_policy_sha256", "intent_event_sha256", "uncertain_event_sha256",
            "event_count", "dispatch_claim_count", "card_count", "decision_count",
        )},
        "credential_read_count": 0, "provider_request_count": 0,
        "retry_eligible": False, "launch_allowed": False, "authorizes_live": False,
        "automatic_schedule_eligible": False, "live_release_eligible": False,
        "accepted_proof": proof,
    }
    return {**body, "record_sha256": no_dispatch_digest(body)}


def validate_no_dispatch_admission(record: object) -> dict[str, object]:
    try:
        if type(record) is not dict:
            raise TenderPlanNoDispatchEvidenceError
        expected = admission_from_accepted_proof(
            record["accepted_proof"], acceptance_id=record["acceptance_id"])
        if canonical_no_dispatch(record) != canonical_no_dispatch(expected):
            raise TenderPlanNoDispatchEvidenceError
        return expected
    except (KeyError, TypeError, ValueError):
        raise TenderPlanNoDispatchEvidenceError from None


def no_dispatch_admission_set_sha256(admissions: object) -> str:
    records = [validate_no_dispatch_admission(record) for record in admissions]
    if len({item["run_id"] for item in records}) != len(records):
        raise TenderPlanNoDispatchEvidenceError
    return no_dispatch_digest({
        "protocol": "tenderplan-no-dispatch-admission-set-v1",
        "records": sorted((item["run_id"], item["record_sha256"]) for item in records),
    })
