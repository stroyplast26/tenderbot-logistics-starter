from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from lead_factory.mdos_v7 import source_read_ledger_v4_rehearsal as rehearsal
from lead_factory.mdos_v7.source_read_ledger import (
    CANONICAL_SCHEMA_FINGERPRINT_SHA256,
    SOURCE_READ_LEDGER_SCHEMA_VERSION,
    SQLITE_APPLICATION_ID,
    ZERO_SHA256,
    SourceReadLedger,
)
from lead_factory.mdos_v7.source_read_ledger_v4_rehearsal import (
    SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER,
    SOURCE_READ_LEDGER_V4_REHEARSAL_MODE,
    SourceReadLedgerV3SchemaAllowlist,
    SourceReadLedgerV4RehearsalBounds,
    SourceReadLedgerV4RehearsalError,
    export_source_read_ledger_v3_verification_manifest,
    run_source_read_ledger_v4_verification_rehearsal,
)


RAW_CURSOR = "cursor://must-never-leave-the-v3-source"
RAW_PLAINTEXT = "customer-secret-must-never-leave-the-v3-source"


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8", "strict")).hexdigest()


def _create_synthetic_v3(path: Path) -> str:
    """Create a test-only v3 shape; it is deliberately not canonical."""

    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA application_id={SQLITE_APPLICATION_ID}")
        connection.execute("PRAGMA user_version=3")
        connection.executescript(
            """
            CREATE TABLE source_read_meta(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL CHECK(schema_version=3),
                protocol_version TEXT NOT NULL
            );
            CREATE TABLE source_read_v3_fixture_rows(
                sequence INTEGER PRIMARY KEY,
                cursor_plaintext TEXT NOT NULL,
                payload_plaintext TEXT NOT NULL,
                payload_blob BLOB,
                source_read_meta_id INTEGER NOT NULL
                    REFERENCES source_read_meta(singleton)
            );
            CREATE INDEX source_read_v3_fixture_rows_meta_idx
                ON source_read_v3_fixture_rows(source_read_meta_id);
            CREATE TRIGGER source_read_v3_fixture_rows_no_delete
            BEFORE DELETE ON source_read_v3_fixture_rows
            BEGIN
                SELECT RAISE(ABORT,'fixture rows are append-only');
            END;
            """
        )
        connection.execute(
            "INSERT INTO source_read_meta VALUES(1,3,'source-read-ledger-v3')"
        )
        connection.executemany(
            """INSERT INTO source_read_v3_fixture_rows(
                   sequence,cursor_plaintext,payload_plaintext,payload_blob,
                   source_read_meta_id
               ) VALUES(?,?,?,?,1)""",
            (
                (1, RAW_CURSOR, RAW_PLAINTEXT, b"\x00\x01fixture"),
                (2, f"{RAW_CURSOR}/2", f"{RAW_PLAINTEXT}/2", None),
            ),
        )
        connection.commit()
        _, fingerprint = rehearsal._schema_inventory(connection)
    return fingerprint


def _file_identity(path: Path) -> tuple[int, int, int, int, str]:
    stat = path.stat()
    return (
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def _paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    return (
        tmp_path / "source-v3.sqlite3",
        tmp_path / "destination-v4.sqlite3",
        tmp_path / "source-read-ledger-v4-rehearsal-receipt.json",
    )


def test_verification_only_rehearsal_is_bounded_private_and_idempotent(
    tmp_path: Path,
) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    allowlist = SourceReadLedgerV3SchemaAllowlist((fingerprint,))
    source_before = _file_identity(source)

    result = run_source_read_ledger_v4_verification_rehearsal(
        source,
        destination,
        receipt_path,
        schema_allowlist=allowlist,
    )

    assert result.replayed is False
    assert _file_identity(source) == source_before
    manifest = result.manifest
    assert manifest.source_application_id == SQLITE_APPLICATION_ID
    assert manifest.source_user_version == 3
    assert manifest.source_schema_fingerprint_sha256 == fingerprint
    assert manifest.export_mode == SOURCE_READ_LEDGER_V4_REHEARSAL_MODE
    assert manifest.table_count == 2
    assert manifest.total_row_count == 3
    assert sum(proof.row_count for proof in manifest.table_proofs) == 3
    assert all(
        proof.table_proof_sha256 != ZERO_SHA256 for proof in manifest.table_proofs
    )
    assert manifest.business_data_transfer_supported is False
    assert manifest.authority_transfer_supported is False
    assert manifest.blocker_code == SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER
    assert manifest.live_release_eligible is False

    exposed = json.dumps(asdict(manifest), ensure_ascii=False)
    exposed += receipt_path.read_text(encoding="utf-8")
    assert RAW_CURSOR not in exposed
    assert RAW_PLAINTEXT not in exposed
    assert str(source) not in exposed
    assert str(destination) not in exposed

    receipt = result.receipt
    assert receipt.rehearsal_mode == SOURCE_READ_LEDGER_V4_REHEARSAL_MODE
    assert receipt.separate_new_store_verified is True
    assert receipt.business_data_transfer_performed is False
    assert receipt.authority_transfer_performed is False
    assert receipt.blocker_code == SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER
    assert receipt.live_release_eligible is False
    assert receipt.destination_schema_version == SOURCE_READ_LEDGER_SCHEMA_VERSION
    assert (
        receipt.destination_schema_fingerprint_sha256
        == CANONICAL_SCHEMA_FINGERPRINT_SHA256
    )

    verification = SourceReadLedger(destination).verify()
    assert verification.batch_count == 0
    assert verification.operation_count == 0
    assert verification.outcome_count == 0
    assert verification.event_count == 0
    assert verification.head_event_sha256 == ZERO_SHA256
    assert verification.external_anchor_status == "NOT_ANCHORED_LOCAL_ONLY"
    assert verification.live_release_eligible is False

    destination_before = _file_identity(destination)
    receipt_before = _file_identity(receipt_path)
    replay = run_source_read_ledger_v4_verification_rehearsal(
        source,
        destination,
        receipt_path,
        schema_allowlist=allowlist,
    )
    assert replay.replayed is True
    assert replay.manifest == result.manifest
    assert replay.receipt == result.receipt
    assert _file_identity(destination) == destination_before
    assert _file_identity(receipt_path) == receipt_before


def test_export_is_deterministic_and_has_full_table_digest_proofs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-v3.sqlite3"
    fingerprint = _create_synthetic_v3(source)
    allowlist = SourceReadLedgerV3SchemaAllowlist((fingerprint,))

    first = export_source_read_ledger_v3_verification_manifest(
        source, schema_allowlist=allowlist
    )
    second = export_source_read_ledger_v3_verification_manifest(
        source, schema_allowlist=allowlist
    )

    assert first == second
    assert first.manifest_sha256 != ZERO_SHA256
    assert first.table_inventory_sha256 != ZERO_SHA256
    assert len({proof.table_name_sha256 for proof in first.table_proofs}) == 2
    assert len({proof.table_proof_sha256 for proof in first.table_proofs}) == 2


@pytest.mark.parametrize(
    ("pragma", "value", "expected_code"),
    (
        ("application_id", 0, "SOURCE_APPLICATION_ID_DIFFERS"),
        ("user_version", 2, "SOURCE_USER_VERSION_DIFFERS"),
    ),
)
def test_exact_application_and_user_version_are_required(
    tmp_path: Path, pragma: str, value: int, expected_code: str
) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    with sqlite3.connect(source) as connection:
        connection.execute(f"PRAGMA {pragma}={value}")
        connection.commit()

    with pytest.raises(SourceReadLedgerV4RehearsalError) as caught:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=SourceReadLedgerV3SchemaAllowlist((fingerprint,)),
        )

    assert caught.value.code == expected_code
    assert not destination.exists()
    assert not receipt_path.exists()


def test_unknown_or_changed_schema_fails_closed_before_artifact_creation(
    tmp_path: Path,
) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    _create_synthetic_v3(source)

    with pytest.raises(SourceReadLedgerV4RehearsalError) as caught:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=SourceReadLedgerV3SchemaAllowlist(
                (_sha("unknown-v3-schema"),)
            ),
        )

    assert caught.value.code == "SOURCE_SCHEMA_FINGERPRINT_NOT_ALLOWLISTED"
    assert not destination.exists()
    assert not receipt_path.exists()


def test_hard_bounds_reject_oversized_full_row_proof(tmp_path: Path) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    bounds = SourceReadLedgerV4RehearsalBounds(max_rows_per_table=1)

    with pytest.raises(SourceReadLedgerV4RehearsalError) as caught:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=SourceReadLedgerV3SchemaAllowlist((fingerprint,)),
            bounds=bounds,
        )

    assert caught.value.code == "SOURCE_ROW_COUNT_OUT_OF_BOUNDS"
    assert not destination.exists()
    assert not receipt_path.exists()


def test_source_tamper_cannot_rebind_existing_receipt(tmp_path: Path) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    allowlist = SourceReadLedgerV3SchemaAllowlist((fingerprint,))
    run_source_read_ledger_v4_verification_rehearsal(
        source,
        destination,
        receipt_path,
        schema_allowlist=allowlist,
    )
    destination_before = _file_identity(destination)
    receipt_before = _file_identity(receipt_path)
    with sqlite3.connect(source) as connection:
        connection.execute(
            """UPDATE source_read_v3_fixture_rows
               SET payload_plaintext=? WHERE sequence=1""",
            ("tampered-source-value",),
        )
        connection.commit()

    with pytest.raises(SourceReadLedgerV4RehearsalError) as caught:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=allowlist,
        )

    assert caught.value.code == "RECEIPT_READBACK_DIFFERS"
    assert _file_identity(destination) == destination_before
    assert _file_identity(receipt_path) == receipt_before


def test_receipt_and_destination_tamper_fail_closed(tmp_path: Path) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    allowlist = SourceReadLedgerV3SchemaAllowlist((fingerprint,))
    run_source_read_ledger_v4_verification_rehearsal(
        source,
        destination,
        receipt_path,
        schema_allowlist=allowlist,
    )

    receipt_path.write_bytes(b"{}\n")
    with pytest.raises(SourceReadLedgerV4RehearsalError) as receipt_error:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=allowlist,
        )
    assert receipt_error.value.code == "RECEIPT_READBACK_DIFFERS"

    receipt_path.unlink()
    with sqlite3.connect(destination) as connection:
        connection.execute("CREATE TABLE rehearsal_tamper(value TEXT)")
        connection.commit()
    receipt_path.write_bytes(b"{}\n")
    with pytest.raises(SourceReadLedgerV4RehearsalError) as destination_error:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=allowlist,
        )
    assert destination_error.value.code == "DESTINATION_VERIFY_FAILED"


def test_existing_target_split_state_and_aliases_never_overwrite(
    tmp_path: Path,
) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    allowlist = SourceReadLedgerV3SchemaAllowlist((fingerprint,))
    destination.write_bytes(b"pre-existing-nonempty-target")
    before = destination.read_bytes()

    with pytest.raises(SourceReadLedgerV4RehearsalError) as split_error:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=allowlist,
        )
    assert split_error.value.code == "REHEARSAL_ARTIFACT_STATE_SPLIT"
    assert destination.read_bytes() == before
    assert not receipt_path.exists()

    destination.unlink()
    with pytest.raises(SourceReadLedgerV4RehearsalError) as alias_error:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            source,
            receipt_path,
            schema_allowlist=allowlist,
        )
    assert alias_error.value.code == "ARTIFACT_PATHS_ALIAS"


def test_source_sidecar_and_v4_fingerprint_pin_are_forbidden(tmp_path: Path) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    Path(f"{source}-wal").write_bytes(b"")
    with pytest.raises(SourceReadLedgerV4RehearsalError) as sidecar_error:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=SourceReadLedgerV3SchemaAllowlist((fingerprint,)),
        )
    assert sidecar_error.value.code == "SOURCE_SIDECAR_PRESENT"

    with pytest.raises(SourceReadLedgerV4RehearsalError) as pin_error:
        SourceReadLedgerV3SchemaAllowlist((CANONICAL_SCHEMA_FINGERPRINT_SHA256,))
    assert pin_error.value.code == "V4_SCHEMA_PIN_FORBIDDEN"


def test_public_evidence_dataclasses_reject_forged_flags_and_seals(
    tmp_path: Path,
) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    result = run_source_read_ledger_v4_verification_rehearsal(
        source,
        destination,
        receipt_path,
        schema_allowlist=SourceReadLedgerV3SchemaAllowlist((fingerprint,)),
    )

    with pytest.raises(SourceReadLedgerV4RehearsalError) as table_error:
        replace(
            result.manifest.table_proofs[0],
            table_proof_sha256=_sha("forged-table-proof"),
        )
    assert table_error.value.code == "TABLE_PROOF_SEAL_DIFFERS"

    with pytest.raises(SourceReadLedgerV4RehearsalError) as manifest_flag_error:
        replace(result.manifest, live_release_eligible=True)
    assert manifest_flag_error.value.code == "MANIFEST_CONTRACT_INVALID"

    with pytest.raises(SourceReadLedgerV4RehearsalError) as manifest_seal_error:
        replace(result.manifest, manifest_sha256=_sha("forged-manifest"))
    assert manifest_seal_error.value.code == "MANIFEST_SEAL_DIFFERS"

    with pytest.raises(SourceReadLedgerV4RehearsalError) as receipt_flag_error:
        replace(result.receipt, authority_transfer_performed=True)
    assert receipt_flag_error.value.code == "RECEIPT_CONTRACT_INVALID"

    with pytest.raises(SourceReadLedgerV4RehearsalError) as receipt_seal_error:
        replace(result.receipt, receipt_sha256=_sha("forged-receipt"))
    assert receipt_seal_error.value.code == "RECEIPT_SEAL_DIFFERS"

    with pytest.raises(SourceReadLedgerV4RehearsalError) as result_error:
        replace(result, replayed=1)
    assert result_error.value.code == "RESULT_CONTRACT_INVALID"


def test_future_target_schema_cannot_pass_as_v4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, destination, receipt_path = _paths(tmp_path)
    fingerprint = _create_synthetic_v3(source)
    monkeypatch.setattr(rehearsal, "SOURCE_READ_LEDGER_SCHEMA_VERSION", 5)

    with pytest.raises(SourceReadLedgerV4RehearsalError) as caught:
        run_source_read_ledger_v4_verification_rehearsal(
            source,
            destination,
            receipt_path,
            schema_allowlist=SourceReadLedgerV3SchemaAllowlist((fingerprint,)),
        )

    assert caught.value.code == "TARGET_SCHEMA_IS_NOT_V4"
    assert not destination.exists()
    assert not receipt_path.exists()
