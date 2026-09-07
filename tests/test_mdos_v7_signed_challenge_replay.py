from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3

import pytest

from lead_factory.mdos_v7 import source_read_authority_boundary as approval_boundary
from lead_factory.mdos_v7.signed_challenge_replay import (
    DEFAULT_MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS,
    SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256,
    SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION,
    SIGNED_CHALLENGE_REPLAY_SQLITE_APPLICATION_ID,
    SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
    SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
    SignedChallengeReplayDetected,
    SignedChallengeReplayIntegrityError,
    SignedChallengeReplayStoreFull,
    SignedChallengeReplayStoreV1,
    SignedChallengeReplayValidationError,
    SignedChallengeReplayVerificationV1,
    signed_challenge_domain_sha256,
)
from lead_factory.mdos_v7.source_read_anchor_boundary import (
    PinnedSignedSourceReadExternalAnchor,
    SourceReadSignedAnchorError,
)
from lead_factory.mdos_v7.source_read_authority_boundary import (
    MAX_SOURCE_READ_SIGNED_APPROVAL_CHALLENGES,
    PinnedSignedSourceReadApprovalAuthorityV1,
)
from tests import test_mdos_v7_source_read_anchor_boundary as anchor_fixtures
from tests import test_mdos_v7_source_read_authority_boundary as approval_fixtures


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8", "strict")).hexdigest()


def _domain(boundary: str, label: str) -> str:
    return signed_challenge_domain_sha256(
        boundary,
        {
            "fixture_identity_sha256": _sha(label),
        },
    )


def test_new_store_pins_sqlite_identity_and_exact_readback(tmp_path: Path) -> None:
    path = tmp_path / "signed-challenges.sqlite3"
    store = SignedChallengeReplayStoreV1.create_new(
        path,
        maximum_reservations=10_000,
    )
    domain = _domain(SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1, "anchor")
    challenge = _sha("challenge-1")

    reservation = store.reserve(
        boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
        domain_sha256=domain,
        challenge_sha256=challenge,
    )
    readback = store.read_reservation(
        boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
        domain_sha256=domain,
        challenge_sha256=challenge,
    )
    verification = store.verify()

    assert store.path == path.resolve(strict=False)
    assert store.canonical_path == str(path.resolve(strict=False))
    assert store.live_release_eligible is False
    assert reservation == readback
    assert reservation.sequence == 1
    assert reservation.live_release_eligible is False
    assert verification == SignedChallengeReplayVerificationV1(
        schema_version=SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION,
        schema_fingerprint_sha256=(SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256),
        store_identity_sha256=store.store_identity_sha256,
        maximum_reservations=10_000,
        reservation_count=1,
        head_reservation_sha256=reservation.reservation_sha256,
        live_release_eligible=False,
    )
    assert "signed-challenges.sqlite3" not in repr(store)
    assert "live_release_eligible=False" in repr(store)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            SIGNED_CHALLENGE_REPLAY_SQLITE_APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (
            SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION,
        )
        assert connection.execute(
            """SELECT schema_fingerprint_sha256,store_identity_sha256,
                      maximum_reservations,live_release_eligible
               FROM signed_challenge_replay_meta"""
        ).fetchone() == (
            SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256,
            store.store_identity_sha256,
            10_000,
            0,
        )

    reopened = SignedChallengeReplayStoreV1.open_existing(
        path,
        expected_store_identity_sha256=store.store_identity_sha256,
        maximum_reservations=10_000,
    )
    assert reopened.verify() == verification
    with pytest.raises(SignedChallengeReplayValidationError, match="already exists"):
        SignedChallengeReplayStoreV1.create_new(path)
    with pytest.raises(SignedChallengeReplayIntegrityError, match="path identity"):
        SignedChallengeReplayStoreV1.open_existing(
            path,
            expected_store_identity_sha256=_sha("wrong-store"),
            maximum_reservations=10_000,
        )
    with pytest.raises(SignedChallengeReplayIntegrityError, match="metadata"):
        SignedChallengeReplayStoreV1.open_existing(
            path,
            expected_store_identity_sha256=store.store_identity_sha256,
            maximum_reservations=10_001,
        )


def test_replay_is_durable_domain_scoped_and_capacity_is_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bounded-challenges.sqlite3"
    store = SignedChallengeReplayStoreV1.create_new(
        path,
        maximum_reservations=3,
    )
    anchor_domain = _domain(
        SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
        "shared",
    )
    approval_domain = _domain(
        SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
        "shared",
    )
    challenge = _sha("same-csprng-output")

    first = store.reserve(
        boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
        domain_sha256=anchor_domain,
        challenge_sha256=challenge,
    )
    with pytest.raises(SignedChallengeReplayDetected, match="already reserved"):
        store.reserve(
            boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
            domain_sha256=anchor_domain,
            challenge_sha256=challenge,
        )

    reopened = SignedChallengeReplayStoreV1.open_existing(
        path,
        expected_store_identity_sha256=store.store_identity_sha256,
        maximum_reservations=3,
    )
    with pytest.raises(SignedChallengeReplayDetected):
        reopened.reserve(
            boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
            domain_sha256=anchor_domain,
            challenge_sha256=challenge,
        )

    cross_boundary = reopened.reserve(
        boundary=SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
        domain_sha256=approval_domain,
        challenge_sha256=challenge,
    )
    cross_domain = reopened.reserve(
        boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
        domain_sha256=_domain(
            SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
            "other-anchor",
        ),
        challenge_sha256=challenge,
    )
    assert (first.sequence, cross_boundary.sequence, cross_domain.sequence) == (
        1,
        2,
        3,
    )
    with pytest.raises(SignedChallengeReplayStoreFull, match="capacity"):
        reopened.reserve(
            boundary=SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
            domain_sha256=approval_domain,
            challenge_sha256=_sha("fresh-but-full"),
        )
    assert reopened.verify().reservation_count == 3
    assert DEFAULT_MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS > 4_096

    for invalid in ("", "lowercase", "A" * 129, "ЮНИКОД"):
        with pytest.raises(SignedChallengeReplayValidationError):
            reopened.reserve(
                boundary=invalid,
                domain_sha256=approval_domain,
                challenge_sha256=_sha("bounded"),
            )
    with pytest.raises(SignedChallengeReplayValidationError):
        reopened.reserve(
            boundary=SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
            domain_sha256="0" * 64,
            challenge_sha256=_sha("bounded"),
        )
    with pytest.raises(SignedChallengeReplayValidationError):
        SignedChallengeReplayVerificationV1(
            schema_version=SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION,
            schema_fingerprint_sha256=(
                SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256
            ),
            store_identity_sha256=store.store_identity_sha256,
            maximum_reservations=3,
            reservation_count=0,
            head_reservation_sha256="0" * 64,
            live_release_eligible=True,
        )


def test_append_only_triggers_and_reopen_detect_history_tamper(tmp_path: Path) -> None:
    path = tmp_path / "tamper-challenges.sqlite3"
    store = SignedChallengeReplayStoreV1.create_new(path)
    boundary = SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1
    domain = _domain(boundary, "tamper")
    store.reserve(
        boundary=boundary,
        domain_sha256=domain,
        challenge_sha256=_sha("challenge-a"),
    )
    store.reserve(
        boundary=boundary,
        domain_sha256=domain,
        challenge_sha256=_sha("challenge-b"),
    )

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE signed_challenge_reservations SET challenge_sha256=? "
                "WHERE sequence=1",
                (_sha("direct-update"),),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM signed_challenge_reservations WHERE sequence=1"
            )

    with sqlite3.connect(path) as connection:
        trigger_sql = connection.execute(
            """SELECT sql FROM sqlite_master
               WHERE type='trigger'
                 AND name='signed_challenge_reservations_no_update'"""
        ).fetchone()[0]
        connection.execute("DROP TRIGGER signed_challenge_reservations_no_update")
        connection.execute(
            "UPDATE signed_challenge_reservations SET challenge_sha256=? "
            "WHERE sequence=1",
            (_sha("sealed-history-tamper"),),
        )
        connection.execute(trigger_sql)

    with pytest.raises(SignedChallengeReplayIntegrityError, match="seal"):
        SignedChallengeReplayStoreV1.open_existing(
            path,
            expected_store_identity_sha256=store.store_identity_sha256,
        )

    corrupt_path = tmp_path / "corrupt-challenges.sqlite3"
    corrupt = SignedChallengeReplayStoreV1.create_new(corrupt_path)
    corrupt_path.write_bytes(b"not-a-sqlite-database")
    with pytest.raises(SignedChallengeReplayIntegrityError):
        SignedChallengeReplayStoreV1.open_existing(
            corrupt_path,
            expected_store_identity_sha256=corrupt.store_identity_sha256,
        )


def _durable_anchor_adapter(
    *,
    signing: anchor_fixtures._SigningFixture,
    transport: anchor_fixtures._SignedAnchorTransport,
    challenge_replay_store: SignedChallengeReplayStoreV1,
    challenge_bytes: bytes,
) -> PinnedSignedSourceReadExternalAnchor:
    return PinnedSignedSourceReadExternalAnchor(
        anchor_identity_sha256=transport.anchor_identity_sha256,
        authority_store_identity_sha256=transport.authority_store_identity_sha256,
        tenant_sha256=signing.tenant_sha256,
        requester_scope_sha256=signing.requester_scope_sha256,
        approver_scope_sha256=signing.approver_scope_sha256,
        transport=transport,
        verifier=signing.verifier,
        now_utc=lambda: "2026-08-28T12:01:00.000000Z",
        challenge_bytes=lambda _size: challenge_bytes,
        challenge_replay_store=challenge_replay_store,
    )


def _durable_approval_adapter(
    *,
    boundaries: approval_fixtures._Boundaries,
    challenge_replay_store: SignedChallengeReplayStoreV1,
    challenge_bytes: bytes,
) -> PinnedSignedSourceReadApprovalAuthorityV1:
    return PinnedSignedSourceReadApprovalAuthorityV1(
        root_policy_identity_sha256=boundaries.signing.issuer_sha256,
        authority_store_identity_sha256=(
            boundaries.signing.authority_store_identity_sha256
        ),
        tenant_sha256=boundaries.signing.tenant_sha256,
        requester_scope_sha256=boundaries.signing.requester_scope_sha256,
        approver_scope_sha256=boundaries.signing.approver_scope_sha256,
        transport=boundaries.transport,
        verifier=boundaries.signing.verifier,
        now_utc=lambda: approval_fixtures.AUTHORITY_NOW,
        challenge_bytes=lambda: challenge_bytes,
        challenge_replay_store=challenge_replay_store,
    )


def test_adapters_reserve_before_transport_and_reject_after_response_loss_restart(
    tmp_path: Path,
) -> None:
    replay_path = tmp_path / "adapter-challenges.sqlite3"
    replay_store = SignedChallengeReplayStoreV1.create_new(replay_path)
    shared_entropy = hashlib.sha256(b"shared-adapter-csprng-output").digest()
    shared_challenge = hashlib.sha256(shared_entropy).hexdigest()

    signing, anchor_transport, _, ledger_store = anchor_fixtures._fixture()
    original_anchor_read = anchor_transport.read_current

    def lose_anchor_response(query):
        original_anchor_read(query)
        raise TimeoutError("anchor response lost after remote read")

    anchor_transport.read_current = lose_anchor_response  # type: ignore[method-assign]
    anchor = _durable_anchor_adapter(
        signing=signing,
        transport=anchor_transport,
        challenge_replay_store=replay_store,
        challenge_bytes=shared_entropy,
    )
    with pytest.raises(SourceReadSignedAnchorError, match="unavailable"):
        anchor.read_receipt(store_identity_sha256=ledger_store)
    assert anchor_transport.read_calls == 1
    assert replay_store.verify().reservation_count == 1
    assert anchor.challenge_replay_store_identity_sha256 == (
        replay_store.store_identity_sha256
    )

    restarted = SignedChallengeReplayStoreV1.open_existing(
        replay_path,
        expected_store_identity_sha256=replay_store.store_identity_sha256,
    )
    anchor_transport.read_current = original_anchor_read  # type: ignore[method-assign]
    repeated_anchor = _durable_anchor_adapter(
        signing=signing,
        transport=anchor_transport,
        challenge_replay_store=restarted,
        challenge_bytes=shared_entropy,
    )
    with pytest.raises(SourceReadSignedAnchorError, match="repeated"):
        repeated_anchor.read_receipt(store_identity_sha256=ledger_store)
    assert anchor_transport.read_calls == 1

    boundaries, ledger, proof, _, candidate = approval_fixtures._setup(tmp_path)
    ledger.rotate_continuation_binding(
        proof,
        candidate,
        governance_evidence_sha256=_sha("durable-approval-governance"),
        idempotency_sha256=_sha("durable-approval-idempotency"),
        occurred_at_utc=approval_fixtures.ROTATION_TIME,
    )
    intent = boundaries.transport.last_intent
    assert intent is not None

    namespace = (
        boundaries.signing.issuer_sha256,
        boundaries.signing.authority_store_identity_sha256,
        boundaries.signing.tenant_sha256,
    )
    with approval_boundary._SIGNED_APPROVAL_CHALLENGE_LOCK:
        used = approval_boundary._SIGNED_APPROVAL_USED_CHALLENGES.setdefault(
            namespace, set()
        )
        while len(used) < MAX_SOURCE_READ_SIGNED_APPROVAL_CHALLENGES:
            used.add(_sha(f"legacy-cap-{len(used)}"))

    original_approval_read = boundaries.transport.read_approval

    def lose_approval_response(*, query):
        original_approval_read(query=query)
        raise TimeoutError("approval response lost after remote read")

    boundaries.transport.read_approval = lose_approval_response  # type: ignore[method-assign]
    durable_approval = _durable_approval_adapter(
        boundaries=boundaries,
        challenge_replay_store=restarted,
        challenge_bytes=shared_entropy,
    )
    approval_reads_before = boundaries.transport.read_calls
    with pytest.raises(TimeoutError, match="response lost"):
        durable_approval.read_approval(intent=intent)
    assert boundaries.transport.read_calls == approval_reads_before + 1
    assert restarted.verify().reservation_count == 2
    assert durable_approval.challenge_replay_store_identity_sha256 == (
        restarted.store_identity_sha256
    )

    second_restart = SignedChallengeReplayStoreV1.open_existing(
        replay_path,
        expected_store_identity_sha256=replay_store.store_identity_sha256,
    )
    boundaries.transport.read_approval = original_approval_read  # type: ignore[method-assign]
    repeated_approval = _durable_approval_adapter(
        boundaries=boundaries,
        challenge_replay_store=second_restart,
        challenge_bytes=shared_entropy,
    )
    with pytest.raises(ValueError, match="repeated"):
        repeated_approval.read_approval(intent=intent)
    assert boundaries.transport.read_calls == approval_reads_before + 1

    anchor_domain = signed_challenge_domain_sha256(
        SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
        {
            "anchor_identity_sha256": anchor.anchor_identity_sha256,
            "authority_store_identity_sha256": (anchor.authority_store_identity_sha256),
            "tenant_sha256": anchor.tenant_sha256,
            "ledger_store_identity_sha256": ledger_store,
        },
    )
    approval_domain = signed_challenge_domain_sha256(
        SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
        {
            "root_policy_identity_sha256": (
                durable_approval.root_policy_identity_sha256
            ),
            "authority_store_identity_sha256": (
                durable_approval.authority_store_identity_sha256
            ),
            "tenant_sha256": durable_approval.tenant_sha256,
        },
    )
    assert (
        second_restart.read_reservation(
            boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
            domain_sha256=anchor_domain,
            challenge_sha256=shared_challenge,
        )
        is not None
    )
    assert (
        second_restart.read_reservation(
            boundary=SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
            domain_sha256=approval_domain,
            challenge_sha256=shared_challenge,
        )
        is not None
    )
