from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from lead_factory.tenderplan_read_only_crypto import (
    EncryptedTenderPlanCardV1,
    TenderPlanReadOnlyCryptoError,
    WindowsDpapiCardKeyProtector,
    decrypt_tenderplan_card,
    encrypt_tenderplan_card,
    encrypted_card_material,
)


RUN_ID = "tenderplan-read-run-0001"
INTENT_RECORD_SHA256 = "1" * 64
QUERY_POLICY_SHA256 = "2" * 64
SEMANTIC_STATUS = "UNVERIFIED_PROVIDER_SEMANTICS"
EXPIRES_AT_UTC = "2026-08-30T12:00:00.000000Z"
SENTINEL = "secret-card-title-token-sentinel"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", "strict")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _card() -> dict[str, object]:
    identity_material = {
        "revision": "1777000000123",
        "tender_id": "000000000000000000000001",
    }
    identity_sha256 = _sha(_canonical(identity_material))
    material: dict[str, object] = {
        "currency": "RUB",
        "customer_legal_names": ["ООО Синтетический заказчик"],
        "identity_sha256": identity_sha256,
        "max_price": "1250000.5",
        "number": "TP-0001",
        "publication_datetime": "1777000000000",
        "region": "77",
        "revision": identity_material["revision"],
        "semantic_status": SEMANTIC_STATUS,
        "status": "1",
        "submission_close_datetime": "1777086400000",
        "tender_id": identity_material["tender_id"],
        "title": SENTINEL,
    }
    material["record_sha256"] = _sha(_canonical(material))
    return material


class FakeProtector:
    prefix = b"fake-card-key-v1:"

    def wrap_key(self, key: bytes) -> bytes:
        if type(key) is not bytes or len(key) != 32:
            raise RuntimeError("fake protector rejected key")
        return self.prefix + key

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        if (
            type(wrapped_key) is not bytes
            or len(wrapped_key) != len(self.prefix) + 32
            or not wrapped_key.startswith(self.prefix)
        ):
            raise RuntimeError("fake protector rejected wrapped key")
        return wrapped_key[len(self.prefix) :]


class LeakingProtector:
    def wrap_key(self, _key: bytes) -> bytes:
        raise RuntimeError(SENTINEL)

    def unwrap_key(self, _wrapped_key: bytes) -> bytes:
        raise RuntimeError(SENTINEL)


class WrongReturnProtector:
    def wrap_key(self, key: bytes) -> bytes:
        return bytearray(key)  # type: ignore[return-value]

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        return bytearray(wrapped_key)  # type: ignore[return-value]


def _bindings(card: dict[str, object]) -> dict[str, object]:
    return {
        "expires_at_utc": EXPIRES_AT_UTC,
        "identity_sha256": card["identity_sha256"],
        "intent_record_sha256": INTENT_RECORD_SHA256,
        "query_policy_sha256": QUERY_POLICY_SHA256,
        "record_sha256": card["record_sha256"],
        "run_id": RUN_ID,
        "semantic_status": SEMANTIC_STATUS,
    }


def _encrypt(
    card: dict[str, object] | None = None,
    *,
    protector: object | None = None,
) -> EncryptedTenderPlanCardV1:
    selected = _card() if card is None else card
    arguments = _bindings(selected)
    arguments["protector"] = FakeProtector() if protector is None else protector
    return encrypt_tenderplan_card(selected, **arguments)  # type: ignore[arg-type]


def _decrypt(
    envelope: EncryptedTenderPlanCardV1,
    *,
    protector: object | None = None,
    **changes: object,
) -> dict[str, object]:
    arguments = _bindings(_card())
    arguments.update(changes)
    arguments["protector"] = FakeProtector() if protector is None else protector
    return decrypt_tenderplan_card(envelope, **arguments)  # type: ignore[arg-type]


def _aad(mapping: dict[str, object]) -> bytes:
    return json.dumps(
        {
            "expires_at_utc": mapping["expires_at_utc"],
            "identity_sha256": mapping["identity_sha256"],
            "intent_record_sha256": mapping["intent_record_sha256"],
            "protocol": "tenderplan-read-only-card-v1",
            "query_policy_sha256": mapping["query_policy_sha256"],
            "record_sha256": mapping["record_sha256"],
            "run_id": mapping["run_id"],
            "semantic_status": mapping["semantic_status"],
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _reseal(mapping: dict[str, object]) -> EncryptedTenderPlanCardV1:
    material = dict(mapping)
    material.pop("envelope_sha256", None)
    material["envelope_sha256"] = _sha(
        json.dumps(
            material,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    )
    return EncryptedTenderPlanCardV1.from_mapping(material)


def _mutate_b64(value: object, *, offset: int) -> str:
    assert type(value) is str
    decoded = bytearray(base64.b64decode(value, validate=True))
    decoded[offset] ^= 1
    return base64.b64encode(decoded).decode("ascii")


def test_fake_protector_round_trip_and_exact_sealed_material() -> None:
    card = _card()
    envelope = _encrypt(card)
    material = encrypted_card_material(envelope)

    assert _decrypt(envelope) == card
    assert EncryptedTenderPlanCardV1.from_mapping(material) == envelope
    assert set(material) == {
        "aad_sha256",
        "automatic_schedule_eligible",
        "ciphertext_b64",
        "envelope_sha256",
        "expires_at_utc",
        "identity_sha256",
        "intent_record_sha256",
        "live_release_eligible",
        "nonce_b64",
        "protocol",
        "query_policy_sha256",
        "record_sha256",
        "run_id",
        "semantic_status",
        "wrapped_key_b64",
    }
    assert set(encrypted_card_material(envelope, include_envelope_sha256=False)) == (
        set(material) - {"envelope_sha256"}
    )
    assert len(base64.b64decode(envelope.nonce_b64, validate=True)) == 12
    assert len(base64.b64decode(envelope.ciphertext_b64, validate=True)) == (
        len(_canonical(card)) + 16
    )
    assert envelope.automatic_schedule_eligible is False
    assert envelope.live_release_eligible is False


def test_fresh_data_key_and_nonce_make_each_envelope_distinct() -> None:
    first = _encrypt()
    second = _encrypt()

    assert first.nonce_b64 != second.nonce_b64
    assert first.ciphertext_b64 != second.ciphertext_b64
    assert first.wrapped_key_b64 != second.wrapped_key_b64
    assert first.envelope_sha256 != second.envelope_sha256
    assert _decrypt(first) == _decrypt(second)


def test_repr_and_errors_never_expose_plaintext_ciphertext_or_protector_error() -> None:
    envelope = _encrypt()
    rendered = repr(envelope)
    assert SENTINEL not in rendered
    assert envelope.ciphertext_b64 not in rendered
    assert envelope.wrapped_key_b64 not in rendered
    assert "content=<encrypted-and-redacted>" in rendered
    assert "live_release_eligible=False" in rendered

    with pytest.raises(TenderPlanReadOnlyCryptoError) as raised:
        _encrypt(protector=LeakingProtector())
    assert SENTINEL not in str(raised.value)
    assert SENTINEL not in repr(raised.value)

    with pytest.raises(TenderPlanReadOnlyCryptoError) as raised:
        _decrypt(envelope, protector=LeakingProtector())
    assert SENTINEL not in str(raised.value)
    assert SENTINEL not in repr(raised.value)


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("run_id", "tenderplan-read-run-evil"),
        ("intent_record_sha256", "a" * 64),
        ("query_policy_sha256", "b" * 64),
        ("identity_sha256", "c" * 64),
        ("record_sha256", "d" * 64),
        ("semantic_status", "OTHER_UNVERIFIED_STATUS"),
        ("expires_at_utc", "2026-09-01T00:00:00.000000Z"),
    ],
)
def test_every_aad_binding_tamper_fails_even_when_hash_and_seal_are_recomputed(
    field: str,
    changed: str,
) -> None:
    mapping = encrypted_card_material(_encrypt())
    mapping[field] = changed
    mapping["aad_sha256"] = _sha(_aad(mapping))
    tampered = _reseal(mapping)

    with pytest.raises(TenderPlanReadOnlyCryptoError) as raised:
        _decrypt(
            tampered,
            **{
                field: changed,
            },
        )
    assert SENTINEL not in str(raised.value)


@pytest.mark.parametrize(
    ("field", "offset"),
    [
        ("nonce_b64", 0),
        ("ciphertext_b64", 0),
        ("ciphertext_b64", -1),
        ("wrapped_key_b64", -1),
    ],
)
def test_nonce_ciphertext_tag_and_wrapped_key_tamper_fail_closed(
    field: str,
    offset: int,
) -> None:
    mapping = encrypted_card_material(_encrypt())
    mapping[field] = _mutate_b64(mapping[field], offset=offset)
    tampered = _reseal(mapping)

    with pytest.raises(TenderPlanReadOnlyCryptoError) as raised:
        _decrypt(tampered)
    assert SENTINEL not in str(raised.value)


def test_aad_hash_envelope_seal_and_protocol_tamper_are_rejected_on_decode() -> None:
    original = encrypted_card_material(_encrypt())
    mutations = [
        {"aad_sha256": "f" * 64},
        {"envelope_sha256": "e" * 64},
        {"protocol": "tenderplan-read-only-card-v2"},
    ]
    for mutation in mutations:
        changed = {**original, **mutation}
        with pytest.raises(TenderPlanReadOnlyCryptoError):
            EncryptedTenderPlanCardV1.from_mapping(changed)


def test_caller_binding_mismatch_fails_before_decryption() -> None:
    envelope = _encrypt()
    mismatches = {
        "run_id": "different-run",
        "intent_record_sha256": "a" * 64,
        "query_policy_sha256": "b" * 64,
        "identity_sha256": "c" * 64,
        "record_sha256": "d" * 64,
        "semantic_status": "OTHER_STATUS",
        "expires_at_utc": "2027-01-01T00:00:00.000000Z",
    }
    for field, changed in mismatches.items():
        with pytest.raises(TenderPlanReadOnlyCryptoError):
            _decrypt(envelope, **{field: changed})


def test_plaintext_must_be_canonical_even_with_a_valid_gcm_tag() -> None:
    envelope = _encrypt()
    mapping = encrypted_card_material(envelope)
    wrapped = base64.b64decode(envelope.wrapped_key_b64, validate=True)
    key = FakeProtector().unwrap_key(wrapped)
    nonce = base64.b64decode(envelope.nonce_b64, validate=True)
    noncanonical = json.dumps(_card(), ensure_ascii=False, indent=2).encode("utf-8")
    mapping["ciphertext_b64"] = base64.b64encode(
        AESGCM(key).encrypt(nonce, noncanonical, _aad(mapping))
    ).decode("ascii")
    tampered = _reseal(mapping)

    with pytest.raises(TenderPlanReadOnlyCryptoError):
        _decrypt(tampered)


def test_plaintext_identity_and_record_seals_are_rechecked_after_valid_gcm() -> None:
    envelope = _encrypt()
    mapping = encrypted_card_material(envelope)
    wrapped = base64.b64decode(envelope.wrapped_key_b64, validate=True)
    key = FakeProtector().unwrap_key(wrapped)
    nonce = base64.b64decode(envelope.nonce_b64, validate=True)
    forged = _card()
    forged["title"] = "forged-title"
    mapping["ciphertext_b64"] = base64.b64encode(
        AESGCM(key).encrypt(nonce, _canonical(forged), _aad(mapping))
    ).decode("ascii")
    tampered = _reseal(mapping)

    with pytest.raises(TenderPlanReadOnlyCryptoError):
        _decrypt(tampered)


def test_encrypt_rejects_mismatched_plaintext_bindings() -> None:
    original = _card()
    mutations = [
        {"identity_sha256": "a" * 64},
        {"record_sha256": "b" * 64},
        {"semantic_status": "OTHER_STATUS"},
        {"tender_id": "f" * 24},
        {"revision": "0"},
    ]
    for mutation in mutations:
        changed = {**original, **mutation}
        arguments = _bindings(changed)
        with pytest.raises(TenderPlanReadOnlyCryptoError):
            encrypt_tenderplan_card(
                changed,
                protector=FakeProtector(),
                **arguments,  # type: ignore[arg-type]
            )


@pytest.mark.parametrize(
    "bad_card",
    [
        {"value": 1.0},
        {"value": b"bytes"},
        {"value": ("tuple",)},
        {"value": 2**63},
        {1: "non-string-key"},
    ],
)
def test_plaintext_json_types_are_exact_and_bounded(
    bad_card: dict[object, object],
) -> None:
    card = _card()
    card["extra"] = bad_card
    card_without_seal = dict(card)
    card_without_seal.pop("record_sha256")
    card["record_sha256"] = (
        _sha(_canonical(card_without_seal))
        if not any(type(value) in {bytes, tuple} for value in bad_card.values())
        else "f" * 64
    )
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        encrypt_tenderplan_card(
            card,
            protector=FakeProtector(),
            **_bindings(card),  # type: ignore[arg-type]
        )


def test_bool_and_int_are_not_interchangeable_in_envelope_or_options() -> None:
    envelope = _encrypt()
    for field in ("automatic_schedule_eligible", "live_release_eligible"):
        changed = encrypted_card_material(envelope) | {field: 0}
        material = dict(changed)
        material.pop("envelope_sha256")
        changed["envelope_sha256"] = _sha(
            json.dumps(
                material,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        )
        with pytest.raises(TenderPlanReadOnlyCryptoError):
            EncryptedTenderPlanCardV1.from_mapping(changed)

    with pytest.raises(TenderPlanReadOnlyCryptoError):
        encrypted_card_material(envelope, include_envelope_sha256=1)  # type: ignore[arg-type]
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        encrypt_tenderplan_card(
            _card(),
            **(_bindings(_card()) | {"run_id": True}),  # type: ignore[arg-type]
            protector=FakeProtector(),
        )


def test_base64_and_exact_wire_key_set_are_fail_closed() -> None:
    mapping = encrypted_card_material(_encrypt())
    changed = dict(mapping)
    changed["nonce_b64"] = "not/base64==="
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        EncryptedTenderPlanCardV1.from_mapping(changed)

    for changed in (
        {key: value for key, value in mapping.items() if key != "run_id"},
        {**mapping, "unexpected": False},
    ):
        with pytest.raises(TenderPlanReadOnlyCryptoError):
            EncryptedTenderPlanCardV1.from_mapping(changed)


def test_injected_protector_requires_exact_bytes_and_exact_protocol_methods() -> None:
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        _encrypt(protector=object())
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        _encrypt(protector=WrongReturnProtector())

    envelope = _encrypt()
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        _decrypt(envelope, protector=WrongReturnProtector())


def test_forged_dataclass_replace_is_revalidated_by_constructor() -> None:
    envelope = _encrypt()
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        replace(envelope, ciphertext_b64=_mutate_b64(envelope.ciphertext_b64, offset=0))
    with pytest.raises(TenderPlanReadOnlyCryptoError):
        replace(envelope, automatic_schedule_eligible=0)  # type: ignore[arg-type]


@pytest.mark.skipif(os.name != "nt", reason="production protector is Windows-only")
def test_windows_dpapi_production_default_round_trip() -> None:
    protector = WindowsDpapiCardKeyProtector()
    key = os.urandom(32)
    wrapped = protector.wrap_key(key)
    assert wrapped != key
    assert protector.unwrap_key(wrapped) == key

    card = _card()
    envelope = encrypt_tenderplan_card(card, **_bindings(card))  # type: ignore[arg-type]
    assert (
        decrypt_tenderplan_card(
            envelope,
            **_bindings(card),  # type: ignore[arg-type]
        )
        == card
    )
