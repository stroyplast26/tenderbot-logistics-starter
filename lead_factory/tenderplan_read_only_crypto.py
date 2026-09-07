"""Worker-side encryption for bounded TenderPlan review cards.

The module encrypts one already-minimized card with a fresh AES-256-GCM key.
Only the encrypted envelope is intended to cross the contained worker boundary.
The data key is wrapped with Windows DPAPI in the production path; tests may
inject an explicit protector object.  There is no environment-controlled or
non-Windows fallback.

This is local, manual-only custody.  It is not a scheduler, credential store,
external rollback authority, non-exportable HSM, or live-release boundary.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import os
import re
from typing import Final, Protocol, Self, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


TENDERPLAN_READ_ONLY_CARD_PROTOCOL: Final = "tenderplan-read-only-card-v1"

_DPAPI_DESCRIPTION = "TenderBot TenderPlan read-only card key v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x00000001
_AES_KEY_BYTES = 32
_GCM_NONCE_BYTES = 12
_GCM_TAG_BYTES = 16
_MAX_CARD_PLAINTEXT_BYTES = 16_384
_MAX_WRAPPED_KEY_BYTES = 8_192
_MAX_JSON_DEPTH = 16
_MAX_JSON_ITEMS = 1_024
_MAX_JSON_STRING_CHARS = 8_192
_MAX_JSON_KEY_CHARS = 256

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,159}$")
_SEMANTIC_STATUS = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z$")


class TenderPlanReadOnlyCryptoError(RuntimeError):
    """Sanitized failure that never includes card or key material."""

    code = "tenderplan_read_only_crypto_failed"

    def __init__(self) -> None:
        super().__init__(self.code)


@runtime_checkable
class TenderPlanCardKeyProtector(Protocol):
    """Explicit key-wrapping seam used by the contained worker.

    Production callers omit the protector argument and therefore always use
    :class:`WindowsDpapiCardKeyProtector`.  The seam exists for deterministic
    unit isolation; it is never selected by configuration or environment.
    """

    def wrap_key(self, key: bytes) -> bytes:
        """Wrap one exact 32-byte AES key."""

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        """Return the exact 32-byte AES key represented by ``wrapped_key``."""


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _zero_mutable(value: bytearray | ctypes.Array[ctypes.c_ubyte]) -> None:
    """Best-effort clearing for mutable copies owned by this module."""

    try:
        if isinstance(value, bytearray):
            value[:] = b"\x00" * len(value)
        elif len(value):
            ctypes.memset(ctypes.addressof(value), 0, len(value))
    except (BufferError, OSError, TypeError, ValueError):
        # Clearing is defense in depth.  It must not replace the original
        # cryptographic result with an exception that might expose context.
        return


def _windows_libraries() -> tuple[object, object]:
    if os.name != "nt":
        raise TenderPlanReadOnlyCryptoError
    try:
        crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DataBlob),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree.restype = wintypes.HLOCAL
    except (AttributeError, OSError, TypeError):
        raise TenderPlanReadOnlyCryptoError from None
    return crypt32, kernel32


def _input_blob(value: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_ubyte]]:
    if type(value) is not bytes or not value:
        raise TenderPlanReadOnlyCryptoError
    try:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    except (MemoryError, OverflowError, TypeError, ValueError):
        raise TenderPlanReadOnlyCryptoError from None
    return _DataBlob(len(value), buffer), buffer


def _copy_and_free_output(
    blob: _DataBlob,
    *,
    kernel32: object,
    maximum: int,
) -> bytes:
    pointer = ctypes.cast(blob.pbData, ctypes.c_void_p)
    size = int(blob.cbData)
    try:
        if not pointer.value or not 1 <= size <= maximum:
            raise TenderPlanReadOnlyCryptoError
        return ctypes.string_at(pointer.value, size)
    finally:
        if pointer.value:
            try:
                if size > 0:
                    ctypes.memset(pointer.value, 0, size)
            finally:
                kernel32.LocalFree(pointer)
                blob.cbData = 0
                blob.pbData = ctypes.POINTER(ctypes.c_ubyte)()


def _free_output_if_present(blob: _DataBlob, *, kernel32: object) -> None:
    pointer = ctypes.cast(blob.pbData, ctypes.c_void_p)
    size = int(blob.cbData)
    if not pointer.value:
        return
    try:
        if size > 0:
            ctypes.memset(pointer.value, 0, size)
    finally:
        kernel32.LocalFree(pointer)
        blob.cbData = 0
        blob.pbData = ctypes.POINTER(ctypes.c_ubyte)()


class WindowsDpapiCardKeyProtector:
    """Current-user Windows DPAPI key wrapping with UI strictly forbidden."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "WindowsDpapiCardKeyProtector(scope='current-user', ui=False)"

    def wrap_key(self, key: bytes) -> bytes:
        if type(key) is not bytes or len(key) != _AES_KEY_BYTES:
            raise TenderPlanReadOnlyCryptoError
        crypt32, kernel32 = _windows_libraries()
        input_blob, input_buffer = _input_blob(key)
        output_blob = _DataBlob()
        try:
            succeeded = crypt32.CryptProtectData(
                ctypes.byref(input_blob),
                _DPAPI_DESCRIPTION,
                None,
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            if not succeeded:
                raise TenderPlanReadOnlyCryptoError
            return _copy_and_free_output(
                output_blob,
                kernel32=kernel32,
                maximum=_MAX_WRAPPED_KEY_BYTES,
            )
        except TenderPlanReadOnlyCryptoError:
            raise
        except Exception:
            raise TenderPlanReadOnlyCryptoError from None
        finally:
            _free_output_if_present(output_blob, kernel32=kernel32)
            _zero_mutable(input_buffer)

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        if (
            type(wrapped_key) is not bytes
            or not 1 <= len(wrapped_key) <= _MAX_WRAPPED_KEY_BYTES
        ):
            raise TenderPlanReadOnlyCryptoError
        crypt32, kernel32 = _windows_libraries()
        input_blob, input_buffer = _input_blob(wrapped_key)
        output_blob = _DataBlob()
        description = wintypes.LPWSTR()
        description_pointer = ctypes.c_void_p()
        try:
            succeeded = crypt32.CryptUnprotectData(
                ctypes.byref(input_blob),
                ctypes.byref(description),
                None,
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            description_pointer = ctypes.cast(description, ctypes.c_void_p)
            if not succeeded:
                raise TenderPlanReadOnlyCryptoError
            key = _copy_and_free_output(
                output_blob,
                kernel32=kernel32,
                maximum=_AES_KEY_BYTES,
            )
            if description.value != _DPAPI_DESCRIPTION or len(key) != _AES_KEY_BYTES:
                raise TenderPlanReadOnlyCryptoError
            return key
        except TenderPlanReadOnlyCryptoError:
            raise
        except Exception:
            raise TenderPlanReadOnlyCryptoError from None
        finally:
            _free_output_if_present(output_blob, kernel32=kernel32)
            _zero_mutable(input_buffer)
            if description_pointer.value:
                kernel32.LocalFree(description_pointer)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validated_digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise TenderPlanReadOnlyCryptoError
    return value


def _validated_run_id(value: object) -> str:
    if type(value) is not str or _SAFE_RUN_ID.fullmatch(value) is None:
        raise TenderPlanReadOnlyCryptoError
    return value


def _validated_semantic_status(value: object) -> str:
    if type(value) is not str or _SEMANTIC_STATUS.fullmatch(value) is None:
        raise TenderPlanReadOnlyCryptoError
    return value


def _validated_expires_at(value: object) -> str:
    if type(value) is not str or _UTC_Z.fullmatch(value) is None:
        raise TenderPlanReadOnlyCryptoError
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise TenderPlanReadOnlyCryptoError from None
    return value


def _json_copy(value: object, *, depth: int, budget: list[int]) -> object:
    budget[0] += 1
    if depth > _MAX_JSON_DEPTH or budget[0] > _MAX_JSON_ITEMS:
        raise TenderPlanReadOnlyCryptoError
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise TenderPlanReadOnlyCryptoError
        return value
    if type(value) is str:
        if len(value) > _MAX_JSON_STRING_CHARS:
            raise TenderPlanReadOnlyCryptoError
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise TenderPlanReadOnlyCryptoError from None
        return value
    if type(value) is list:
        return [_json_copy(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        try:
            items = value.items()
            for key, item in items:
                if (
                    type(key) is not str
                    or not key
                    or len(key) > _MAX_JSON_KEY_CHARS
                    or key in result
                ):
                    raise TenderPlanReadOnlyCryptoError
                try:
                    key.encode("utf-8", "strict")
                except UnicodeEncodeError:
                    raise TenderPlanReadOnlyCryptoError from None
                result[key] = _json_copy(
                    item,
                    depth=depth + 1,
                    budget=budget,
                )
        except TenderPlanReadOnlyCryptoError:
            raise
        except Exception:
            raise TenderPlanReadOnlyCryptoError from None
        return result
    raise TenderPlanReadOnlyCryptoError


def _canonical_mapping_bytes(
    value: Mapping[str, object],
) -> tuple[dict[str, object], bytes]:
    if not isinstance(value, Mapping):
        raise TenderPlanReadOnlyCryptoError
    normalized = _json_copy(value, depth=0, budget=[0])
    if type(normalized) is not dict or not normalized:
        raise TenderPlanReadOnlyCryptoError
    try:
        rendered = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (MemoryError, TypeError, UnicodeEncodeError, ValueError):
        raise TenderPlanReadOnlyCryptoError from None
    if not 1 <= len(rendered) <= _MAX_CARD_PLAINTEXT_BYTES:
        raise TenderPlanReadOnlyCryptoError
    return normalized, rendered


def _strict_canonical_plaintext(value: bytes) -> tuple[dict[str, object], bytes]:
    if type(value) is not bytes or not 1 <= len(value) <= _MAX_CARD_PLAINTEXT_BYTES:
        raise TenderPlanReadOnlyCryptoError

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TenderPlanReadOnlyCryptoError from None
    if type(parsed) is not dict:
        raise TenderPlanReadOnlyCryptoError
    normalized, canonical = _canonical_mapping_bytes(parsed)
    if not hmac.compare_digest(canonical, value):
        raise TenderPlanReadOnlyCryptoError
    return normalized, canonical


def _card_bindings(
    card: Mapping[str, object],
    *,
    identity_sha256: str,
    record_sha256: str,
    semantic_status: str,
) -> None:
    if (
        card.get("identity_sha256") != identity_sha256
        or type(card.get("identity_sha256")) is not str
        or card.get("record_sha256") != record_sha256
        or type(card.get("record_sha256")) is not str
        or card.get("semantic_status") != semantic_status
        or type(card.get("semantic_status")) is not str
        or "tender_id" not in card
        or "revision" not in card
    ):
        raise TenderPlanReadOnlyCryptoError

    identity_material = {
        "revision": card["revision"],
        "tender_id": card["tender_id"],
    }
    _, identity_bytes = _canonical_mapping_bytes(identity_material)
    record_material = dict(card)
    record_material.pop("record_sha256", None)
    _, record_bytes = _canonical_mapping_bytes(record_material)
    if not hmac.compare_digest(
        _sha256(identity_bytes), identity_sha256
    ) or not hmac.compare_digest(_sha256(record_bytes), record_sha256):
        raise TenderPlanReadOnlyCryptoError


def _aad_material(
    *,
    run_id: str,
    intent_record_sha256: str,
    query_policy_sha256: str,
    identity_sha256: str,
    record_sha256: str,
    semantic_status: str,
    expires_at_utc: str,
) -> dict[str, object]:
    return {
        "expires_at_utc": expires_at_utc,
        "identity_sha256": identity_sha256,
        "intent_record_sha256": intent_record_sha256,
        "protocol": TENDERPLAN_READ_ONLY_CARD_PROTOCOL,
        "query_policy_sha256": query_policy_sha256,
        "record_sha256": record_sha256,
        "run_id": run_id,
        "semantic_status": semantic_status,
    }


def _canonical_control_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, UnicodeEncodeError, ValueError):
        raise TenderPlanReadOnlyCryptoError from None


def _b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii", "strict")


def _b64_decode(value: object, *, minimum: int, maximum: int) -> bytes:
    if type(value) is not str or not value:
        raise TenderPlanReadOnlyCryptoError
    try:
        decoded = base64.b64decode(value.encode("ascii", "strict"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise TenderPlanReadOnlyCryptoError from None
    if not minimum <= len(decoded) <= maximum or not hmac.compare_digest(
        _b64_encode(decoded), value
    ):
        raise TenderPlanReadOnlyCryptoError
    return decoded


def _envelope_material_values(
    *,
    identity_sha256: str,
    record_sha256: str,
    run_id: str,
    intent_record_sha256: str,
    query_policy_sha256: str,
    semantic_status: str,
    expires_at_utc: str,
    nonce_b64: str,
    ciphertext_b64: str,
    wrapped_key_b64: str,
    aad_sha256: str,
) -> dict[str, object]:
    return {
        "aad_sha256": aad_sha256,
        "automatic_schedule_eligible": False,
        "ciphertext_b64": ciphertext_b64,
        "expires_at_utc": expires_at_utc,
        "identity_sha256": identity_sha256,
        "intent_record_sha256": intent_record_sha256,
        "live_release_eligible": False,
        "nonce_b64": nonce_b64,
        "protocol": TENDERPLAN_READ_ONLY_CARD_PROTOCOL,
        "query_policy_sha256": query_policy_sha256,
        "record_sha256": record_sha256,
        "run_id": run_id,
        "semantic_status": semantic_status,
        "wrapped_key_b64": wrapped_key_b64,
    }


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedTenderPlanCardV1:
    """Sealed encrypted card envelope whose representation is digest-only."""

    identity_sha256: str
    record_sha256: str
    run_id: str
    intent_record_sha256: str
    query_policy_sha256: str
    semantic_status: str
    expires_at_utc: str
    nonce_b64: str
    ciphertext_b64: str
    wrapped_key_b64: str
    aad_sha256: str
    envelope_sha256: str
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        _validate_envelope(self)

    def __repr__(self) -> str:
        return (
            "EncryptedTenderPlanCardV1(content=<encrypted-and-redacted>, "
            f"envelope_sha256={self.envelope_sha256!r}, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object]) -> Self:
        """Decode the exact canonical wire fields without decrypting content."""

        expected = {
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
        try:
            if not isinstance(mapping, Mapping) or set(mapping) != expected:
                raise TenderPlanReadOnlyCryptoError
            if mapping.get("protocol") != TENDERPLAN_READ_ONLY_CARD_PROTOCOL:
                raise TenderPlanReadOnlyCryptoError
            return cls(
                identity_sha256=mapping["identity_sha256"],  # type: ignore[arg-type]
                record_sha256=mapping["record_sha256"],  # type: ignore[arg-type]
                run_id=mapping["run_id"],  # type: ignore[arg-type]
                intent_record_sha256=mapping["intent_record_sha256"],  # type: ignore[arg-type]
                query_policy_sha256=mapping["query_policy_sha256"],  # type: ignore[arg-type]
                semantic_status=mapping["semantic_status"],  # type: ignore[arg-type]
                expires_at_utc=mapping["expires_at_utc"],  # type: ignore[arg-type]
                nonce_b64=mapping["nonce_b64"],  # type: ignore[arg-type]
                ciphertext_b64=mapping["ciphertext_b64"],  # type: ignore[arg-type]
                wrapped_key_b64=mapping["wrapped_key_b64"],  # type: ignore[arg-type]
                aad_sha256=mapping["aad_sha256"],  # type: ignore[arg-type]
                envelope_sha256=mapping["envelope_sha256"],  # type: ignore[arg-type]
                automatic_schedule_eligible=mapping["automatic_schedule_eligible"],  # type: ignore[arg-type]
                live_release_eligible=mapping["live_release_eligible"],  # type: ignore[arg-type]
            )
        except TenderPlanReadOnlyCryptoError:
            raise
        except Exception:
            raise TenderPlanReadOnlyCryptoError from None


def encrypted_card_material(
    envelope: EncryptedTenderPlanCardV1,
    *,
    include_envelope_sha256: bool = True,
) -> dict[str, object]:
    """Return the exact canonical-serializable envelope material."""

    if (
        type(envelope) is not EncryptedTenderPlanCardV1
        or type(include_envelope_sha256) is not bool
    ):
        raise TenderPlanReadOnlyCryptoError
    _validate_envelope(envelope)
    material = _envelope_material_values(
        identity_sha256=envelope.identity_sha256,
        record_sha256=envelope.record_sha256,
        run_id=envelope.run_id,
        intent_record_sha256=envelope.intent_record_sha256,
        query_policy_sha256=envelope.query_policy_sha256,
        semantic_status=envelope.semantic_status,
        expires_at_utc=envelope.expires_at_utc,
        nonce_b64=envelope.nonce_b64,
        ciphertext_b64=envelope.ciphertext_b64,
        wrapped_key_b64=envelope.wrapped_key_b64,
        aad_sha256=envelope.aad_sha256,
    )
    if include_envelope_sha256:
        material["envelope_sha256"] = envelope.envelope_sha256
    return material


def _validate_envelope(envelope: EncryptedTenderPlanCardV1) -> None:
    try:
        identity_sha256 = _validated_digest(envelope.identity_sha256)
        record_sha256 = _validated_digest(envelope.record_sha256)
        run_id = _validated_run_id(envelope.run_id)
        intent_record_sha256 = _validated_digest(envelope.intent_record_sha256)
        query_policy_sha256 = _validated_digest(envelope.query_policy_sha256)
        semantic_status = _validated_semantic_status(envelope.semantic_status)
        expires_at_utc = _validated_expires_at(envelope.expires_at_utc)
        _b64_decode(
            envelope.nonce_b64,
            minimum=_GCM_NONCE_BYTES,
            maximum=_GCM_NONCE_BYTES,
        )
        _b64_decode(
            envelope.ciphertext_b64,
            minimum=_GCM_TAG_BYTES + 1,
            maximum=_MAX_CARD_PLAINTEXT_BYTES + _GCM_TAG_BYTES,
        )
        _b64_decode(
            envelope.wrapped_key_b64,
            minimum=1,
            maximum=_MAX_WRAPPED_KEY_BYTES,
        )
        aad_sha256 = _validated_digest(envelope.aad_sha256)
        envelope_sha256 = _validated_digest(envelope.envelope_sha256)
        if (
            type(envelope.automatic_schedule_eligible) is not bool
            or envelope.automatic_schedule_eligible is not False
            or type(envelope.live_release_eligible) is not bool
            or envelope.live_release_eligible is not False
        ):
            raise TenderPlanReadOnlyCryptoError
        aad = _canonical_control_bytes(
            _aad_material(
                run_id=run_id,
                intent_record_sha256=intent_record_sha256,
                query_policy_sha256=query_policy_sha256,
                identity_sha256=identity_sha256,
                record_sha256=record_sha256,
                semantic_status=semantic_status,
                expires_at_utc=expires_at_utc,
            )
        )
        if not hmac.compare_digest(_sha256(aad), aad_sha256):
            raise TenderPlanReadOnlyCryptoError
        material = _envelope_material_values(
            identity_sha256=identity_sha256,
            record_sha256=record_sha256,
            run_id=run_id,
            intent_record_sha256=intent_record_sha256,
            query_policy_sha256=query_policy_sha256,
            semantic_status=semantic_status,
            expires_at_utc=expires_at_utc,
            nonce_b64=envelope.nonce_b64,
            ciphertext_b64=envelope.ciphertext_b64,
            wrapped_key_b64=envelope.wrapped_key_b64,
            aad_sha256=aad_sha256,
        )
        if not hmac.compare_digest(
            _sha256(_canonical_control_bytes(material)),
            envelope_sha256,
        ):
            raise TenderPlanReadOnlyCryptoError
    except TenderPlanReadOnlyCryptoError:
        raise
    except Exception:
        raise TenderPlanReadOnlyCryptoError from None


def _protector(value: TenderPlanCardKeyProtector | None) -> TenderPlanCardKeyProtector:
    if value is None:
        return WindowsDpapiCardKeyProtector()
    if not isinstance(value, TenderPlanCardKeyProtector):
        raise TenderPlanReadOnlyCryptoError
    return value


def encrypt_tenderplan_card(
    card: Mapping[str, object],
    *,
    run_id: str,
    intent_record_sha256: str,
    query_policy_sha256: str,
    identity_sha256: str,
    record_sha256: str,
    semantic_status: str,
    expires_at_utc: str,
    protector: TenderPlanCardKeyProtector | None = None,
) -> EncryptedTenderPlanCardV1:
    """Encrypt one exact canonical card with a fresh per-card data key."""

    key_buffer = bytearray()
    try:
        run_id = _validated_run_id(run_id)
        intent_record_sha256 = _validated_digest(intent_record_sha256)
        query_policy_sha256 = _validated_digest(query_policy_sha256)
        identity_sha256 = _validated_digest(identity_sha256)
        record_sha256 = _validated_digest(record_sha256)
        semantic_status = _validated_semantic_status(semantic_status)
        expires_at_utc = _validated_expires_at(expires_at_utc)
        normalized, plaintext = _canonical_mapping_bytes(card)
        _card_bindings(
            normalized,
            identity_sha256=identity_sha256,
            record_sha256=record_sha256,
            semantic_status=semantic_status,
        )
        aad = _canonical_control_bytes(
            _aad_material(
                run_id=run_id,
                intent_record_sha256=intent_record_sha256,
                query_policy_sha256=query_policy_sha256,
                identity_sha256=identity_sha256,
                record_sha256=record_sha256,
                semantic_status=semantic_status,
                expires_at_utc=expires_at_utc,
            )
        )
        key_buffer = bytearray(os.urandom(_AES_KEY_BYTES))
        nonce = os.urandom(_GCM_NONCE_BYTES)
        selected_protector = _protector(protector)
        key = bytes(key_buffer)
        wrapped_key = selected_protector.wrap_key(key)
        if (
            type(wrapped_key) is not bytes
            or not 1 <= len(wrapped_key) <= _MAX_WRAPPED_KEY_BYTES
        ):
            raise TenderPlanReadOnlyCryptoError
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        nonce_b64 = _b64_encode(nonce)
        ciphertext_b64 = _b64_encode(ciphertext)
        wrapped_key_b64 = _b64_encode(wrapped_key)
        aad_sha256 = _sha256(aad)
        material = _envelope_material_values(
            identity_sha256=identity_sha256,
            record_sha256=record_sha256,
            run_id=run_id,
            intent_record_sha256=intent_record_sha256,
            query_policy_sha256=query_policy_sha256,
            semantic_status=semantic_status,
            expires_at_utc=expires_at_utc,
            nonce_b64=nonce_b64,
            ciphertext_b64=ciphertext_b64,
            wrapped_key_b64=wrapped_key_b64,
            aad_sha256=aad_sha256,
        )
        return EncryptedTenderPlanCardV1(
            identity_sha256=identity_sha256,
            record_sha256=record_sha256,
            run_id=run_id,
            intent_record_sha256=intent_record_sha256,
            query_policy_sha256=query_policy_sha256,
            semantic_status=semantic_status,
            expires_at_utc=expires_at_utc,
            nonce_b64=nonce_b64,
            ciphertext_b64=ciphertext_b64,
            wrapped_key_b64=wrapped_key_b64,
            aad_sha256=aad_sha256,
            envelope_sha256=_sha256(_canonical_control_bytes(material)),
        )
    except TenderPlanReadOnlyCryptoError:
        raise
    except Exception:
        raise TenderPlanReadOnlyCryptoError from None
    finally:
        _zero_mutable(key_buffer)


def decrypt_tenderplan_card(
    envelope: EncryptedTenderPlanCardV1,
    *,
    run_id: str,
    intent_record_sha256: str,
    query_policy_sha256: str,
    identity_sha256: str,
    record_sha256: str,
    semantic_status: str,
    expires_at_utc: str,
    protector: TenderPlanCardKeyProtector | None = None,
) -> dict[str, object]:
    """Decrypt after independently rechecking every caller-provided binding."""

    key_buffer = bytearray()
    plaintext_buffer = bytearray()
    try:
        if type(envelope) is not EncryptedTenderPlanCardV1:
            raise TenderPlanReadOnlyCryptoError
        _validate_envelope(envelope)
        expected = (
            _validated_run_id(run_id),
            _validated_digest(intent_record_sha256),
            _validated_digest(query_policy_sha256),
            _validated_digest(identity_sha256),
            _validated_digest(record_sha256),
            _validated_semantic_status(semantic_status),
            _validated_expires_at(expires_at_utc),
        )
        observed = (
            envelope.run_id,
            envelope.intent_record_sha256,
            envelope.query_policy_sha256,
            envelope.identity_sha256,
            envelope.record_sha256,
            envelope.semantic_status,
            envelope.expires_at_utc,
        )
        if any(
            not hmac.compare_digest(left, right)
            for left, right in zip(expected, observed, strict=True)
        ):
            raise TenderPlanReadOnlyCryptoError
        aad = _canonical_control_bytes(
            _aad_material(
                run_id=envelope.run_id,
                intent_record_sha256=envelope.intent_record_sha256,
                query_policy_sha256=envelope.query_policy_sha256,
                identity_sha256=envelope.identity_sha256,
                record_sha256=envelope.record_sha256,
                semantic_status=envelope.semantic_status,
                expires_at_utc=envelope.expires_at_utc,
            )
        )
        if not hmac.compare_digest(_sha256(aad), envelope.aad_sha256):
            raise TenderPlanReadOnlyCryptoError
        nonce = _b64_decode(
            envelope.nonce_b64,
            minimum=_GCM_NONCE_BYTES,
            maximum=_GCM_NONCE_BYTES,
        )
        ciphertext = _b64_decode(
            envelope.ciphertext_b64,
            minimum=_GCM_TAG_BYTES + 1,
            maximum=_MAX_CARD_PLAINTEXT_BYTES + _GCM_TAG_BYTES,
        )
        wrapped_key = _b64_decode(
            envelope.wrapped_key_b64,
            minimum=1,
            maximum=_MAX_WRAPPED_KEY_BYTES,
        )
        unwrapped = _protector(protector).unwrap_key(wrapped_key)
        if type(unwrapped) is not bytes or len(unwrapped) != _AES_KEY_BYTES:
            raise TenderPlanReadOnlyCryptoError
        key_buffer = bytearray(unwrapped)
        plaintext = AESGCM(bytes(key_buffer)).decrypt(nonce, ciphertext, aad)
        plaintext_buffer = bytearray(plaintext)
        normalized, _canonical = _strict_canonical_plaintext(bytes(plaintext_buffer))
        _card_bindings(
            normalized,
            identity_sha256=envelope.identity_sha256,
            record_sha256=envelope.record_sha256,
            semantic_status=envelope.semantic_status,
        )
        return normalized
    except (InvalidTag, TenderPlanReadOnlyCryptoError):
        raise TenderPlanReadOnlyCryptoError from None
    except Exception:
        raise TenderPlanReadOnlyCryptoError from None
    finally:
        _zero_mutable(plaintext_buffer)
        _zero_mutable(key_buffer)


__all__ = [
    "EncryptedTenderPlanCardV1",
    "TenderPlanCardKeyProtector",
    "TenderPlanReadOnlyCryptoError",
    "WindowsDpapiCardKeyProtector",
    "decrypt_tenderplan_card",
    "encrypt_tenderplan_card",
    "encrypted_card_material",
]
