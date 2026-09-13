"""Prepare a bounded direct-profile body from independently pinned local bytes.

The caller must obtain ``expected_sha256`` from a prior review of the binding,
including its mapping evidence. A digest proves byte identity, not the truth of
the evidence or provider semantics. This module neither discovers mappings nor
authorizes a search. Unknown mappings must remain absent and fail validation.

Only the direct-profile subset of Tenderplan's published ``body.key`` schema is
accepted. No saved-profile lookup, query grammar conversion, HTTP, credentials,
operational database, or environment-controlled defaults are involved.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path

TENDERPLAN_PROFILE_BINDING_PROTOCOL = "tenderplan-direct-profile-binding/v1"
TENDERPLAN_PROFILE_BINDING_MAX_BYTES = 4096
_REPARSE_POINT = 0x400
_MAX_ARRAY_ITEMS = 16
# Bounded local support for the reviewed profile and placing-way catalog.
# These are admission limits, not claims about provider-wide schema maxima.
_MAX_PURCHASE_TYPES = 201
_MAX_PLACING_WAYS = 31
_MAX_TEXT_CHARS = 1024
_MAX_IDENTIFIER_CHARS = 128
_MAX_INTEGER = 2_147_483_647
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PROFILE_ID = re.compile(r"[0-9a-f]{24}")
_KLADR_ID = re.compile(r"[0-9]{13,20}")
_OBVIOUS_PERSONAL_WORD = re.compile(r"@|://|\d{7,}")
_BINDING_FIELDS = frozenset({
    "protocol", "profile_id", "profile_snapshot_sha256", "mapping_evidence", "criteria",
})
_EVIDENCE_FIELDS = frozenset({
    "region_sha256", "place_sha256", "purchase_types_sha256", "purchase_kind_sha256",
    "word_semantics_sha256", "exclusion_semantics_sha256",
})
_CRITERIA_FIELDS = frozenset({
    "regions", "deliveryPlaces", "garDeliveryPlaces", "words", "docWords", "types", "kind",
    "condition", "regionCondition", "inDocs",
})
_WORD_FIELDS = frozenset({"value", "excluded", "slop"})


class TenderPlanProfileRequestError(ValueError):
    """One sanitized rejection, without profile text, paths, or parser details."""

    code = "TENDERPLAN_PROFILE_REQUEST_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


def _require(condition: bool) -> None:
    if not condition:
        raise TenderPlanProfileRequestError


def _digest(value: object) -> str:
    _require(type(value) is str and _HEX64.fullmatch(value) is not None)
    _require(value != "0" * 64)
    return value


def _shape(value: object, fields: frozenset[str]) -> dict[str, object]:
    _require(type(value) is dict and value.keys() == fields)
    return value


def _unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise TenderPlanProfileRequestError


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")


def _text(value: object, maximum: int = _MAX_TEXT_CHARS) -> str:
    _require(type(value) is str and 0 < len(value) <= maximum and value == value.strip())
    _require(all(not unicodedata.category(char).startswith("C")
                 and unicodedata.category(char) not in {"Zl", "Zp"} for char in value))
    return value


def _integer_array(value: object, minimum: int, *, maximum: int = _MAX_ARRAY_ITEMS) -> None:
    _require(type(value) is list and 0 < len(value) <= maximum)
    _require(all(type(item) is int and minimum <= item <= _MAX_INTEGER for item in value))
    _require(len(set(value)) == len(value))


def _place_array(value: object, *, kladr: bool) -> None:
    _require(type(value) is list and len(value) <= _MAX_ARRAY_ITEMS)
    for item in value:
        _text(item, _MAX_IDENTIFIER_CHARS)
        if kladr:
            _require(_KLADR_ID.fullmatch(item) is not None)
    _require(len(set(value)) == len(value))


def _validated_material(binding_bytes: bytes, expected_sha256: str) -> tuple[bytes, str]:
    _require(type(binding_bytes) is bytes
             and 0 < len(binding_bytes) <= TENDERPLAN_PROFILE_BINDING_MAX_BYTES)
    digest = _digest(expected_sha256)
    _require(hmac.compare_digest(hashlib.sha256(binding_bytes).hexdigest(), digest))
    document = json.loads(
        binding_bytes.decode("ascii"), object_pairs_hook=_unique_pairs,
        parse_constant=_reject_constant,
    )
    binding = _shape(document, _BINDING_FIELDS)
    _require(_canonical(binding) == binding_bytes)
    _require(binding["protocol"] == TENDERPLAN_PROFILE_BINDING_PROTOCOL)
    profile_id = binding["profile_id"]
    _require(type(profile_id) is str and _PROFILE_ID.fullmatch(profile_id) is not None)
    _digest(binding["profile_snapshot_sha256"])
    criteria = binding["criteria"]
    _require(type(criteria) is dict)
    has_placing_ways = "placingWayNames" in criteria
    # Preserve old bindings while requiring reviewed mapping evidence whenever
    # the optional placing-way selection is supplied. Neither is synthesized.
    criteria_fields = _CRITERIA_FIELDS
    evidence_fields = _EVIDENCE_FIELDS
    if has_placing_ways:
        criteria_fields = criteria_fields | {"placingWayNames"}
        evidence_fields = evidence_fields | {"placing_ways_sha256"}
    evidence = _shape(binding["mapping_evidence"], evidence_fields)
    for value in evidence.values():
        _digest(value)

    criteria = _shape(criteria, criteria_fields)
    _integer_array(criteria["regions"], 0)
    _integer_array(criteria["types"], 0, maximum=_MAX_PURCHASE_TYPES)
    _integer_array(criteria["kind"], 1)
    if has_placing_ways:
        _integer_array(criteria["placingWayNames"], 0, maximum=_MAX_PLACING_WAYS)
    _place_array(criteria["deliveryPlaces"], kladr=True)
    _place_array(criteria["garDeliveryPlaces"], kladr=False)
    _require(bool(criteria["deliveryPlaces"] or criteria["garDeliveryPlaces"]))
    _require(criteria["condition"] == "or" and criteria["regionCondition"] == "or")
    _require(criteria["inDocs"] is False)
    words = _shape(criteria["words"], _WORD_FIELDS)
    doc_words = _shape(criteria["docWords"], _WORD_FIELDS)
    _text(words["value"])
    _text(words["excluded"])
    if doc_words["excluded"] is not None:
        _text(doc_words["excluded"])
        _require(words["excluded"] == doc_words["excluded"])
    # Preserve the legacy query privacy boundary only for search text. Provider
    # geography identifiers legitimately contain long numeric sequences.
    _require(not any(_OBVIOUS_PERSONAL_WORD.search(value) for value in (
        words["value"], words["excluded"], doc_words["excluded"],
    ) if value is not None))
    _require(words["slop"] is None and doc_words["slop"] is None)
    _require(doc_words["value"] is None)
    return _canonical({"key": criteria}), profile_id


@dataclass(frozen=True, repr=False, slots=True)
class PreparedTenderPlanSearch:
    """Immutable admitted bytes; construction always rechecks binding and pin."""

    body_bytes: bytes
    binding_bytes: bytes
    binding_sha256: str
    profile_id: str

    def __post_init__(self) -> None:
        try:
            body, profile_id = _validated_material(self.binding_bytes, self.binding_sha256)
            _require(type(self.body_bytes) is bytes and self.body_bytes == body)
            _require(type(self.profile_id) is str and self.profile_id == profile_id)
        except (AttributeError, OSError, TypeError, ValueError, RecursionError):
            raise TenderPlanProfileRequestError from None


def prepare_tenderplan_profile_request(
    binding_bytes: bytes, *, expected_sha256: str,
) -> PreparedTenderPlanSearch:
    """Check exact canonical binding bytes against a separately supplied review pin."""
    try:
        body, profile_id = _validated_material(binding_bytes, expected_sha256)
        return PreparedTenderPlanSearch(body, binding_bytes, expected_sha256, profile_id)
    except (AttributeError, OSError, TypeError, ValueError, RecursionError):
        raise TenderPlanProfileRequestError from None


def validate_prepared_tenderplan_search(value: object) -> PreparedTenderPlanSearch:
    """Recompute every field, including when an object was forged after construction."""
    try:
        _require(type(value) is PreparedTenderPlanSearch)
        checked = prepare_tenderplan_profile_request(
            value.binding_bytes, expected_sha256=value.binding_sha256,
        )
        _require(type(value.body_bytes) is bytes and value.body_bytes == checked.body_bytes)
        _require(type(value.profile_id) is str and value.profile_id == checked.profile_id)
        return checked
    except (AttributeError, OSError, TypeError, ValueError, RecursionError):
        raise TenderPlanProfileRequestError from None


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns, getattr(info, "st_file_attributes", 0),
    )


def _path_snapshot(path: Path) -> tuple[tuple[object, ...], ...]:
    result = []
    for item in (*reversed(path.parents), path):
        info = os.lstat(item)
        _require(not stat.S_ISLNK(info.st_mode))
        _require(not getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
        if item == path:
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            _require(0 < info.st_size <= TENDERPLAN_PROFILE_BINDING_MAX_BYTES)
            result.append((str(item), *_file_identity(info)))
        else:
            _require(stat.S_ISDIR(info.st_mode))
            result.append((str(item), info.st_dev, info.st_ino, info.st_mode,
                           getattr(info, "st_file_attributes", 0)))
    return tuple(result)


def _read_binding(binding_path: str | Path) -> bytes:
    _require(isinstance(binding_path, (str, Path)))
    path = Path(binding_path)
    _require(path.is_absolute() and ".." not in path.parts)
    _require(not path.drive.startswith("\\\\"))
    _require(all(":" not in part and not part.endswith((".", " "))
                 for part in path.parts[1:]))
    before = _path_snapshot(path)
    _require(os.path.normcase(str(path.resolve(strict=True))) == os.path.normcase(str(path)))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        _require((str(path), *_file_identity(opened)) == before[-1])
        payload = stream.read(TENDERPLAN_PROFILE_BINDING_MAX_BYTES + 1)
        _require(_file_identity(os.fstat(stream.fileno())) == _file_identity(opened))
    _require(before == _path_snapshot(path))
    _require(len(payload) == opened.st_size and len(payload) <= TENDERPLAN_PROFILE_BINDING_MAX_BYTES)
    return payload


def load_tenderplan_profile_request(
    path: str | Path, *, expected_sha256: str,
) -> PreparedTenderPlanSearch:
    """Load a bounded regular local file, rejecting aliases and mid-read replacement."""
    try:
        _digest(expected_sha256)
        return prepare_tenderplan_profile_request(
            _read_binding(path), expected_sha256=expected_sha256,
        )
    except (AttributeError, OSError, TypeError, ValueError, RecursionError):
        raise TenderPlanProfileRequestError from None
