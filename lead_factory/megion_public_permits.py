"""Deterministic public-only parser for supplied Megion dataset 31875 CSV bytes.

No source access, authority, storage or network operation occurs here. The raw
CSV includes personal-data columns and must not become evidence. Only the exact
allowlisted public fields of accepted legal-entity records are returned.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import re
import unicodedata
from collections import Counter
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit


MAX_CSV_BYTES = 2 * 1024 * 1024
MAX_CSV_ROWS = 5000
MEGION_DATASET_ID = "31875"
MEGION_JURISDICTION = "RU-KHM-MEGION"
MEGION_CSV_HEADERS = (
    "Адрес объекта",
    "Дата и номер заключения органа государственного строительного надзора",
    "кадастровый номер з/у",
    "Адрес места нахождения юр.лица",
    "Организационно-правовая форма юр.лица",
    "Сокращённое наименование юридического лица",
    "Полное наименование юр.лица, ФИО ИП или физ.лица (застройщика)",
    "Координаты (долгота)",
    "Координаты (широта)",
    "субъект Российской Федерации",
    "Описание объекта, на который выдано разрешение",
    "Реквизиты выданного разрешения",
    "Дата выдачи разрешения",
    "Должность лица, выдавшего разрешение",
    "ФИО должностного лица, выдавшего разрешение",
    "Наименование органа, выдавшего разрешение",
    "Муниципальное образование",
)
_SOURCE_PATH = re.compile(
    r"^/opendata/csv/31875/data/data-(\d{8}T\d{6})-structure-(\d{8}T\d{6})\.csv$"
)
_NUMBER = re.compile(r"^[+-]?[0-9]+(?:[.,][0-9]+)?$")
_PERMIT = re.compile(r"^[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9./_-]{1,159}$")
_PRIVATE_NAME = re.compile(
    r"(?:\bип\b|индивидуальн\w*\s+предпринимател|физическ\w*\s+лиц|\bфио\b|"
    r"\b[а-яё]+\s+[а-яё]\.\s*[а-яё]\.|"
    r"\b[а-яё]+\s+[а-яё]+\s+[а-яё]+(?:ович|евич|овна|евна)\b)",
    re.IGNORECASE,
)
_CONTACT = re.compile(
    r"@|https?://|\b(?:тел(?:ефон)?|факс|e-?mail)\b|"
    r"(?<![\d+])(?:\+7|[78])[\s./\-\u2010-\u2015\u2212]*"
    r"(?:\(\s*[0-9]{3}\s*\)|[0-9]{3})[\s./\-\u2010-\u2015\u2212]*"
    r"[0-9]{3}[\s./\-\u2010-\u2015\u2212]*[0-9]{2}"
    r"[\s./\-\u2010-\u2015\u2212]*[0-9]{2}(?!\d)",
    re.IGNORECASE,
)
_NAME_TOKEN = re.compile(
    r"(?<![а-яё])([а-яё][а-яё'-]{0,31})(?![а-яё])", re.IGNORECASE
)
_PROBABLE_GIVEN_NAMES = frozenset(
    ("александр алексей андрей антон аркадий артем артём василий виктор владимир дмитрий евгений "
     "иван игорь лев максим михаил николай олег павел петр пётр роман сергей юрий ян "
     "александра анна виктория дарья екатерина елена ирина марина мария наталья "
     "ольга светлана татьяна юлия").split()
)
_PROBABLE_NAME_SUFFIXES = (
    "ов", "ев", "ёв", "ин", "ын", "ский", "цкий", "ова", "ева", "ёва",
    "ина", "ына", "ская", "цкая", "ович", "евич", "овна", "евна", "ична",
)
_NON_PERSON_NAME_TOKENS = frozenset(
    ("автономный автономная бульвар город городской городская дом дома домов жилой жилая "
     "здание земельный застройщик застройщика квартал комплекс край магазин магазина "
     "материалов микрорайон "
     "муниципальный муниципальная долина остров источник источники источников "
     "набережная объект область округ парк переулок площадь поселение поселок посёлок "
     "проезд проспект район республика село сквер сооружение строение улица улице улицы "
     "ул участок центр шоссе корпус во на по до от из за со").split()
)
_TOPONYM_NAME_MARKERS = frozenset(
    "бульвар набережная переулок площадь проезд проспект улица улице улицы ул шоссе им имени".split()
)
_LEGAL_FORMS = {
    "ооо": "ООО", "общество с ограниченной ответственностью": "ООО",
    "ао": "АО", "акционерное общество": "АО",
    "пао": "ПАО", "публичное акционерное общество": "ПАО",
    "оао": "ОАО", "открытое акционерное общество": "ОАО",
    "зао": "ЗАО", "закрытое акционерное общество": "ЗАО",
    "гуп": "ГУП", "государственное унитарное предприятие": "ГУП",
    "муп": "МУП", "муниципальное унитарное предприятие": "МУП",
    "фгуп": "ФГУП", "федеральное государственное унитарное предприятие": "ФГУП",
    "гку": "ГКУ", "государственное казенное учреждение": "ГКУ",
    "мку": "МКУ", "муниципальное казенное учреждение": "МКУ",
    "мунициальное казенное учреждение": "МКУ",  # Exact typo in the published dataset.
    "фгку": "ФГКУ", "федеральное государственное казенное учреждение": "ФГКУ",
    "гбу": "ГБУ", "государственное бюджетное учреждение": "ГБУ",
    "мбу": "МБУ", "муниципальное бюджетное учреждение": "МБУ",
    "фгбу": "ФГБУ", "федеральное государственное бюджетное учреждение": "ФГБУ",
    "гау": "ГАУ", "государственное автономное учреждение": "ГАУ",
    "мау": "МАУ", "муниципальное автономное учреждение": "МАУ",
    "учреждение": "УЧРЕЖДЕНИЕ", "бюджетное учреждение": "БУ",
    "казенное учреждение": "КУ", "автономное учреждение": "АУ",
}


class MegionPermitsValidationError(ValueError):
    """Safe structural error; never embeds CSV values or personal data."""


@dataclass(frozen=True, slots=True, repr=False)
class MegionPermitRecord:
    source_external_key: str
    source_revision: str
    revision_binding_sha256: str
    permit_number: str
    issuer: str
    jurisdiction: str
    title: str
    address: str
    cadastral_id: str
    developer_name: str
    issued_at_utc: str
    latitude: str
    longitude: str
    source_url: str
    published_at_utc: str
    published_precision: str
    stage: str
    stage_source_date_utc: str
    sanitized_row_json: str
    sanitized_row_sha256: str

    @property
    def sanitized_row_bytes(self) -> bytes:
        return self.sanitized_row_json.encode("utf-8")


@dataclass(frozen=True, slots=True, repr=False)
class MegionPermitsParseResult:
    records: tuple[MegionPermitRecord, ...]
    input_row_count: int
    excluded_counts: Mapping[str, int]
    csv_sha256: str


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _pii_probe(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return "".join(char for char in normalized
                   if unicodedata.category(char) not in {"Mn", "Mc", "Me"})


def _name_separator(value: str, left, right) -> bool:
    return bool(re.fullmatch(r"[\s.,;]+", value[left.end():right.start()]))


def _is_toponym_name_pair(value: str, words: tuple, index: int) -> bool:
    for marker_index in range(index - 1, max(-1, index - 3), -1):
        if words[marker_index].group(1).casefold() not in _TOPONYM_NAME_MARKERS:
            continue
        if any(
            not re.fullmatch(r"[\s.]+", value[words[position].end():words[position + 1].start()])
            for position in range(marker_index, index + 1)
        ):
            continue
        intervening = words[marker_index + 1:index]
        if not intervening or all(len(match.group(1)) == 1 for match in intervening):
            return True
    return False


def _has_probable_private_name(value: str) -> bool:
    words = tuple(_NAME_TOKEN.finditer(value))
    for index, (left, right) in enumerate(zip(words, words[1:])):
        if not _name_separator(value, left, right):
            continue
        if _is_toponym_name_pair(value, words, index):
            continue
        raw_first, raw_second = left.group(1), right.group(1)
        first, second = raw_first.casefold(), raw_second.casefold()
        if first in _NON_PERSON_NAME_TOKENS or second in _NON_PERSON_NAME_TOKENS:
            continue
        surrounding = (
            words[index - 1].group(1).casefold() if index else "",
            words[index + 2].group(1).casefold() if index + 2 < len(words) else "",
        )
        geographic_suffix = ("ский", "цкий", "ская", "цкая")
        first_geographic = first.endswith(geographic_suffix)
        second_geographic = second.endswith(geographic_suffix)
        if ((first_geographic or second_geographic)
                and (any(token in _NON_PERSON_NAME_TOKENS for token in surrounding)
                     or (first_geographic and second_geographic)
                     or (min(len(first), len(second)) <= 4
                         and first not in _PROBABLE_GIVEN_NAMES
                         and second not in _PROBABLE_GIVEN_NAMES))):
            continue
        has_name_suffix = first.endswith(_PROBABLE_NAME_SUFFIXES) or second.endswith(
            _PROBABLE_NAME_SUFFIXES
        )
        if (has_name_suffix or first in _PROBABLE_GIVEN_NAMES
                or second in _PROBABLE_GIVEN_NAMES):
            return True
    return False


def _has_private_text(value: str) -> bool:
    probe = _pii_probe(value)
    return bool(_CONTACT.search(probe) or _PRIVATE_NAME.search(probe)
                or _has_probable_private_name(probe))


def _form_key(value: str) -> str:
    return _clean(value).lower().replace("ё", "е").strip(' ."«»')


def validate_megion_source_url(source_url: str) -> str:
    """Validate the observed official URL shape, without resolving or fetching it."""
    if type(source_url) is not str or len(source_url) > 512:
        raise MegionPermitsValidationError("Megion source URL is invalid")
    try:
        url = urlsplit(source_url)
        match = _SOURCE_PATH.fullmatch(url.path)
        if (url.scheme != "https" or url.netloc != "opendata.admmegion.ru"
                or url.query or url.fragment or "?" in source_url or "#" in source_url or not match):
            raise ValueError
        datetime.strptime(match[1], "%Y%m%dT%H%M%S")
        if match[2] != "20240702T122402":
            raise ValueError
    except (ValueError, TypeError):
        raise MegionPermitsValidationError("Megion source URL or structure is invalid") from None
    return source_url


def _source_version(source_url: str, published_at_utc: str) -> str:
    validated_url = validate_megion_source_url(source_url)
    match = _SOURCE_PATH.fullmatch(urlsplit(validated_url).path)
    try:
        version = datetime.strptime(match[1], "%Y%m%dT%H%M%S")
        if (type(published_at_utc) is not str
                or published_at_utc != version.strftime("%Y-%m-%dT00:00:00Z")):
            raise ValueError
    except (ValueError, TypeError):
        raise MegionPermitsValidationError("Megion source version/date-only publication is invalid") from None
    # Filename time has no documented timezone. This is an opaque decimal
    # version sequence, deliberately not a claimed UTC publication instant.
    return match[1].replace("T", "")


def _issued_date(value: str) -> str:
    value = _clean(value)
    for pattern, format_ in ((r"\d{2}\.\d{2}\.\d{4}", "%d.%m.%Y"),
                             (r"\d{4}-\d{2}-\d{2}", "%Y-%m-%d")):
        if re.fullmatch(pattern, value):
            try:
                date = datetime.strptime(value, format_)
            except ValueError:
                break
            if 1900 <= date.year <= 2100:
                return date.strftime("%Y-%m-%dT00:00:00Z")
    raise ValueError("INVALID_ISSUED_DATE")


def _coordinates(longitude: str, latitude: str) -> tuple[str, str]:
    values = (_clean(longitude), _clean(latitude))
    # Links such as 2GIS are not coordinate systems. Do not parse them as points.
    if not all(_NUMBER.fullmatch(value) for value in values):
        return "", ""
    try:
        lon, lat = (Decimal(value.replace(",", ".")) for value in values)
        if not (-180 <= lon <= 180 and -90 <= lat <= 90):
            return "", ""
    except InvalidOperation:
        return "", ""
    def normalize(number: Decimal) -> str:
        return format(number.normalize(), "f") if number else "0"

    return normalize(lon), normalize(lat)


def _public_row(row: list[str]) -> dict[str, str]:
    # Ignored personal fields never participate in classification or evidence.
    for index in (0, 2, 4, 5, 7, 8, 10, 11, 12, 15, 16):
        value = row[index]
        stripped = unicodedata.normalize("NFKC", value).lstrip()
        if any(
            unicodedata.category(char) == "Cf"
            or (unicodedata.category(char) == "Cc" and char not in "\t\r\n")
            for char in value
        ):
            raise ValueError("UNTRUSTED_CONTROL")
        placeholder = bool(stripped) and set(stripped.strip()) <= {"-"}
        if (stripped.startswith(("=", "+", "-", "@"))
                and not _NUMBER.fullmatch(stripped) and not placeholder):
            raise ValueError("FORMULA_CELL")
    # Fields 3, 6, 13, 14 are deliberately never consulted or returned.
    form, developer = _clean(row[4]), _clean(row[5])
    if _PRIVATE_NAME.search(_pii_probe(form)) or _PRIVATE_NAME.search(_pii_probe(developer)):
        raise ValueError("PRIVATE_DEVELOPER")
    legal_form = _LEGAL_FORMS.get(_form_key(form))
    if not legal_form:
        raise ValueError("UNCONFIRMED_LEGAL_FORM")
    if not developer or len(developer) > 512 or _has_private_text(developer):
        raise ValueError("UNSAFE_OR_MISSING_LEGAL_NAME")
    if not any(re.match(rf"^{re.escape(prefix)}(?:\s|[«\"]|$)", developer, re.IGNORECASE)
               for prefix in set(_LEGAL_FORMS.values())):
        developer = f"{legal_form} {developer}"
    permit, issuer, municipality = (_clean(row[index]) for index in (11, 15, 16))
    if not _PERMIT.fullmatch(permit):
        raise ValueError("INVALID_PERMIT_NUMBER")
    if not issuer or len(issuer) > 256 or _has_private_text(issuer):
        raise ValueError("UNSAFE_OR_MISSING_ISSUER")
    if "мегион" not in municipality.casefold() or len(municipality) > 256:
        raise ValueError("UNEXPECTED_JURISDICTION")
    title, address, cadastral = (_clean(row[index]) for index in (10, 0, 2))
    if not title or len(title) > 4096 or len(address) > 2048:
        raise ValueError("INVALID_PUBLIC_OBJECT_TEXT")
    if any(_has_private_text(value) for value in (title, address)):
        raise ValueError("PRIVATE_OBJECT_TEXT")
    if not cadastral.strip("-") or cadastral.lower() in {"нет", "не указан"}:
        cadastral = ""
    elif len(cadastral) > 512 or not re.fullmatch(r"[0-9:;,\s/-]+", cadastral):
        raise ValueError("UNSUPPORTED_CADASTRAL")
    issued = _issued_date(row[12])
    lon, lat = _coordinates(row[7], row[8])
    return {"permit_number": permit, "issuer": issuer, "jurisdiction": MEGION_JURISDICTION,
            "title": title, "address": address, "cadastral_id": cadastral,
            "developer_name": developer, "issued_at_utc": issued, "longitude": lon, "latitude": lat,
            "stage": "PERMIT_ISSUED", "stage_source_date_utc": issued}


def parse_megion_permits_csv(
    csv_bytes: bytes, *, source_url: str, published_at_utc: str,
) -> MegionPermitsParseResult:
    """Parse supplied bytes; structural errors abort, excluded rows return counts.

    Original CSV bytes and ignored personal-data fields are never returned.
    Exact duplicate public rows are collapsed. Every row in a conflicting permit
    group is excluded, so file ordering cannot select an arbitrary winner.
    """
    if type(csv_bytes) is not bytes or not 0 < len(csv_bytes) <= MAX_CSV_BYTES:
        raise MegionPermitsValidationError("Megion CSV byte limit is invalid")
    revision = _source_version(source_url, published_at_utc)
    try:
        text = csv_bytes.decode("utf-8-sig", "strict")
    except UnicodeDecodeError:
        raise MegionPermitsValidationError("Megion CSV must be UTF-8 with optional BOM") from None
    excluded: Counter[str] = Counter()
    groups: dict[str, list[tuple[dict[str, str], str, str]]] = {}
    row_count = 0
    try:
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=",", strict=True)
        headers = next(reader, None)
        if headers is None or tuple(headers) != MEGION_CSV_HEADERS or len(set(headers)) != len(headers):
            raise MegionPermitsValidationError("Megion CSV headers do not match structure 20240702T122402")
        for row in reader:
            if not row:
                continue
            row_count += 1
            if row_count > MAX_CSV_ROWS:
                raise MegionPermitsValidationError("Megion CSV row limit exceeded")
            if len(row) != len(MEGION_CSV_HEADERS):
                raise MegionPermitsValidationError("Megion CSV row width does not match its headers")
            try:
                public = _public_row(row)
            except ValueError as error:
                excluded[str(error)] += 1
                continue
            identity = {key: public[key].casefold() for key in ("permit_number", "issuer", "jurisdiction")}
            key = "megion-permit:" + _hash(_canonical(identity).encode("utf-8"))
            canonical = _canonical(public)
            groups.setdefault(key, []).append((public, canonical, _hash(canonical.encode("utf-8"))))
    except csv.Error:
        raise MegionPermitsValidationError("Megion CSV syntax is invalid") from None
    records = []
    for key, group in groups.items():
        if len({entry[2] for entry in group}) != 1:
            excluded["CONFLICTING_PERMIT_ROWS"] += len(group)
            continue
        public, canonical, row_hash = group[0]
        excluded["DUPLICATE_PUBLIC_ROW"] += len(group) - 1
        binding = {"source_revision": revision, "published_at_utc": published_at_utc,
                   "sanitized_row_sha256": row_hash}
        records.append(MegionPermitRecord(
            source_external_key=key, source_revision=revision,
            revision_binding_sha256=_hash(_canonical(binding).encode("utf-8")),
            source_url=source_url, published_at_utc=published_at_utc, published_precision="DATE",
            sanitized_row_json=canonical, sanitized_row_sha256=row_hash, **public,
        ))
    return MegionPermitsParseResult(
        records=tuple(sorted(records, key=lambda record: record.source_external_key)),
        input_row_count=row_count,
        excluded_counts=MappingProxyType({key: count for key, count in sorted(excluded.items()) if count}),
        csv_sha256=_hash(csv_bytes),
    )
