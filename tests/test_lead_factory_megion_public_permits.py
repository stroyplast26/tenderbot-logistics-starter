import csv
import hashlib
import io
import json
import unittest

from lead_factory.megion_public_permits import (
    MAX_CSV_BYTES,
    MAX_CSV_ROWS,
    MEGION_CSV_HEADERS,
    MegionPermitsValidationError,
    parse_megion_permits_csv,
    validate_megion_source_url,
)


URL = "https://opendata.admmegion.ru/opendata/csv/31875/data/data-20260902T145832-structure-20240702T122402.csv"
PUBLISHED = "2026-09-02T00:00:00Z"


def row():
    # Synthetic public-business schema fixture. Ignored fields contain sentinels,
    # never actual individual names or contacts from the municipal dataset.
    return [
        "Мегион, улица Примерная, участок 1",
        "IGNORED_OVERSIGHT_REFERENCE",
        "86:19:0010405:1234",
        "PRIVATE_REGISTERED_ADDRESS_SENTINEL",
        "Общество с ограниченной ответственностью",
        "ООО «Тестовая организация»",
        "PRIVATE_DEVELOPER_FULLNAME_SENTINEL",
        "76.105056",
        "61.036799",
        "Ханты-Мансийский автономный округ — Югра",
        'Здание мастерской,\nкорпус "А"',
        "86-19-TEST-2026",
        "14.04.2026",
        "PRIVATE_OFFICIAL_POSITION_SENTINEL",
        "PRIVATE_OFFICIAL_NAME_SENTINEL",
        "ДЗиГ",
        "городской округ город Мегион",
    ]


def csv_bytes(rows, headers=MEGION_CSV_HEADERS, *, bom=True):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return ("\ufeff" if bom else "").encode("utf-8") + output.getvalue().encode("utf-8")


def parse(blob):
    return parse_megion_permits_csv(blob, source_url=URL, published_at_utc=PUBLISHED)


class MegionPublicPermitsTests(unittest.TestCase):
    def test_real_csv_shape_bom_multiline_and_sanitized_evidence(self):
        blob = csv_bytes([row()])
        result = parse(blob)
        self.assertEqual(result.input_row_count, 1)
        self.assertEqual(dict(result.excluded_counts), {})
        self.assertEqual(result.csv_sha256, hashlib.sha256(blob).hexdigest())
        record = result.records[0]
        self.assertEqual(record.source_revision, "20260902145832")
        self.assertEqual(record.published_at_utc, PUBLISHED)
        self.assertEqual(record.published_precision, "DATE")
        self.assertEqual(record.issued_at_utc, "2026-04-14T00:00:00Z")
        self.assertEqual(record.stage, "PERMIT_ISSUED")
        self.assertEqual(record.stage_source_date_utc, record.issued_at_utc)
        self.assertEqual(record.latitude, "61.036799")
        self.assertEqual(record.longitude, "76.105056")
        self.assertEqual(record.sanitized_row_sha256, hashlib.sha256(record.sanitized_row_bytes).hexdigest())
        public = json.loads(record.sanitized_row_json)
        self.assertEqual(set(public), {"permit_number", "issuer", "jurisdiction", "title", "address",
                                       "cadastral_id", "developer_name", "issued_at_utc", "longitude",
                                       "latitude", "stage", "stage_source_date_utc"})
        self.assertNotIn("SENTINEL", record.sanitized_row_json)
        self.assertNotIn("source_url", public)
        self.assertNotIn("source_revision", public)
        self.assertNotIn("csv_sha256", public)
        self.assertNotIn("demand", public)
        self.assertNotIn("expires_at_utc", public)

    def test_private_ambiguous_and_contact_polluted_developers_are_excluded(self):
        cases = []
        for form, name in [("ИП", "ИП Тестовый Т.Т."), ("----", "Неопределённый заявитель"),
                           ("ООО", "Иванов Иван Иванович"), ("ООО", ""),
                           ("ООО", "ООО Тест, email@example.invalid")]:
            value = row()
            value[4], value[5] = form, name
            cases.append(value)
        result = parse(csv_bytes(cases))
        self.assertEqual(result.records, ())
        self.assertEqual(sum(result.excluded_counts.values()), len(cases))
        self.assertEqual(set(result.excluded_counts), {"PRIVATE_DEVELOPER", "UNCONFIRMED_LEGAL_FORM",
                                                     "UNSAFE_OR_MISSING_LEGAL_NAME"})

    def test_whitelisted_legal_forms_and_known_municipal_typo(self):
        for form in ["ООО", "АО", "ПАО", "ЗАО", "ГУП", "МУП", "ГКУ", "МКУ", "ФГБУ",
                     "бюджетное учреждение", "Мунициальное казённое учреждение"]:
            with self.subTest(form=form):
                value = row()
                value[4], value[5] = form, "Тестовый объект"
                self.assertEqual(len(parse(csv_bytes([value])).records), 1)

    def test_identical_duplicates_collapse_but_conflicting_permit_rows_all_rejected(self):
        first = row()
        copy = row()
        copy[14] = "DIFFERENT_IGNORED_OFFICIAL_SENTINEL"
        equal = parse(csv_bytes([first, copy]))
        self.assertEqual(len(equal.records), 1)
        self.assertEqual(dict(equal.excluded_counts), {"DUPLICATE_PUBLIC_ROW": 1})
        copy[10] = "Другое здание"
        conflict = parse(csv_bytes([first, copy]))
        reversed_ = parse(csv_bytes([copy, first]))
        self.assertEqual(conflict.records, ())
        self.assertEqual(dict(conflict.excluded_counts), {"CONFLICTING_PERMIT_ROWS": 2})
        self.assertEqual(dict(conflict.excluded_counts), dict(reversed_.excluded_counts))

    def test_stable_identity_and_row_digest_ignore_file_order_publication_and_region_metadata(self):
        first = parse(csv_bytes([row()])).records[0]
        modified = row()
        modified[9] = "Обновлённое название того же региона"
        modified[14] = "NEW_IGNORED_OFFICIAL_SENTINEL"
        next_version = parse_megion_permits_csv(
            csv_bytes([modified]),
            source_url=URL.replace("20260902T145832", "20261002T123456"),
            published_at_utc="2026-10-02T00:00:00Z",
        ).records[0]
        self.assertEqual(first.source_external_key, next_version.source_external_key)
        self.assertEqual(first.sanitized_row_sha256, next_version.sanitized_row_sha256)
        self.assertNotEqual(first.source_revision, next_version.source_revision)
        self.assertNotEqual(first.revision_binding_sha256, next_version.revision_binding_sha256)
        modified[15] = "УАиГ"
        another_issuer = parse(csv_bytes([modified])).records[0]
        self.assertNotEqual(first.source_external_key, another_issuer.source_external_key)

    def test_invalid_coordinates_do_not_become_invented_locations(self):
        for longitude, latitude in [("", ""), ("https://2gis.ru/example", "61.1"),
                                    ("76.1", ""), ("181", "61"), ("76", "91"),
                                    ("NaN", "61"), ("76E1", "61")]:
            value = row()
            value[7], value[8] = longitude, latitude
            record = parse(csv_bytes([value])).records[0]
            self.assertEqual((record.longitude, record.latitude), ("", ""))
        value = row()
        value[7], value[8] = "76,1050560", "61,0367990"
        record = parse(csv_bytes([value])).records[0]
        self.assertEqual((record.longitude, record.latitude), ("76.105056", "61.036799"))

    def test_untrusted_formula_and_invalid_required_values_are_excluded(self):
        for index, bad in [(0, "=HYPERLINK(\"https://example.invalid\")"), (5, "\t@SUM(1,2)"),
                           (10, "-cmd|malicious"), (10, "+SUM(1,2)"),
                           (11, ""), (12, "31.02.2026"), (10, "bad\x00title"), (16, "another city")]:
            with self.subTest(index=index):
                value = row()
                value[index] = bad
                result = parse(csv_bytes([value]))
                self.assertEqual(result.records, ())
                self.assertEqual(sum(result.excluded_counts.values()), 1)

    def test_ignored_private_fields_and_dash_placeholders_do_not_drop_public_facts(self):
        value = row()
        for index in (1, 3, 6, 9, 13, 14):
            value[index] = "=IGNORED_PRIVATE_SENTINEL"
        value[2] = "-----"
        result = parse(csv_bytes([value]))
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].cadastral_id, "")
        self.assertNotIn("IGNORED_PRIVATE_SENTINEL", result.records[0].sanitized_row_json)
        self.assertEqual(dict(result.excluded_counts), {})

    def test_embedded_contacts_in_public_text_are_not_preserved_as_public_evidence(self):
        for index in (0, 10):
            for suffix in (" Контакт: contact@example.invalid, +7 900 000-00-00",
                           " Ответственный: Тестов Иван Иванович"):
                with self.subTest(index=index, suffix=suffix):
                    value = row()
                    value[index] += suffix
                    result = parse(csv_bytes([value]))
                    self.assertEqual(result.records, ())
                    self.assertEqual(dict(result.excluded_counts), {"PRIVATE_OBJECT_TEXT": 1})
        value = row()
        value[0] = "Мегион, улица Пушкина, участок 1"
        self.assertEqual(len(parse(csv_bytes([value])).records), 1)

    def test_common_russian_contacts_and_probable_names_are_fail_closed(self):
        unsafe = (
            " 8 (900) 123-45-67", " +7-900-123-45-67", " +7.900.123.45.67",
            " 7 (900) 123-45-67", " 8-900-123-45-67", " 8.900.123.45.67",
            " +7/900/123/45/67", " 89001234567", " 8\u00a0(900)\u2009123\u201145\u201167",
            " 8\u200b(900)\u200b123-45-67", " 8\u2060(900)\u2060123-45-67",
            " 8\x00(900)123-45-67",
            " 8(900)123\u0301-45-67", " ＋７ ９００ １２３ ４５ ６７",
            " 8(900)123\ufe63 45\ufe63 67",
            " Иван Иванов", " иван иванов", " иВан ИВАНОВ", " ИВАНОВ\u00a0ИВАН",
            " Иван\u200bИванов", " Иван\u2060Иванов", " Ива\u0301н Иванов",
            " Иван,\nИванов", " И.И. Иванов", " Иванов И. И.",
            " и.и. Иванов", " и. и. Иванов", " И.и. Иванов",
            " Иванов И И", " И И Иванов", " В. Иванов", " Иванов С.",
            " Иван П. Иванов", " Иван П Иванов", " Василий Петров", " василий петров",
            " Аркадий Сидоров", " аркадий сидоров", " Иван Шевченко", " Шевченко Иван",
            " денис сидоров", " Иван Иванович", " Анна Сергеевна",
        )
        reasons = {
            0: {"PRIVATE_OBJECT_TEXT", "UNTRUSTED_CONTROL"},
            5: {"PRIVATE_DEVELOPER", "UNSAFE_OR_MISSING_LEGAL_NAME", "UNTRUSTED_CONTROL"},
            10: {"PRIVATE_OBJECT_TEXT", "UNTRUSTED_CONTROL"},
            15: {"UNSAFE_OR_MISSING_ISSUER", "UNTRUSTED_CONTROL"},
        }
        for index, allowed_reasons in reasons.items():
            for suffix in unsafe:
                with self.subTest(index=index, suffix=suffix):
                    value = row()
                    value[index] += suffix
                    result = parse(csv_bytes([value]))
                    self.assertEqual(result.records, ())
                    self.assertEqual(sum(result.excluded_counts.values()), 1)
                    self.assertTrue(set(result.excluded_counts) <= allowed_reasons)

        safe = row()
        safe[0] = ("Ханты Мансийский автономный округ — Югра, Г.О. Мегион, "
                   "улица Пушкина, улица пушкина, дом 8, корпус 900")
        safe[2] = "86:19:006:2026"
        safe[5] = "ООО «Ивановский квартал»"
        safe[10] = "Жилой комплекс Ивановский, корпус 86-19-006-2026"
        safe[11] = "86-19-006-2026"
        self.assertEqual(len(parse(csv_bytes([safe])).records), 1)

        safe_names = row()
        safe_names[5] = "ООО «Проект жилых домов Югры»"
        safe_names[10] = "Жилой комплекс Северная Долина, магазин строительных материалов"
        self.assertEqual(len(parse(csv_bytes([safe_names])).records), 1)

        quoted_private_name = row()
        quoted_private_name[5] = "ООО «василий петров»"
        self.assertEqual(parse(csv_bytes([quoted_private_name])).records, ())

        for private_name in (
            "Денис Сидоров", "Рустам Ахметов", "Рустам Ахметов Консалтинг",
        ):
            replacements = {
                0: f"Мегион, объект «{private_name}»",
                5: f"ООО «{private_name}»",
                10: f"Ответственный «{private_name}»",
                15: f"Департамент «{private_name}»",
            }
            for index, replacement in replacements.items():
                with self.subTest(index=index, private_name=private_name):
                    quoted = row()
                    quoted[index] = replacement
                    result = parse(csv_bytes([quoted]))
                    self.assertEqual(result.records, ())
                    self.assertEqual(sum(result.excluded_counts.values()), 1)

        eponymous_address = row()
        eponymous_address[0] = "Мегион, улица Ивана Иванова, улица Василия Петрова, дом 1"
        self.assertEqual(len(parse(csv_bytes([eponymous_address])).records), 1)

        ordinary_unicode_whitespace = row()
        ordinary_unicode_whitespace[0] = "Мегион, улица\u00a0Пушкина, дом 1"
        self.assertEqual(len(parse(csv_bytes([ordinary_unicode_whitespace])).records), 1)

    def test_strict_header_csv_width_encoding_and_bounds(self):
        duplicate = list(MEGION_CSV_HEADERS)
        duplicate[-1] = duplicate[0]
        bad_inputs = [csv_bytes([row()], headers=duplicate), csv_bytes([row()[:-1]]),
                      csv_bytes([row() + ["extra"]]), csv_bytes([row()], headers=MEGION_CSV_HEADERS[:-1]),
                      b"\xff\xfeinvalid", b"x" * (MAX_CSV_BYTES + 1), b""]
        header_only = csv_bytes([])
        bad_inputs.append(header_only + b'"unterminated\n')
        for blob in bad_inputs:
            with self.subTest(size=len(blob)), self.assertRaises(MegionPermitsValidationError):
                parse(blob)
        many_rows = csv_bytes([[""] * 17] * (MAX_CSV_ROWS + 1))
        self.assertLess(len(many_rows), MAX_CSV_BYTES)
        with self.assertRaises(MegionPermitsValidationError):
            parse(many_rows)
        self.assertEqual(len(parse(csv_bytes([row()], bom=False)).records), 1)

    def test_only_exact_official_version_url_and_date_only_publication_are_accepted(self):
        self.assertEqual(validate_megion_source_url(URL), URL)
        for url, publication in [(URL.replace("https:", "http:"), PUBLISHED),
                                 (URL + "?key=private", PUBLISHED), (URL + "#fragment", PUBLISHED),
                                 (URL.replace("31875", "12345"), PUBLISHED),
                                 (URL.replace("20240702T122402", "20260702T122402"), PUBLISHED),
                                 (URL, "2026-09-02T14:58:32Z"), (URL, "2026-09-03T00:00:00Z")]:
            with self.subTest(url=url), self.assertRaises(MegionPermitsValidationError):
                parse_megion_permits_csv(csv_bytes([row()]), source_url=url, published_at_utc=publication)


if __name__ == "__main__":
    unittest.main()
