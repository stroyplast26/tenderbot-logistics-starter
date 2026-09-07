from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from lead_factory.bitrix_graph_mapping import (
    GRAPH_ACTIVITY_MARKER_VERSION,
    GRAPH_CONTRACT_VERSION,
    GRAPH_INPUT_CONTRACT_VERSION,
    GRAPH_MAPPING_EVIDENCE_MODE,
    GRAPH_MAPPING_LIFECYCLE,
    GRAPH_MAPPING_MANIFEST_VERSION,
    BitrixGraphCorrelationField,
    BitrixGraphFieldBinding,
    BitrixGraphMappingManifest,
    BitrixGraphRoute,
    BitrixGraphSourceBinding,
    graph_mapping_manifest_hash,
)
from lead_factory.bitrix_graph_schema_admin import (
    BitrixGraphUfAdminBoundary,
    BitrixGraphUfOutcomeUncertain,
    BitrixGraphUfProvisioner,
    BitrixGraphUfSchemaError,
    build_bitrix_graph_uf_plan,
)


_CUSTOM = {
    "company": {"UF_CRM_LF_COMPANY_ID", "UF_CRM_LF_INN"},
    "contact": {"UF_CRM_LF_CONTACT_ID"},
    "deal": {
        "UF_CRM_LF_AD_CLICK_ID",
        "UF_CRM_LF_ATTRIBUTION",
        "UF_CRM_LF_CONSENT_HASH",
        "UF_CRM_LF_CONSENT_VERSION",
        "UF_CRM_LF_CORRELATION_ID",
        "UF_CRM_LF_FORM_ID",
        "UF_CRM_LF_FORM_VERSION",
        "UF_CRM_LF_IDENTITY_POLICY_VERSION",
        "UF_CRM_LF_LANDING_URL",
        "UF_CRM_LF_LANDING_VERSION",
        "UF_CRM_LF_LATEST_UTM_CAMPAIGN",
        "UF_CRM_LF_LATEST_UTM_CONTENT",
        "UF_CRM_LF_LATEST_UTM_MEDIUM",
        "UF_CRM_LF_LATEST_UTM_SOURCE",
        "UF_CRM_LF_LATEST_UTM_TERM",
        "UF_CRM_LF_OFFER_VERSION",
        "UF_CRM_LF_OPPORTUNITY_ID",
        "UF_CRM_LF_ORIGINAL_UTM_CAMPAIGN",
        "UF_CRM_LF_ORIGINAL_UTM_CONTENT",
        "UF_CRM_LF_ORIGINAL_UTM_MEDIUM",
        "UF_CRM_LF_ORIGINAL_UTM_SOURCE",
        "UF_CRM_LF_ORIGINAL_UTM_TERM",
        "UF_CRM_LF_PRODUCT_KEY",
        "UF_CRM_LF_PROJECT_ID",
        "UF_CRM_LF_SITE_POLICY_HASH",
        "UF_CRM_LF_SITE_POLICY_ID",
        "UF_CRM_LF_SITE_POLICY_VERSION",
        "UF_CRM_LF_SOURCE_EVENT_ID",
        "UF_CRM_LF_SOURCE_ID",
        "UF_CRM_LF_SOURCE_RECORD_ID",
        "UF_CRM_LF_SUBMISSION_ID",
        "UF_CRM_LF_YCLID",
    },
}
_STANDARD = {
    ("activity", "DEADLINE"): "deadline",
    ("activity", "DESCRIPTION"): "description",
    ("activity", "SUBJECT"): "title",
    ("company", "TITLE"): "TITLE",
    ("contact", "EMAIL"): "EMAIL",
    ("contact", "NAME"): "NAME",
    ("contact", "PHONE"): "PHONE",
    ("contact", "POST"): "POST",
    ("deal", "TITLE"): "TITLE",
}


def _manifest(portal_identity: str, *, remap_inn: bool = False):
    bindings = [
        BitrixGraphFieldBinding(entity, key, remote)
        for (entity, key), remote in _STANDARD.items()
    ]
    for entity, fields in _CUSTOM.items():
        for field in fields:
            remote = "UF_CRM_CUSTOM_INN" if remap_inn and field == "UF_CRM_LF_INN" else field
            bindings.append(BitrixGraphFieldBinding(entity, field, remote))
    raw = BitrixGraphMappingManifest(
        manifest_version=GRAPH_MAPPING_MANIFEST_VERSION,
        mapping_id="alumkomplekt:bitrix:graph:v1",
        mapping_version="1",
        contract_version=GRAPH_CONTRACT_VERSION,
        input_contract_version=GRAPH_INPUT_CONTRACT_VERSION,
        lifecycle=GRAPH_MAPPING_LIFECYCLE,
        evidence_mode=GRAPH_MAPPING_EVIDENCE_MODE,
        portal_identity=portal_identity,
        field_bindings=tuple(sorted(bindings, key=lambda item: (item.entity_type, item.payload_key))),
        correlation_fields=(
            BitrixGraphCorrelationField("company", "UF_CRM_LF_CORRELATION_COMPANY"),
            BitrixGraphCorrelationField("contact", "UF_CRM_LF_CORRELATION_CONTACT"),
            BitrixGraphCorrelationField("deal", "UF_CRM_LF_CORRELATION_DEAL"),
        ),
        source_bindings=(BitrixGraphSourceBinding("alumkomplekt-site", "WEB"),),
        route=BitrixGraphRoute("7", "C7:NEW", "10", "11"),
        activity_marker_version=GRAPH_ACTIVITY_MARKER_VERSION,
    )
    return replace(raw, declared_manifest_hash=graph_mapping_manifest_hash(raw))


class _Response:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = {} if body is None else body

    def json(self):
        return self._body


class _Session:
    def __init__(self):
        self.fields: dict[tuple[str, str], dict] = {}
        self.calls: list[tuple[str, dict]] = []
        self.next_id = 100
        self.ambiguous_field = ""
        self.apply_ambiguous = False

    @staticmethod
    def _entity(method: str) -> str:
        return method.split(".")[1]

    @staticmethod
    def _shape(fields: dict) -> dict:
        return {
            "ID": "1",
            "FIELD_NAME": fields["FIELD_NAME"],
            "USER_TYPE_ID": fields["USER_TYPE_ID"],
            "MULTIPLE": fields["MULTIPLE"],
            "MANDATORY": fields["MANDATORY"],
            "IS_SEARCHABLE": fields["IS_SEARCHABLE"],
            "EDIT_IN_LIST": fields["EDIT_IN_LIST"],
        }

    def request(self, _http_method, url, **kwargs):
        method = url.rsplit("/", 1)[-1].removesuffix(".json")
        payload = kwargs["json"]
        self.calls.append((method, payload))
        entity = self._entity(method)
        if method.endswith(".list"):
            name = payload["filter"]["FIELD_NAME"]
            row = self.fields.get((entity, name))
            rows = [] if row is None else [dict(row)]
            return _Response(body={"result": rows, "total": len(rows)})
        if method.endswith(".add"):
            fields = payload["fields"]
            name = fields["FIELD_NAME"]
            if name == self.ambiguous_field:
                if self.apply_ambiguous:
                    self.fields[(entity, name)] = self._shape(fields)
                return _Response(status_code=503, body={})
            self.next_id += 1
            row = self._shape(fields)
            row["ID"] = str(self.next_id)
            self.fields[(entity, name)] = row
            return _Response(body={"result": str(self.next_id)})
        raise AssertionError(method)


class BitrixGraphUfSchemaAdminTests(unittest.TestCase):
    webhook = "https://example.bitrix24.ru/rest/7/secret-webhook-value"

    def setUp(self) -> None:
        authority = patch(
            "lead_factory.bitrix_rest.assert_external_allowed", return_value=None
        )
        authority.start()
        self.addCleanup(authority.stop)

    def composition(self):
        session = _Session()
        boundary = BitrixGraphUfAdminBoundary(
            webhook_url=self.webhook, session=session, timeout_seconds=7.5
        )
        manifest = _manifest(boundary.portal_identity)
        return session, boundary, manifest, build_bitrix_graph_uf_plan(manifest)

    def test_plan_is_sealed_from_manifest_remote_fields_and_exact_union(self):
        _, boundary, manifest, plan = self.composition()
        self.assertEqual(len(plan.fields), 38)
        self.assertEqual(plan.portal_identity, boundary.portal_identity)
        self.assertEqual(
            {field.field_name for field in plan.fields if field.searchable == "Y"},
            {
                "UF_CRM_LF_CORRELATION_COMPANY",
                "UF_CRM_LF_CORRELATION_CONTACT",
                "UF_CRM_LF_CORRELATION_DEAL",
            },
        )
        remapped = build_bitrix_graph_uf_plan(
            _manifest(boundary.portal_identity, remap_inn=True)
        )
        names = {field.field_name for field in remapped.fields}
        self.assertIn("UF_CRM_CUSTOM_INN", names)
        self.assertNotIn("UF_CRM_LF_INN", names)

        tampered = replace(plan, mapping_manifest=replace(manifest, mapping_version="2"))
        with self.assertRaises(BitrixGraphUfSchemaError):
            BitrixGraphUfProvisioner(boundary, tampered)

    def test_missing_fields_are_added_once_read_back_and_second_run_is_read_only(self):
        session, boundary, _manifest_value, plan = self.composition()
        first = plan.fields[0]
        session.fields[(first.entity_type, first.field_name)] = {
            "ID": "9",
            "FIELD_NAME": first.field_name,
            "USER_TYPE_ID": "string",
            "MULTIPLE": "N",
            "MANDATORY": "N",
            "IS_SEARCHABLE": first.searchable,
            "EDIT_IN_LIST": "Y",
        }
        report = BitrixGraphUfProvisioner(boundary, plan).provision()
        self.assertEqual(len(report.existing), 1)
        self.assertEqual(len(report.created), 37)
        add_calls = [call for call in session.calls if call[0].endswith(".add")]
        self.assertEqual(len(add_calls), 37)
        self.assertTrue(all(call[1]["fields"]["USER_TYPE_ID"] == "string" for call in add_calls))
        self.assertFalse(any("update" in call[0] or "delete" in call[0] for call in session.calls))

        session.calls.clear()
        second = BitrixGraphUfProvisioner(boundary, plan).provision()
        self.assertEqual(len(second.existing), 38)
        self.assertEqual(second.created, ())
        self.assertFalse(any(call[0].endswith(".add") for call in session.calls))

    def test_wrong_existing_shape_fails_before_any_add(self):
        session, boundary, _manifest_value, plan = self.composition()
        first = plan.fields[0]
        session.fields[(first.entity_type, first.field_name)] = {
            "ID": "9",
            "FIELD_NAME": first.field_name,
            "USER_TYPE_ID": "integer",
            "MULTIPLE": "N",
            "MANDATORY": "N",
            "IS_SEARCHABLE": first.searchable,
            "EDIT_IN_LIST": "Y",
        }
        with self.assertRaises(BitrixGraphUfSchemaError):
            BitrixGraphUfProvisioner(boundary, plan).provision()
        self.assertFalse(any(call[0].endswith(".add") for call in session.calls))

    def test_add_is_capability_bound_and_secret_is_redacted(self):
        session, boundary, _manifest_value, plan = self.composition()
        field = plan.fields[0]
        with self.assertRaises(BitrixGraphUfSchemaError):
            boundary._add_exact(
                field, plan_hash=plan.declared_plan_hash, capability=None  # type: ignore[arg-type]
            )
        self.assertEqual(session.calls, [])
        self.assertNotIn("secret-webhook-value", repr(boundary))
        self.assertNotIn("example.bitrix24.ru", repr(boundary))

    def test_ambiguous_add_is_never_retried_and_can_reconcile_by_read(self):
        session, boundary, _manifest_value, plan = self.composition()
        field = plan.fields[0]
        session.ambiguous_field = field.field_name
        with self.assertRaises(BitrixGraphUfOutcomeUncertain):
            BitrixGraphUfProvisioner(boundary, plan).provision()
        self.assertEqual(
            sum(1 for method, _ in session.calls if method.endswith(".add")), 1
        )

        session, boundary, _manifest_value, plan = self.composition()
        session.ambiguous_field = plan.fields[0].field_name
        session.apply_ambiguous = True
        report = BitrixGraphUfProvisioner(boundary, plan).provision()
        self.assertEqual(len(report.created), 38)
        self.assertEqual(
            sum(1 for method, _ in session.calls if method.endswith(".add")), 38
        )


if __name__ == "__main__":
    unittest.main()
