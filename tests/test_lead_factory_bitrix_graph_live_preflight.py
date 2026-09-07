from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from lead_factory.bitrix_graph_live_preflight import (
    BitrixGraphLivePreflightError,
    BitrixGraphLiveReadBoundary,
    run_bitrix_graph_live_preflight,
)
from lead_factory.bitrix_graph_preflight import graph_required_field_shapes
from lead_factory.bitrix_graph_mapping import BitrixGraphRoute, graph_mapping_manifest_hash
from lead_factory.bitrix_rest import BitrixRestBoundary
from tests.test_lead_factory_bitrix_graph_schema_admin import _manifest


_AUTHORITY_PATCHER = patch(
    "lead_factory.bitrix_rest.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class _Response:
    status_code = 200

    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class _Session:
    def __init__(self):
        self.manifest = None
        self.calls: list[tuple[str, dict]] = []
        self.bad_searchable = ""
        self.correlation_collision = False

    def _fields(self, entity):
        values = {}
        for (item_entity, field), shape in graph_required_field_shapes(self.manifest).items():
            if item_entity != entity:
                continue
            value_type, multiple, mandatory, _searchable = shape
            provider_field = field
            if entity == "activity":
                provider_field = {
                    "title": "SUBJECT",
                    "description": "DESCRIPTION",
                    "deadline": "DEADLINE",
                    "ownerTypeId": "OWNER_TYPE_ID",
                    "ownerId": "OWNER_ID",
                    "responsibleId": "RESPONSIBLE_ID",
                }.get(field, field)
            values[provider_field] = {
                "type": value_type,
                "isMultiple": multiple,
                "isRequired": mandatory,
                "isReadOnly": False,
            }
        return values

    def request(self, _http_method, url, **kwargs):
        method = url.rsplit("/", 1)[-1].removesuffix(".json")
        payload = kwargs["json"]
        self.calls.append((method, payload))
        parts = method.split(".")
        if method.endswith(".fields"):
            return _Response({"result": self._fields(parts[1])})
        if ".userfield.list" in method:
            field = payload["filter"]["FIELD_NAME"]
            searchable = any(
                item.remote_field == field for item in self.manifest.correlation_fields
            )
            if field == self.bad_searchable:
                searchable = not searchable
            return _Response(
                {
                    "result": [
                        {
                            "FIELD_NAME": field,
                            "IS_SEARCHABLE": "Y" if searchable else "N",
                            "EDIT_IN_LIST": "Y",
                        }
                    ],
                    "total": 1,
                }
            )
        if method == "crm.category.list":
            return _Response({"result": {"categories": [{"id": "7"}]}})
        if method == "crm.status.list":
            entity_id = payload["filter"]["ENTITY_ID"]
            rows = (
                [{"STATUS_ID": "C7:NEW"}]
                if entity_id == "DEAL_STAGE_7"
                else [{"STATUS_ID": "WEB"}]
            )
            return _Response({"result": rows, "total": len(rows)})
        entity = parts[1]
        if method.endswith(".list"):
            if any(str(key).startswith("=") for key in payload.get("filter", {})):
                rows = (
                    [{"ID": "91"}]
                    if self.correlation_collision and entity == "company"
                    else []
                )
                return _Response({"result": rows, "total": len(rows)})
            return _Response({"result": [{"ID": "1"}], "total": 1})
        if method.endswith(".get"):
            result = {"ID": "1"}
            if entity == "contact":
                result["COMPANY_ID"] = "1"
            elif entity == "deal":
                result.update({"COMPANY_ID": "1", "CONTACT_ID": "1"})
            elif entity == "activity":
                result.update(
                    {
                        "OWNER_TYPE_ID": "2",
                        "OWNER_ID": "1",
                        "RESPONSIBLE_ID": "7",
                        "DESCRIPTION": "existing",
                        "DEADLINE": "2026-08-22T10:00:00+03:00",
                    }
                )
            return _Response({"result": result})
        raise AssertionError(method)


class BitrixGraphLivePreflightTests(unittest.TestCase):
    webhook = "https://example.bitrix24.ru/rest/7/secret-webhook-value"

    def composition(self):
        session = _Session()
        transport = BitrixRestBoundary(webhook_url=self.webhook, session=session)
        raw = replace(
            _manifest(transport.portal_fingerprint),
            route=BitrixGraphRoute("7", "C7:NEW", "7", "7"),
            declared_manifest_hash="",
        )
        manifest = replace(raw, declared_manifest_hash=graph_mapping_manifest_hash(raw))
        session.manifest = manifest
        boundary = BitrixGraphLiveReadBoundary(transport)
        return session, manifest, boundary

    def test_exact_live_inventory_is_green_but_never_canary_authority(self):
        session, manifest, boundary = self.composition()
        report = run_bitrix_graph_live_preflight(manifest, boundary)
        self.assertTrue(report.live_preflight_ok)
        self.assertEqual(report.external_writes_performed, 0)
        self.assertEqual(report.required_field_count, 57)
        self.assertEqual(report.correlation_probe_totals, (("company", 0), ("contact", 0), ("deal", 0)))
        self.assertTrue(report.credential_owner_bound)
        self.assertTrue(report.credential_isolation_limited)
        self.assertTrue(report.owner_approval_required)
        self.assertFalse(report.canary_ready)
        self.assertFalse(
            any(
                method.endswith((".add", ".update", ".delete"))
                for method, _payload in session.calls
            )
        )

    def test_field_or_correlation_mismatch_fails_closed(self):
        session, manifest, boundary = self.composition()
        session.bad_searchable = manifest.correlation_fields[0].remote_field
        report = run_bitrix_graph_live_preflight(manifest, boundary)
        self.assertFalse(report.live_preflight_ok)
        self.assertEqual(report.error_code, "LIVE_GRAPH_PREFLIGHT_FAILED")

        session, manifest, boundary = self.composition()
        session.correlation_collision = True
        report = run_bitrix_graph_live_preflight(manifest, boundary)
        self.assertFalse(report.live_preflight_ok)
        self.assertEqual(report.correlation_probe_totals, (("company", 1),))

    def test_boundary_rejects_arbitrary_entity_without_http(self):
        session, _manifest_value, boundary = self.composition()
        with self.assertRaises(BitrixGraphLivePreflightError):
            boundary.field_catalog("lead")
        self.assertEqual(session.calls, [])


if __name__ == "__main__":
    unittest.main()
