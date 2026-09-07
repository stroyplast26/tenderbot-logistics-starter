from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from lead_factory.bitrix_graph_live_preflight import BitrixGraphLivePreflightReport
from lead_factory.bitrix_graph_mapping import (
    BitrixGraphMapper,
    graph_mapping_manifest_hash,
)
from lead_factory.bitrix_graph_runtime import (
    BitrixGraphRuntimeError,
    BitrixGraphWriteBoundary,
    BitrixGraphWritePermit,
    BitrixGraphWriterController,
    BitrixGraphWriterDisabled,
    bitrix_graph_write_permit_hash,
)
from lead_factory.bitrix_rest import BitrixRestBoundary
from lead_factory.crm_graph_outbox import COMPANY_CREATE
from tests.test_lead_factory_bitrix_graph_mapping import _manifest, _request


_AUTHORITY_PATCHER = patch(
    "lead_factory.bitrix_rest.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class _Response:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self.body = {} if body is None else body

    def json(self):
        return self.body


class _Session:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.created_fields: dict = {}
        self.ambiguous_create = False

    def request(self, _http_method, url, **kwargs):
        method = url.rsplit("/", 1)[-1].removesuffix(".json")
        payload = kwargs["json"]
        self.calls.append((method, payload))
        if method == "crm.company.add":
            self.created_fields = dict(payload["fields"])
            if self.ambiguous_create:
                return _Response(status_code=503, body={})
            return _Response(body={"result": "91"})
        if method == "crm.company.list":
            correlation_field, token = next(iter(payload["filter"].items()))
            field = correlation_field.removeprefix("=")
            return _Response(
                body={
                    "result": [{"ID": "91", field: token}],
                    "total": 1,
                }
            )
        if method == "crm.company.get":
            return _Response(body={"result": {"ID": "91", **self.created_fields}})
        raise AssertionError(method)


class BitrixGraphRuntimeTests(unittest.TestCase):
    webhook = "https://example.bitrix24.ru/rest/7/secret-webhook-value"

    def composition(self, *, enabled=False):
        session = _Session()
        transport = BitrixRestBoundary(webhook_url=self.webhook, session=session)
        raw_manifest = replace(
            _manifest(),
            portal_identity=transport.portal_fingerprint,
            declared_manifest_hash="",
        )
        manifest = replace(
            raw_manifest,
            declared_manifest_hash=graph_mapping_manifest_hash(raw_manifest),
        )
        mapper = BitrixGraphMapper(manifest)
        plan = mapper.compile_create(_request(COMPANY_CREATE, mapper.manifest_hash))
        report = BitrixGraphLivePreflightReport(
            live_preflight_ok=True,
            checks=("GREEN",),
            error_code="",
            manifest_hash=mapper.manifest_hash,
            portal_identity=transport.portal_fingerprint,
            read_calls_performed=1,
            external_writes_performed=0,
            required_field_count=57,
            correlation_probe_totals=(("company", 0), ("contact", 0), ("deal", 0)),
            credential_owner_bound=True,
            credential_isolation_limited=True,
            owner_approval_required=True,
            canary_ready=False,
            report_hash="a" * 64,
        )
        controller = BitrixGraphWriterController(
            BitrixGraphWriteBoundary(transport),
            mapper,
            report,
            writer_enabled=enabled,
        )
        raw = BitrixGraphWritePermit(
            manifest_hash=mapper.manifest_hash,
            live_preflight_report_hash=report.report_hash,
            operation_id=plan.operation_id,
            mapped_plan_hash=plan.plan_hash,
            canary_step=1,
            owner_approval_ref="owner-approval:test-only",
            declared_permit_hash="",
        )
        permit = replace(raw, declared_permit_hash=bitrix_graph_write_permit_hash(raw))
        return session, controller, plan, permit

    def test_default_off_denies_before_http(self):
        session, controller, plan, permit = self.composition()
        with self.assertRaises(BitrixGraphWriterDisabled):
            controller.execute(plan, permit)
        self.assertEqual(session.calls, [])

    def test_enabled_exact_permit_creates_gets_and_verifies_once(self):
        session, controller, plan, permit = self.composition(enabled=True)
        readback = controller.execute(plan, permit)
        self.assertTrue(readback.readback_verified)
        self.assertEqual(readback.remote_id, "91")
        self.assertEqual(
            [method for method, _payload in session.calls],
            ["crm.company.add", "crm.company.get"],
        )
        with self.assertRaises(BitrixGraphRuntimeError):
            controller.execute(plan, permit)
        self.assertEqual(len(session.calls), 2)

    def test_ambiguous_nonactivity_create_reconciles_without_second_add(self):
        session, controller, plan, permit = self.composition(enabled=True)
        session.ambiguous_create = True
        readback = controller.execute(plan, permit)
        self.assertTrue(readback.readback_verified)
        self.assertEqual(
            [method for method, _payload in session.calls],
            ["crm.company.add", "crm.company.list", "crm.company.get"],
        )

    def test_tampered_permit_and_direct_boundary_write_fail_before_http(self):
        session, controller, plan, permit = self.composition(enabled=True)
        with self.assertRaises(BitrixGraphRuntimeError):
            controller.execute(plan, replace(permit, canary_step=5))
        self.assertEqual(session.calls, [])

        boundary = controller._boundary
        with self.assertRaises(BitrixGraphRuntimeError):
            boundary.create(
                "crm.company.add",
                {"fields": {}},
                permit_hash=permit.declared_permit_hash,
                capability=None,  # type: ignore[arg-type]
            )
        self.assertEqual(session.calls, [])


if __name__ == "__main__":
    unittest.main()
