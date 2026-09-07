from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from unittest.mock import patch

from lead_factory.bitrix_graph_canary_runtime import (
    SealedBitrixGraphCanaryTransport,
)
from lead_factory.bitrix_graph_mapping import (
    BitrixGraphMapper,
    graph_mapping_manifest_hash,
)
from lead_factory.bitrix_rate_gate import BitrixPortalRateGate, BitrixRateGateClosed
from lead_factory.bitrix_rest import BitrixRestBoundary
from lead_factory.crm_graph_outbox import COMPANY_CREATE
from lead_factory.store import FactoryStore
from tests.test_lead_factory_bitrix_graph_mapping import _manifest, _request


_AUTHORITY_PATCHER = patch(
    "lead_factory.bitrix_rest.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class _Clock:
    def __init__(self):
        self.now = datetime(2026, 8, 22, 9, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += timedelta(seconds=float(seconds))


class _Response:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self.body = {} if body is None else body

    def json(self):
        return self.body


class _Session:
    def __init__(self):
        self.calls = []
        self.created_fields = {}
        self.ambiguous = False
        self.list_empty = False

    def request(self, _http_method, url, **kwargs):
        method = url.rsplit("/", 1)[-1].removesuffix(".json")
        payload = kwargs["json"]
        self.calls.append((method, payload))
        if method == "crm.company.add":
            self.created_fields = dict(payload["fields"])
            if self.ambiguous:
                return _Response(503, {})
            return _Response(body={"result": "91"})
        if method == "crm.company.list":
            if self.list_empty:
                return _Response(body={"result": [], "total": 0})
            key, token = next(iter(payload["filter"].items()))
            return _Response(
                body={"result": [{"ID": "91", key.removeprefix("="): token}], "total": 1}
            )
        if method == "crm.company.get":
            return _Response(body={"result": {"ID": "91", **self.created_fields}})
        raise AssertionError(method)


class SealedBitrixGraphCanaryTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(self.temp.name + "/control.sqlite3")
        self.store.init()
        self.clock = _Clock()
        self.session = _Session()
        self.webhook = "https://example.bitrix24.ru/rest/7/secret-value"
        self.boundary = BitrixRestBoundary(
            webhook_url=self.webhook, session=self.session
        )
        raw = replace(
            _manifest(),
            portal_identity=self.boundary.portal_fingerprint,
            declared_manifest_hash="",
        )
        manifest = replace(
            raw, declared_manifest_hash=graph_mapping_manifest_hash(raw)
        )
        self.mapper = BitrixGraphMapper(manifest)
        self.gate = BitrixPortalRateGate(
            self.store,
            portal_identity=self.boundary.portal_fingerprint,
            clock=self.clock,
            sleeper=self.clock.sleep,
        )
        self.transport = SealedBitrixGraphCanaryTransport(
            self.store,
            rate_gate=self.gate,
            rest_boundary=self.boundary,
            mapper=self.mapper,
        )
        self.request = replace(
            _request(COMPANY_CREATE, self.mapper.manifest_hash),
            operation_id="lf_crm_operation_" + "1" * 32,
        )

    def tearDown(self):
        self.temp.cleanup()

    def _validator(self, _reservation, con):
        row = con.execute(
            "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
        ).fetchone()
        if not row or row[0] != "1":
            raise BitrixRateGateClosed("writer cutover is not active")

    def _enable(self):
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )

    def test_default_off_validator_blocks_before_http(self):
        with self.assertRaises(BitrixRateGateClosed):
            self.transport.execute(
                self.request,
                permit_hash="a" * 64,
                create_validator=self._validator,
            )
        self.assertEqual(self.session.calls, [])

    def test_each_create_and_readback_gets_its_own_durable_rate_slot(self):
        self._enable()
        receipt = self.transport.execute(
            self.request,
            permit_hash="a" * 64,
            create_validator=self._validator,
        )
        self.assertTrue(receipt.readback_verified)
        self.assertEqual(receipt.remote_id, "91")
        self.assertEqual(
            [method for method, _ in self.session.calls],
            ["crm.company.add", "crm.company.get"],
        )
        with self.store.transaction() as con:
            states = [
                row[0]
                for row in con.execute(
                    "SELECT state FROM bitrix_rate_reservations ORDER BY sequence_number"
                )
            ]
            audits = con.execute(
                "SELECT COUNT(*) FROM events WHERE producer='bitrix_graph_canary_runtime'"
            ).fetchone()[0]
        self.assertEqual(states, ["DISPATCHED", "DISPATCHED"])
        self.assertEqual(audits, 2)

    def test_exact_correlation_is_checked_before_create(self):
        self._enable()
        self.session.list_empty = True
        self.transport.assert_correlation_unused(self.request)
        self.assertEqual(
            [method for method, _ in self.session.calls], ["crm.company.list"]
        )

    def test_ambiguous_create_reconciles_without_second_add(self):
        self._enable()
        self.session.ambiguous = True
        receipt = self.transport.execute(
            self.request,
            permit_hash="b" * 64,
            create_validator=self._validator,
        )
        self.assertTrue(receipt.readback_verified)
        self.assertEqual(
            [method for method, _ in self.session.calls],
            ["crm.company.add", "crm.company.list", "crm.company.get"],
        )
        self.assertEqual(
            sum(method == "crm.company.add" for method, _ in self.session.calls), 1
        )

    def test_repr_and_errors_do_not_expose_webhook(self):
        rendered = repr(self.transport)
        self.assertNotIn("secret-value", rendered)
        self.assertEqual(rendered, "SealedBitrixGraphCanaryTransport(<redacted>)")


if __name__ == "__main__":
    unittest.main()
