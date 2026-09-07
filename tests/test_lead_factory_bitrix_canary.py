from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.bitrix_canary import (
    BitrixCanaryConfig,
    BitrixCanaryPreflight,
    BitrixLeadCanaryAdapter,
    CorrelationReadbackMismatch,
    FixedIntervalRateGate,
    ReadbackUncertain,
)
from lead_factory.crm_outbox import (
    AmbiguousRemoteError,
    MappingConflict,
    PermanentRemoteError,
    RetryableRemoteError,
)
from lead_factory.store import FactoryStore


_AUTHORITY_PATCHER = patch(
    "lead_factory.bitrix_canary.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class FakeRateGate:
    def __init__(self):
        self.calls = 0

    def reserve(self):
        self.calls += 1


class FakeRest:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def call(self, method, payload):
        self.calls.append((method, payload))
        if not self.responses:
            raise AssertionError("unexpected REST call")
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class BitrixCanaryAdapterTests(unittest.TestCase):
    field = "UF_CRM_123456789"
    token = "lf_evt_v1_fixture"

    def adapter(self, responses):
        self.rest = FakeRest(responses)
        self.rate = FakeRateGate()
        return BitrixLeadCanaryAdapter(
            self.rest, self.rate, BitrixCanaryConfig(self.field)
        )

    def test_create_whitelists_payload_and_requires_exact_readback(self):
        adapter = self.adapter([
            {"result": 501},
            {"result": {"ID": "501", self.field: self.token}},
        ])
        remote_id = adapter.create_lead(
            {
                "title": "Fixture",
                "company_title": "Company",
                "_lf_correlation_token": self.token,
            },
            self.token,
        )
        self.assertEqual(remote_id, "501")
        self.assertEqual(self.rate.calls, 2)
        method, request = self.rest.calls[0]
        self.assertEqual(method, "crm.lead.add")
        self.assertEqual(request["fields"][self.field], self.token)
        self.assertNotIn("_lf_correlation_token", request["fields"])
        self.assertEqual(request["params"]["REGISTER_SONET_EVENT"], "N")

    def test_non_whitelisted_payload_never_reaches_rest(self):
        adapter = self.adapter([])
        with self.assertRaises(PermanentRemoteError):
            adapter.create_lead({"SECRET_FIELD": "x"}, self.token)
        self.assertEqual(self.rest.calls, [])

    def test_add_success_then_readback_timeout_is_ambiguous(self):
        adapter = self.adapter([{"result": "502"}, TimeoutError("redacted")])
        with self.assertRaises(ReadbackUncertain) as caught:
            adapter.create_lead({"title": "Fixture"}, self.token)
        self.assertEqual(caught.exception.remote_id, "502")
        self.assertEqual([call[0] for call in self.rest.calls], ["crm.lead.add", "crm.lead.get"])

    def test_add_success_then_any_readback_error_keeps_remote_id(self):
        adapter = self.adapter([
            {"result": "504"},
            {"error": "ACCESS_DENIED", "error_description": "private"},
        ])
        with self.assertRaises(ReadbackUncertain) as caught:
            adapter.create_lead({"title": "Fixture"}, self.token)
        self.assertEqual(caught.exception.remote_id, "504")
        self.assertNotIn("private", str(caught.exception))

    def test_wrong_readback_is_mapping_conflict_with_suspect_id(self):
        adapter = self.adapter([
            {"result": "503"},
            {"result": {"ID": "503", self.field: "different"}},
        ])
        with self.assertRaises(CorrelationReadbackMismatch) as caught:
            adapter.create_lead({"title": "Fixture"}, self.token)
        self.assertEqual(caught.exception.remote_id, "503")

    def test_readback_must_return_the_same_remote_id(self):
        adapter = self.adapter([
            {"result": "505"},
            {"result": {"ID": "999", self.field: self.token}},
        ])
        with self.assertRaises(CorrelationReadbackMismatch) as caught:
            adapter.create_lead({"title": "Fixture"}, self.token)
        self.assertEqual(caught.exception.remote_id, "505")

    def test_lookup_zero_one_and_duplicate(self):
        zero = self.adapter([{"result": [], "total": 0}])
        self.assertIsNone(zero.find_lead_by_correlation_token(self.token))
        one = self.adapter([{"result": [{"ID": "601", self.field: self.token}], "total": 1}])
        self.assertEqual(one.find_lead_by_correlation_token(self.token), "601")
        duplicate = self.adapter([{"result": [
            {"ID": "601", self.field: self.token},
            {"ID": "602", self.field: self.token},
        ]}])
        with self.assertRaises(MappingConflict):
            duplicate.find_lead_by_correlation_token(self.token)
        incomplete = self.adapter([{
            "result": [{"ID": "601", self.field: self.token}],
            "total": 2,
            "next": 50,
        }])
        with self.assertRaises(MappingConflict):
            incomplete.find_lead_by_correlation_token(self.token)

    def test_lookup_requires_total_metadata_to_prove_completeness(self):
        missing_total = self.adapter([{"result": []}])
        with self.assertRaises(MappingConflict):
            missing_total.find_lead_by_correlation_token(self.token)

    def test_provider_error_matrix_is_typed_without_payload_in_error(self):
        for code in ("QUERY_LIMIT_EXCEEDED", "OPERATION_TIME_LIMIT"):
            retry = self.adapter([{"error": code, "error_description": "private"}])
            with self.assertRaises(RetryableRemoteError) as caught:
                retry.find_lead_by_correlation_token(self.token)
            self.assertNotIn("private", str(caught.exception))
        for code in ("ACCESS_DENIED", "ERROR_ARGUMENT"):
            permanent = self.adapter([{"error": code, "error_description": "private"}])
            with self.assertRaises(PermanentRemoteError) as caught:
                permanent.find_lead_by_correlation_token(self.token)
            self.assertNotIn("private", str(caught.exception))
        for code in (
            "INTERNAL_SERVER_ERROR",
            "ERROR_UNEXPECTED_ANSWER",
            "OVERLOAD_LIMIT",
            "UNCLASSIFIED_PROVIDER_ERROR",
        ):
            ambiguous = self.adapter([{"error": code, "error_description": "private"}])
            with self.assertRaises(AmbiguousRemoteError) as caught:
                ambiguous.find_lead_by_correlation_token(self.token)
            self.assertNotIn("private", str(caught.exception))

    def test_fixed_rate_gate_reserves_gap_without_real_sleep(self):
        now = [0.0]
        sleeps = []

        def clock():
            return now[0]

        def sleeper(value):
            sleeps.append(value)
            now[0] += value

        gate = FixedIntervalRateGate(interval_seconds=1.0, clock=clock, sleeper=sleeper)
        gate.reserve()
        gate.reserve()
        gate.reserve()
        self.assertEqual(sleeps, [1.0, 1.0])


class BitrixCanaryPreflightTests(unittest.TestCase):
    field = "UF_CRM_987654321"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "preflight.sqlite3")
        self.store.init()

    def tearDown(self):
        self.temp.cleanup()

    def preflight(self, responses):
        rest = FakeRest(responses)
        rate = FakeRateGate()
        check = BitrixCanaryPreflight(
            self.store, rest, rate, BitrixCanaryConfig(self.field)
        )
        return check, rest

    def test_preflight_passes_read_only_and_keeps_writers_off(self):
        check, rest = self.preflight([
            {"result": [{
                "FIELD_NAME": self.field,
                "USER_TYPE_ID": "string",
                "MULTIPLE": "N",
                "MANDATORY": "N",
            }], "total": 1},
            {"result": {self.field: {"type": "string"}}},
            {"result": [], "total": 0},
        ])
        result = check.run(unused_correlation_token="lf_evt_v1_unused")
        self.assertTrue(result.ok)
        self.assertNotIn("crm.lead.add", [call[0] for call in rest.calls])
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
                ).fetchone()[0],
                "0",
            )
        finally:
            con.close()

    def test_preflight_fails_closed_on_missing_field(self):
        check, rest = self.preflight([{"result": [], "total": 0}])
        result = check.run(unused_correlation_token="lf_evt_v1_unused")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "CORRELATION_FIELD_COUNT")
        self.assertEqual([call[0] for call in rest.calls], ["crm.lead.userfield.list"])

    def test_preflight_fails_closed_when_userfield_total_is_missing(self):
        check, rest = self.preflight([{"result": [{
            "FIELD_NAME": self.field,
            "USER_TYPE_ID": "string",
            "MULTIPLE": "N",
            "MANDATORY": "N",
        }]}])
        result = check.run(unused_correlation_token="lf_evt_v1_unused")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "USERFIELD_LIST_INCOMPLETE")
        self.assertEqual([call[0] for call in rest.calls], ["crm.lead.userfield.list"])

    def test_preflight_rejects_blank_token_without_rest(self):
        check, rest = self.preflight([])
        result = check.run(unused_correlation_token="")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "CANARY_TOKEN_INVALID")
        self.assertEqual(rest.calls, [])

    def test_preflight_refuses_to_run_if_writers_are_enabled(self):
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )
        check, rest = self.preflight([])
        result = check.run(unused_correlation_token="lf_evt_v1_unused")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "WRITER_NOT_DISABLED")
        self.assertEqual(rest.calls, [])

    def test_preflight_requires_an_empty_local_crm_queue(self):
        company, _ = self.store.create_company(name="Fixture", inn="7701000001")
        project, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"], source="fixture", external_key="p1"
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            lf_project_id=project["lf_project_id"],
            source="fixture",
            external_key="o1",
        )
        from lead_factory.crm_outbox import CrmOutbox

        CrmOutbox(self.store).enqueue_lead_create(
            lf_entity_id=opportunity["lf_opportunity_id"],
            external_event_id="fixture:event",
            payload={"title": "Fixture"},
        )
        check, rest = self.preflight([])
        result = check.run(unused_correlation_token="lf_evt_v1_unused")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "CRM_OUTBOX_NOT_EMPTY")
        self.assertEqual(rest.calls, [])


if __name__ == "__main__":
    unittest.main()
