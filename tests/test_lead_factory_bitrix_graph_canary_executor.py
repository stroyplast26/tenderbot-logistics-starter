from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch
import unittest

from lead_factory.bitrix_graph_canary_executor import BitrixGraphCanaryExecutor
from lead_factory.bitrix_graph_canary_runtime import (
    BitrixGraphCanaryOutcomeUncertain,
    SealedBitrixGraphCanaryTransport,
)
from lead_factory.bitrix_graph_mapping import (
    BitrixGraphMapper,
    graph_mapping_manifest_hash,
)
from lead_factory.bitrix_rate_gate import BitrixPortalRateGate
from lead_factory.bitrix_rest import BitrixRestBoundary
from lead_factory.crm_graph_outbox import CrmGraphReadback
from tests import test_lead_factory_bitrix_graph_canary_control as control_fixture
from tests.test_lead_factory_bitrix_graph_mapping import _manifest


class _UnusedSession:
    def request(self, *_args, **_kwargs):  # pragma: no cover - safety tripwire
        raise AssertionError("executor unit test must not cross an HTTP boundary")


class BitrixGraphCanaryExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = control_fixture.BitrixGraphCanaryControlTests("runTest")
        self.fixture.setUp()
        self.run_id, _evidence = self.fixture.activate()
        self.lease = self.fixture.control.acquire_writer_lease(
            self.run_id, owner_id="executor-test", lease_seconds=300
        )
        boundary = BitrixRestBoundary(
            webhook_url="https://example.bitrix24.ru/rest/7/unit-test-secret",
            session=_UnusedSession(),
        )
        raw = replace(
            _manifest(),
            portal_identity=boundary.portal_fingerprint,
            declared_manifest_hash="",
        )
        manifest = replace(
            raw, declared_manifest_hash=graph_mapping_manifest_hash(raw)
        )
        transport = SealedBitrixGraphCanaryTransport(
            self.fixture.store,
            rate_gate=BitrixPortalRateGate(
                self.fixture.store,
                portal_identity=boundary.portal_fingerprint,
            ),
            rest_boundary=boundary,
            mapper=BitrixGraphMapper(manifest),
        )
        self.executor = BitrixGraphCanaryExecutor(self.fixture.control, transport)

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def test_sealed_dependencies_reject_subclasses(self) -> None:
        derived_control = type(
            "DerivedBitrixGraphCanaryControl", (type(self.fixture.control),), {}
        )
        derived_transport = type(
            "DerivedSealedBitrixGraphCanaryTransport",
            (SealedBitrixGraphCanaryTransport,),
            {},
        )
        with self.assertRaises(TypeError):
            BitrixGraphCanaryExecutor(
                object.__new__(derived_control), self.executor._transport
            )
        with self.assertRaises(TypeError):
            BitrixGraphCanaryExecutor(
                self.fixture.control, object.__new__(derived_transport)
            )

    @staticmethod
    def _readback(request, *_args, **_kwargs):
        dependencies = dict(request.dependency_remote_ids)
        return CrmGraphReadback(
            remote_entity_type=request.remote_entity_type,
            remote_id="101",
            correlation_token=request.correlation_token,
            readback_verified=True,
            company_remote_id=dependencies.get("company", ""),
            contact_remote_id=dependencies.get("contact", ""),
            deal_remote_id=dependencies.get("deal", ""),
        )

    def test_success_is_durably_sent_and_advances_only_one_operation(self) -> None:
        with patch.object(
            SealedBitrixGraphCanaryTransport,
            "execute",
            autospec=True,
            side_effect=lambda _transport, request, **kwargs: self._readback(
                request, **kwargs
            ),
        ) as execute, patch.object(
            SealedBitrixGraphCanaryTransport,
            "assert_correlation_unused",
            autospec=True,
        ) as lookup:
            result = self.executor.execute_next(self.lease, actor="executor-test")
        self.assertEqual(result.state, "SENT")
        self.assertEqual(result.operation_id, self.fixture.plan.company_operation_id)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(
            self.fixture.operation_states(),
            ("SENT", "PENDING", "PENDING", "PENDING"),
        )

    def test_ambiguous_outcome_is_never_made_create_eligible_again(self) -> None:
        with patch.object(
            SealedBitrixGraphCanaryTransport,
            "execute",
            autospec=True,
            side_effect=BitrixGraphCanaryOutcomeUncertain(),
        ), patch.object(
            SealedBitrixGraphCanaryTransport,
            "assert_correlation_unused",
            autospec=True,
        ):
            result = self.executor.execute_next(self.lease, actor="executor-test")
        self.assertEqual(result.state, "UNCERTAIN")
        self.assertEqual(
            self.fixture.operation_states(),
            ("UNCERTAIN", "PENDING", "PENDING", "PENDING"),
        )
        self.assertIsNone(
            self.executor.execute_next(self.lease, actor="executor-test")
        )


if __name__ == "__main__":
    unittest.main()
