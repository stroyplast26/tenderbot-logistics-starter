from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.bitrix_canary import BitrixCanaryConfig, BitrixCanaryPreflight
from lead_factory.bitrix_preflight_runtime import (
    BitrixPreflightCompositionError,
    SealedBitrixCanaryPreflightRuntime,
    _PreflightRateRequest,
)
from lead_factory.bitrix_rate_gate import BitrixPortalRateGate
from lead_factory.bitrix_rest import READ_ONLY_PREFLIGHT_METHODS, BitrixRestBoundary
from lead_factory.crm_outbox import AmbiguousRemoteError, CrmOutbox
from lead_factory.store import FactoryStore
from lead_factory.windows_canary_quiesce import ReversibleWindowsQuiesce
from lead_factory.windows_canary_readiness import (
    WindowsCanaryReadinessReport,
    WindowsReadinessComponent,
)


_AUTHORITY_PATCHERS = (
    patch("lead_factory.bitrix_canary.assert_external_allowed", return_value=None),
    patch("lead_factory.bitrix_rest.assert_external_allowed", return_value=None),
)


def setUpModule():
    for patcher in _AUTHORITY_PATCHERS:
        patcher.start()


def tearDownModule():
    for patcher in reversed(_AUTHORITY_PATCHERS):
        patcher.stop()


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)
        self.sleeps: list[float] = []

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += timedelta(seconds=seconds)


class _Response:
    def __init__(self, body, *, status_code: int = 200) -> None:
        self.status_code = status_code
        self.body = body

    def json(self):
        return self.body


class _Session:
    def __init__(self, *bodies) -> None:
        self.bodies = list(bodies)
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        body = self.bodies.pop(0)
        if isinstance(body, BaseException):
            raise body
        if isinstance(body, _Response):
            return body
        return _Response(body)


class _StoreSubclass(FactoryStore):
    pass


class _GateSubclass(BitrixPortalRateGate):
    pass


class _BoundarySubclass(BitrixRestBoundary):
    pass


class _ConfigSubclass(BitrixCanaryConfig):
    pass


class _QuiesceProvider:
    def __init__(self):
        self.calls = []

    def capture(self):
        self.calls.append("capture")
        return object()

    def quiesce(self, receipt):
        self.calls.append("quiesce")

    def readiness(self):
        self.calls.append("readiness")
        return WindowsCanaryReadinessReport(
            ok=True,
            components=(WindowsReadinessComponent("fixture", "absent"),),
        )

    def restore(self, receipt):
        self.calls.append("restore")


class BitrixPreflightRuntimeTests(unittest.TestCase):
    field = "UF_CRM_LF_CORRELATION"
    webhook = "https://private-portal.example/rest/123/private-webhook-token"
    unused_token = "lf_evt_v1_0123456789abcdef0123456789abcdef01234567"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "stage.sqlite3")
        self.store.init()
        self.default_path_patch = patch(
            "lead_factory.bitrix_preflight_runtime.DEFAULT_DB_PATH",
            Path(self.store.path),
        )
        self.default_path_patch.start()
        self.clock = _Clock()

    def tearDown(self) -> None:
        self.default_path_patch.stop()
        self.temp.cleanup()

    def _boundary(self, session: _Session, *, webhook: str | None = None):
        return BitrixRestBoundary(
            webhook_url=webhook or self.webhook,
            session=session,
        )

    def _gate(
        self,
        boundary: BitrixRestBoundary,
        *,
        store: FactoryStore | None = None,
        identity: str | None = None,
    ) -> BitrixPortalRateGate:
        return BitrixPortalRateGate(
            store or self.store,
            portal_identity=identity or boundary.portal_fingerprint,
            clock=self.clock,
            sleeper=self.clock.sleep,
        )

    @classmethod
    def _config(cls) -> BitrixCanaryConfig:
        return BitrixCanaryConfig(correlation_field=cls.field)

    def _runtime(self, session: _Session):
        boundary = self._boundary(session)
        return SealedBitrixCanaryPreflightRuntime(
            self.store,
            rate_gate=self._gate(boundary),
            rest_boundary=boundary,
            config=self._config(),
        )

    def _happy_session(self) -> _Session:
        return _Session(
            {
                "result": [
                    {
                        "FIELD_NAME": self.field,
                        "USER_TYPE_ID": "string",
                        "MULTIPLE": "N",
                        "MANDATORY": "N",
                    }
                ],
                "total": 1,
            },
            {"result": {self.field: {"type": "string"}}},
            {"result": [], "total": 0},
        )

    @staticmethod
    def _called_methods(session: _Session) -> list[str]:
        return [
            str(url).rsplit("/", 1)[-1].removesuffix(".json")
            for _, url, _ in session.calls
        ]

    def test_happy_path_uses_existing_preflight_and_keeps_writer_off(self):
        session = self._happy_session()
        runtime = self._runtime(session)

        original_run = BitrixCanaryPreflight.run
        invoked: list[BitrixCanaryPreflight] = []

        def _traced_run(preflight, *, unused_correlation_token):
            invoked.append(preflight)
            return original_run(
                preflight, unused_correlation_token=unused_correlation_token
            )

        with patch.object(BitrixCanaryPreflight, "run", _traced_run):
            report = runtime.run(unused_correlation_token=self.unused_token)

        self.assertTrue(report.ok)
        self.assertEqual(
            report.checks,
            (
                "WRITER_DISABLED",
                "CRM_OUTBOX_EMPTY",
                "CORRELATION_FIELD_VALID",
                "CORRELATION_FIELD_READABLE",
                "CANARY_TOKEN_UNUSED",
            ),
        )
        self.assertEqual(invoked, [runtime._preflight])
        self.assertEqual(
            self._called_methods(session),
            [
                "crm.lead.userfield.list",
                "crm.lead.fields",
                "crm.lead.list",
            ],
        )
        con = self.store.connect()
        try:
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(writer, "0")
        self.assertEqual(
            repr(runtime), "SealedBitrixCanaryPreflightRuntime(read_only=True)"
        )

    def test_verified_windows_quiesce_brackets_the_only_preflight_attempt(self):
        session = self._happy_session()
        runtime = self._runtime(session)
        provider = _QuiesceProvider()

        report = runtime.run_inside_windows_quiesce(
            quiesce=ReversibleWindowsQuiesce(provider),
            unused_correlation_token=self.unused_token,
        )

        self.assertTrue(report.ok)
        self.assertEqual(
            provider.calls, ["capture", "quiesce", "readiness", "restore"]
        )
        self.assertEqual(
            self._called_methods(session),
            [
                "crm.lead.userfield.list",
                "crm.lead.fields",
                "crm.lead.list",
            ],
        )

    def test_quiesce_entrypoint_rejects_a_lookalike(self):
        runtime = self._runtime(self._happy_session())
        with self.assertRaises(BitrixPreflightCompositionError):
            runtime.run_inside_windows_quiesce(
                quiesce=object(),
                unused_correlation_token=self.unused_token,
            )

    def test_split_store_keeps_canonical_schema13_byte_identical(self):
        canonical_path = Path(self.temp.name) / "canonical-schema13.sqlite3"
        con = sqlite3.connect(canonical_path)
        con.executescript(
            """
            CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO schema_meta VALUES('schema_version','13');
            INSERT INTO schema_meta VALUES('external_writers_enabled','0');
            CREATE TABLE crm_outbox(state TEXT NOT NULL);
            """
        )
        con.commit()
        con.close()
        canonical_before = canonical_path.read_bytes()
        audit_store = FactoryStore(Path(self.temp.name) / "preflight-audit.sqlite3")
        audit_store.init()
        session = self._happy_session()
        boundary = self._boundary(session)

        with patch(
            "lead_factory.bitrix_preflight_runtime.DEFAULT_DB_PATH",
            canonical_path,
        ):
            runtime = SealedBitrixCanaryPreflightRuntime(
                audit_store,
                rate_gate=self._gate(boundary, store=audit_store),
                rest_boundary=boundary,
                config=self._config(),
                canonical_stage_path=canonical_path,
            )
            report = runtime.run(unused_correlation_token=self.unused_token)

        self.assertTrue(report.ok)
        self.assertEqual(canonical_path.read_bytes(), canonical_before)
        self.assertFalse(Path(str(canonical_path) + "-wal").exists())
        self.assertFalse(Path(str(canonical_path) + "-shm").exists())
        audit = audit_store.connect()
        try:
            self.assertEqual(
                audit.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE producer='bitrix_canary_preflight_runtime'"
                ).fetchone()[0],
                3,
            )
        finally:
            audit.close()

    def test_composition_rejects_wrong_database_portal_and_concrete_types(self):
        session = _Session()
        boundary = self._boundary(session)
        gate = self._gate(boundary)
        config = self._config()

        wrong_store = FactoryStore(Path(self.temp.name) / "wrong.sqlite3")
        wrong_store.init()
        with self.assertRaises(BitrixPreflightCompositionError):
            SealedBitrixCanaryPreflightRuntime(
                wrong_store,
                rate_gate=self._gate(boundary, store=wrong_store),
                rest_boundary=boundary,
                config=config,
            )
        with self.assertRaises(BitrixPreflightCompositionError):
            SealedBitrixCanaryPreflightRuntime(
                self.store,
                rate_gate=self._gate(boundary, store=wrong_store),
                rest_boundary=boundary,
                config=config,
            )
        with self.assertRaises(BitrixPreflightCompositionError):
            SealedBitrixCanaryPreflightRuntime(
                self.store,
                rate_gate=self._gate(boundary, identity="another-portal"),
                rest_boundary=boundary,
                config=config,
            )

        bad_store = _StoreSubclass(self.store.path)
        bad_gate = _GateSubclass(
            self.store,
            portal_identity=boundary.portal_fingerprint,
            clock=self.clock,
            sleeper=self.clock.sleep,
        )
        bad_boundary = _BoundarySubclass(webhook_url=self.webhook, session=session)
        bad_config = _ConfigSubclass(correlation_field=self.field)
        exact_cases = (
            (bad_store, gate, boundary, config),
            (self.store, bad_gate, boundary, config),
            (self.store, gate, bad_boundary, config),
            (self.store, gate, boundary, bad_config),
        )
        for (
            candidate_store,
            candidate_gate,
            candidate_boundary,
            candidate_config,
        ) in exact_cases:
            with self.subTest(
                store_type=type(candidate_store).__name__,
                gate_type=type(candidate_gate).__name__,
                boundary_type=type(candidate_boundary).__name__,
                config_type=type(candidate_config).__name__,
            ):
                with self.assertRaises(BitrixPreflightCompositionError):
                    SealedBitrixCanaryPreflightRuntime(
                        candidate_store,
                        rate_gate=candidate_gate,
                        rest_boundary=candidate_boundary,
                        config=candidate_config,
                    )
        self.assertEqual(session.calls, [])

    def test_post_construction_gate_store_mutation_blocks_before_http(self):
        session = self._happy_session()
        boundary = self._boundary(session)
        gate = self._gate(boundary)
        runtime = SealedBitrixCanaryPreflightRuntime(
            self.store,
            rate_gate=gate,
            rest_boundary=boundary,
            config=self._config(),
        )
        alternate = FactoryStore(Path(self.temp.name) / "alternate.sqlite3")
        alternate.init()

        gate.store = alternate
        report = runtime.run(unused_correlation_token=self.unused_token)

        self.assertFalse(report.ok)
        self.assertEqual(report.error_code, "REMOTE_AMBIGUOUS")
        self.assertEqual(session.calls, [])
        self.assertEqual(self.store.table_count("bitrix_rate_reservations"), 0)
        self.assertEqual(alternate.table_count("bitrix_rate_reservations"), 0)

    def test_post_construction_portal_mutation_blocks_before_http(self):
        session = self._happy_session()
        boundary = self._boundary(session)
        gate = self._gate(boundary)
        runtime = SealedBitrixCanaryPreflightRuntime(
            self.store,
            rate_gate=gate,
            rest_boundary=boundary,
            config=self._config(),
        )

        gate.portal_identity = "mutated-portal"
        report = runtime.run(unused_correlation_token=self.unused_token)

        self.assertFalse(report.ok)
        self.assertEqual(report.error_code, "REMOTE_AMBIGUOUS")
        self.assertEqual(session.calls, [])
        self.assertEqual(self.store.table_count("bitrix_rate_reservations"), 0)

    def test_public_composition_has_no_transport_or_generic_rest_surface(self):
        parameters = inspect.signature(
            SealedBitrixCanaryPreflightRuntime.__init__
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "self",
                "store",
                "rate_gate",
                "rest_boundary",
                "config",
                "canonical_stage_path",
            ),
        )
        self.assertNotIn("session", parameters)
        self.assertNotIn("transport", parameters)
        self.assertEqual(
            READ_ONLY_PREFLIGHT_METHODS,
            frozenset(
                {
                    "crm.lead.userfield.list",
                    "crm.lead.fields",
                    "crm.lead.list",
                }
            ),
        )

    def test_write_and_unknown_methods_cannot_cross_sealed_preflight(self):
        for method in ("crm.lead.add", "crm.activity.get", "batch", "crm.lead.delete"):
            with self.subTest(method=method):
                session = _Session()
                runtime = self._runtime(session)

                def _attempt(preflight, *, unused_correlation_token):
                    return preflight.adapter._call(method, {"secret": unused_correlation_token})

                with patch.object(BitrixCanaryPreflight, "run", _attempt):
                    with self.assertRaises(AmbiguousRemoteError) as caught:
                        runtime.run(unused_correlation_token=self.unused_token)
                self.assertEqual(str(caught.exception), "Bitrix call outcome is ambiguous")
                self.assertEqual(session.calls, [])
                con = self.store.connect()
                try:
                    reservations = con.execute(
                        "SELECT COUNT(*) FROM bitrix_rate_reservations"
                    ).fetchone()[0]
                finally:
                    con.close()
                self.assertEqual(reservations, 0)
                self.assertFalse(hasattr(runtime, "call"))

    def test_writer_or_nonempty_outbox_blocks_before_any_http(self):
        writer_session = _Session()
        writer_runtime = self._runtime(writer_session)
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )
        writer_report = writer_runtime.run(
            unused_correlation_token=self.unused_token
        )
        self.assertEqual(writer_report.error_code, "WRITER_NOT_DISABLED")
        self.assertEqual(writer_session.calls, [])
        con = self.store.connect()
        try:
            writer_after = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(writer_after, "1")

        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value='0' WHERE key='external_writers_enabled'"
            )
        company, _ = self.store.create_company(name="Fixture", inn="7701000001")
        project, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"],
            source="fixture",
            external_key="preflight-project",
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            lf_project_id=project["lf_project_id"],
            source="fixture",
            external_key="preflight-opportunity",
        )
        CrmOutbox(self.store).enqueue_lead_create(
            lf_entity_id=opportunity["lf_opportunity_id"],
            external_event_id="fixture:preflight",
            payload={"title": "Fixture"},
        )
        outbox_session = _Session()
        outbox_runtime = self._runtime(outbox_session)
        outbox_report = outbox_runtime.run(
            unused_correlation_token=self.unused_token
        )
        self.assertEqual(outbox_report.error_code, "CRM_OUTBOX_NOT_EMPTY")
        self.assertEqual(outbox_session.calls, [])

    def test_token_must_be_exact_opaque_event_id_before_rate_or_http(self):
        invalid_tokens = (
            "",
            "lf_evt_v1_unused",
            "lf_evt_v1_" + "a" * 39,
            "lf_evt_v1_" + "a" * 41,
            "lf_evt_v1_" + "A" * 40,
            " " + self.unused_token,
            self.unused_token + "\n",
            "buyer+private@example.test",
        )
        for invalid_token in invalid_tokens:
            with self.subTest(token_length=len(invalid_token)):
                session = self._happy_session()
                report = self._runtime(session).run(
                    unused_correlation_token=invalid_token
                )
                self.assertFalse(report.ok)
                self.assertEqual(report.error_code, "CANARY_TOKEN_INVALID")
                self.assertEqual(session.calls, [])
        self.assertEqual(self.store.table_count("bitrix_rate_reservations"), 0)

    def test_writer_change_after_local_check_is_blocked_at_dispatch_barrier(self):
        session = self._happy_session()
        runtime = self._runtime(session)
        original_reserve = _PreflightRateRequest.reserve

        def _enable_writer_then_reserve(rate_request):
            with self.store.transaction() as con:
                con.execute(
                    "UPDATE schema_meta SET value='1' "
                    "WHERE key='external_writers_enabled'"
                )
            return original_reserve(rate_request)

        with patch.object(_PreflightRateRequest, "reserve", _enable_writer_then_reserve):
            report = runtime.run(unused_correlation_token=self.unused_token)

        self.assertFalse(report.ok)
        self.assertEqual(report.error_code, "REMOTE_AMBIGUOUS")
        self.assertEqual(session.calls, [])
        con = self.store.connect()
        try:
            reservation = con.execute(
                "SELECT state FROM bitrix_rate_reservations"
            ).fetchone()
            audit_count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE producer='bitrix_canary_preflight_runtime'"""
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(reservation["state"], "BLOCKED")
        self.assertEqual(audit_count, 0)

    def test_every_http_read_is_rate_gated_and_safely_audited(self):
        session = self._happy_session()
        report = self._runtime(session).run(
            unused_correlation_token=self.unused_token
        )
        self.assertTrue(report.ok)

        con = self.store.connect()
        try:
            reservations = con.execute(
                """SELECT reservation_id,portal_identity,fence_token,sequence_number,state
                   FROM bitrix_rate_reservations ORDER BY sequence_number"""
            ).fetchall()
            events = con.execute(
                """SELECT aggregate_id,payload_json FROM events
                   WHERE producer='bitrix_canary_preflight_runtime'"""
            ).fetchall()
        finally:
            con.close()
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(len(reservations), 3)
        self.assertEqual([row["state"] for row in reservations], ["DISPATCHED"] * 3)
        self.assertEqual([row["sequence_number"] for row in reservations], [1, 2, 3])
        self.assertEqual(self.clock.sleeps, [1.0, 1.0])
        self.assertEqual(len(events), 3)
        audited = sorted(
            (json.loads(row["payload_json"]) for row in events),
            key=lambda value: value["read_number"],
        )
        self.assertTrue(
            all(
                set(value)
                == {
                    "portal_identity",
                    "fence_token",
                    "reservation_id",
                    "sequence_number",
                    "preflight_run_id",
                    "read_number",
                    "method",
                }
                for value in audited
            )
        )
        self.assertEqual(
            [value["method"] for value in audited], self._called_methods(session)
        )
        self.assertEqual([value["read_number"] for value in audited], [1, 2, 3])
        self.assertEqual(
            {value["reservation_id"] for value in audited},
            {row["reservation_id"] for row in reservations},
        )
        self.assertEqual(len({value["preflight_run_id"] for value in audited}), 1)
        self.assertTrue(
            next(iter({value["preflight_run_id"] for value in audited})).startswith(
                "lf_bitrix_preflight_"
            )
        )

    def test_events_and_errors_never_contain_payload_pii_or_webhook(self):
        pii_token = "buyer+private@example.test"
        provider_secret = "PRIVATE_PROVIDER_DESCRIPTION_789"
        session = _Session(
            {
                "error": "PRIVATE_UNKNOWN_CODE",
                "error_description": provider_secret,
                "result": [{"email": pii_token}],
            }
        )
        runtime = self._runtime(session)
        report = runtime.run(unused_correlation_token=self.unused_token)
        self.assertFalse(report.ok)
        self.assertEqual(report.error_code, "REMOTE_AMBIGUOUS")

        con = self.store.connect()
        try:
            event_rows = [
                dict(row)
                for row in con.execute(
                    "SELECT * FROM events ORDER BY recorded_at_utc,event_id"
                ).fetchall()
            ]
        finally:
            con.close()
        evidence = json.dumps(event_rows, ensure_ascii=False, sort_keys=True)
        error_text = repr(report) + " " + repr(runtime)
        for secret in (
            pii_token,
            self.unused_token,
            provider_secret,
            "private-portal.example",
            "private-webhook-token",
            self.field,
        ):
            self.assertNotIn(secret, evidence)
            self.assertNotIn(secret, error_text)
        self.assertEqual(len(session.calls), 1)


if __name__ == "__main__":
    unittest.main()
