from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import lead_factory.bitrix_graph_mapping as graph_mapping
from lead_factory.bitrix_graph_mapping import (
    GRAPH_ACTIVITY_MARKER_VERSION,
    GRAPH_CONTRACT_VERSION,
    GRAPH_INPUT_CONTRACT_VERSION,
    GRAPH_MAPPING_EVIDENCE_MODE,
    GRAPH_MAPPING_LIFECYCLE,
    GRAPH_MAPPING_MANIFEST_VERSION,
    BitrixGraphBridgeBinding,
    BitrixGraphCorrelationField,
    BitrixGraphFieldBinding,
    BitrixGraphManifestMismatch,
    BitrixGraphMapper,
    BitrixGraphMappingError,
    BitrixGraphMappingManifest,
    BitrixGraphProviderConflict,
    BitrixGraphRoute,
    BitrixGraphSourceBinding,
    graph_mapping_manifest_hash,
    validate_graph_mapping_manifest,
)
from lead_factory.bitrix_graph_canary import (
    BitrixGraphCanaryActivationDenied,
    BitrixGraphCanaryError,
    prepare_bitrix_graph_offline_canary,
)
from lead_factory.bitrix_graph_preflight import (
    GRAPH_SCHEMA_SNAPSHOT_VERSION,
    BitrixGraphCapabilityFact,
    BitrixGraphCorrelationProbe,
    BitrixGraphFieldFact,
    BitrixGraphPreflightError,
    BitrixGraphRouteFact,
    BitrixGraphSchemaSnapshot,
    graph_schema_snapshot_hash,
    run_bitrix_graph_offline_preflight,
    validate_graph_schema_snapshot,
)
from lead_factory.crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphCreateRequest,
    CrmGraphOutbox,
    SafeReconciliationUnsupported,
)
from lead_factory.ids import payload_hash
from lead_factory.store import FactoryStore


_AUTHORITY_PATCHER = patch(
    "lead_factory.crm_graph_outbox.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


_PORTAL_IDENTITY = "bitrix-host-v1:" + "1" * 64
_SOURCE_ID = "wave1:tenderplan"
_COMPANY_ID = "cmp_0001"
_CONTACT_ID = "con_0001"
_PROJECT_ID = "prj_0001"
_OPPORTUNITY_ID = "opp_0001"
_SOURCE_EVENT_ID = "evt_graph_0001"
_EXPECTED_MANIFEST_HASH = (
    "1b0cf02c1804d42ae94c5d59b597d495c2a122612521d4487cf200450a8a449f"
)
_EXPECTED_SNAPSHOT_HASH = (
    "5c4d755d782b146c64adcecf780f7132b3eb424adf45672f9fc79bedab12fc66"
)

_CAPABILITIES = (
    "activity.deal_owner_readback",
    "activity.description_marker_readback",
    "activity.get",
    "activity.mapped_fields_readback",
    "activity.route_fields_readback",
    "company.correlation_lookup",
    "company.get",
    "company.mapped_fields_readback",
    "contact.company_readback",
    "contact.correlation_lookup",
    "contact.get",
    "contact.mapped_fields_readback",
    "deal.company_contact_readback",
    "deal.correlation_lookup",
    "deal.get",
    "deal.mapped_fields_readback",
)


def _field_bindings() -> tuple[BitrixGraphFieldBinding, ...]:
    fixed = {
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
    keys = {
        ("activity", "DEADLINE"),
        ("activity", "DESCRIPTION"),
        ("activity", "SUBJECT"),
        ("company", "TITLE"),
        ("company", "UF_CRM_LF_COMPANY_ID"),
        ("company", "UF_CRM_LF_INN"),
        ("contact", "EMAIL"),
        ("contact", "NAME"),
        ("contact", "PHONE"),
        ("contact", "POST"),
        ("contact", "UF_CRM_LF_CONTACT_ID"),
        ("deal", "TITLE"),
        ("deal", "UF_CRM_LF_OPPORTUNITY_ID"),
        ("deal", "UF_CRM_LF_PRODUCT_KEY"),
        ("deal", "UF_CRM_LF_PROJECT_ID"),
        ("deal", "UF_CRM_LF_SOURCE_EVENT_ID"),
        ("deal", "UF_CRM_LF_SOURCE_ID"),
    }
    return tuple(
        BitrixGraphFieldBinding(entity, key, fixed.get((entity, key), key))
        for entity, key in sorted(keys)
    )


def _unsealed_manifest() -> BitrixGraphMappingManifest:
    return BitrixGraphMappingManifest(
        manifest_version=GRAPH_MAPPING_MANIFEST_VERSION,
        mapping_id="alumkomplekt:bitrix:graph:v1",
        mapping_version="1.0.0",
        contract_version=GRAPH_CONTRACT_VERSION,
        input_contract_version=GRAPH_INPUT_CONTRACT_VERSION,
        lifecycle=GRAPH_MAPPING_LIFECYCLE,
        evidence_mode=GRAPH_MAPPING_EVIDENCE_MODE,
        portal_identity=_PORTAL_IDENTITY,
        field_bindings=_field_bindings(),
        correlation_fields=(
            BitrixGraphCorrelationField(
                "company", "UF_CRM_LF_CORRELATION_COMPANY"
            ),
            BitrixGraphCorrelationField(
                "contact", "UF_CRM_LF_CORRELATION_CONTACT"
            ),
            BitrixGraphCorrelationField("deal", "UF_CRM_LF_CORRELATION_DEAL"),
        ),
        source_bindings=(
            BitrixGraphSourceBinding(_SOURCE_ID, "LF_TENDERPLAN"),
        ),
        route=BitrixGraphRoute(
            deal_category_id="7",
            deal_stage_id="C7:NEW",
            deal_assigned_by_id="10",
            activity_responsible_id="11",
            activity_ping_offsets=(0, 60),
            activity_color_id="3",
        ),
        activity_marker_version=GRAPH_ACTIVITY_MARKER_VERSION,
    )


def _manifest() -> BitrixGraphMappingManifest:
    raw = _unsealed_manifest()
    return replace(raw, declared_manifest_hash=graph_mapping_manifest_hash(raw))


def _identity(
    operation_type: str, lf_entity_type: str, lf_entity_id: str
) -> tuple[str, str]:
    idempotency_key = (
        f"crm-graph-v1:{operation_type}:{lf_entity_type}:{lf_entity_id}"
    )
    correlation_token = "lf_graph_v1_" + payload_hash(
        {
            "operation_type": operation_type,
            "lf_entity_type": lf_entity_type,
            "lf_entity_id": lf_entity_id,
        }
    )[:40]
    return idempotency_key, correlation_token


def _request(
    operation_type: str, manifest_hash: str
) -> CrmGraphCreateRequest:
    common = {
        "source_event_id": _SOURCE_EVENT_ID,
        "mapping_manifest_hash": manifest_hash,
    }
    if operation_type == COMPANY_CREATE:
        remote_type = "company"
        local_type = "company"
        local_id = _COMPANY_ID
        payload = {
            "TITLE": "ООО АлюмКомплект",
            "UF_CRM_LF_COMPANY_ID": _COMPANY_ID,
            "UF_CRM_LF_INN": "7707083893",
        }
        dependencies: tuple[tuple[str, str], ...] = ()
        identities = (("company", _COMPANY_ID),)
        operation_id = "crmop_company_0001"
    elif operation_type == CONTACT_CREATE:
        remote_type = "contact"
        local_type = "contact"
        local_id = _CONTACT_ID
        payload = {
            "NAME": "Иван Иванов",
            "EMAIL": "sales@example.test",
            "PHONE": "+79990000000",
            "POST": "Закупки",
            "UF_CRM_LF_CONTACT_ID": _CONTACT_ID,
        }
        dependencies = (("company", "101"),)
        identities = (
            ("company", _COMPANY_ID),
            ("contact", _CONTACT_ID),
        )
        operation_id = "crmop_contact_0001"
    elif operation_type == DEAL_CREATE:
        remote_type = "deal"
        local_type = "opportunity"
        local_id = _OPPORTUNITY_ID
        payload = {
            "TITLE": "Поставка алюминиевого профиля",
            "UF_CRM_LF_OPPORTUNITY_ID": _OPPORTUNITY_ID,
            "UF_CRM_LF_PROJECT_ID": _PROJECT_ID,
            "UF_CRM_LF_PRODUCT_KEY": "aluminium_profile",
            "UF_CRM_LF_SOURCE_EVENT_ID": _SOURCE_EVENT_ID,
            "UF_CRM_LF_SOURCE_ID": _SOURCE_ID,
        }
        dependencies = (("company", "101"), ("contact", "202"))
        identities = (
            ("company", _COMPANY_ID),
            ("contact", _CONTACT_ID),
            ("opportunity", _OPPORTUNITY_ID),
            ("project", _PROJECT_ID),
        )
        operation_id = "crmop_deal_0001"
    elif operation_type == ACTIVITY_CREATE:
        remote_type = "activity"
        local_type = "opportunity"
        local_id = _OPPORTUNITY_ID
        payload = {
            "SUBJECT": "Связаться с заказчиком",
            "DESCRIPTION": "Проверить спецификацию",
            "DEADLINE": "2026-08-22T09:00:00Z",
            "UF_CRM_LF_OPPORTUNITY_ID": _OPPORTUNITY_ID,
        }
        dependencies = (
            ("company", "101"),
            ("contact", "202"),
            ("deal", "303"),
        )
        identities = (
            ("company", _COMPANY_ID),
            ("contact", _CONTACT_ID),
            ("opportunity", _OPPORTUNITY_ID),
            ("project", _PROJECT_ID),
        )
        operation_id = "crmop_activity_0001"
    else:  # pragma: no cover - test fixture guard
        raise AssertionError(operation_type)
    idempotency_key, correlation_token = _identity(
        operation_type, local_type, local_id
    )
    sealed_metadata = {
        f"{identity_type}_id": identity_id
        for identity_type, identity_id in identities
    }
    sealed_metadata["mapping_manifest_hash"] = manifest_hash
    if operation_type in {DEAL_CREATE, ACTIVITY_CREATE}:
        sealed_metadata["lf_source_id"] = _SOURCE_ID
    sealed_body = {
        **payload,
        "_lf_correlation_token": correlation_token,
        "_lf_graph_v1": sealed_metadata,
    }
    return CrmGraphCreateRequest(
        operation_id=operation_id,
        operation_type=operation_type,
        remote_entity_type=remote_type,
        correlation_token=correlation_token,
        payload=payload,
        dependency_remote_ids=dependencies,
        lf_entity_type=local_type,
        lf_entity_id=local_id,
        idempotency_key=idempotency_key,
        command_payload_hash=payload_hash(sealed_body),
        lf_source_id=(
            _SOURCE_ID
            if operation_type in {DEAL_CREATE, ACTIVITY_CREATE}
            else ""
        ),
        graph_identity_ids=identities,
        **common,
    )


def _reseal_request(request: CrmGraphCreateRequest) -> CrmGraphCreateRequest:
    metadata = {
        f"{identity_type}_id": identity_id
        for identity_type, identity_id in request.graph_identity_ids
    }
    metadata["mapping_manifest_hash"] = request.mapping_manifest_hash
    if request.lf_source_id:
        metadata["lf_source_id"] = request.lf_source_id
    sealed_body = {
        **request.payload,
        "_lf_correlation_token": request.correlation_token,
        "_lf_graph_v1": metadata,
    }
    return replace(request, command_payload_hash=payload_hash(sealed_body))


def _field_facts(
    manifest: BitrixGraphMappingManifest,
) -> tuple[BitrixGraphFieldFact, ...]:
    facts: dict[tuple[str, str], BitrixGraphFieldFact] = {}
    for binding in manifest.field_bindings:
        if (
            binding.entity_type == "activity"
            and binding.payload_key == "UF_CRM_LF_OPPORTUNITY_ID"
        ):
            continue
        value_type = (
            "crm_multifield"
            if binding.payload_key in {"EMAIL", "PHONE"}
            else "datetime"
            if binding.payload_key == "DEADLINE"
            else "string"
        )
        facts[(binding.entity_type, binding.remote_field)] = BitrixGraphFieldFact(
            entity_type=binding.entity_type,
            field_code=binding.remote_field,
            value_type=value_type,
            multiple=value_type == "crm_multifield",
            mandatory=(binding.entity_type, binding.payload_key)
            in {
                ("company", "TITLE"),
                ("contact", "NAME"),
                ("activity", "SUBJECT"),
            },
            read_only=False,
            searchable=False,
        )
    for correlation in manifest.correlation_fields:
        facts[(correlation.entity_type, correlation.remote_field)] = (
            BitrixGraphFieldFact(
                entity_type=correlation.entity_type,
                field_code=correlation.remote_field,
                value_type="string",
                multiple=False,
                mandatory=False,
                read_only=False,
                searchable=True,
            )
        )
    relationship_shapes = {
        ("activity", "ownerId"): "integer",
        ("activity", "ownerTypeId"): "integer",
        ("activity", "responsibleId"): "integer",
        ("contact", "COMPANY_ID"): "integer",
        ("deal", "ASSIGNED_BY_ID"): "integer",
        ("deal", "CATEGORY_ID"): "integer",
        ("deal", "COMPANY_ID"): "integer",
        ("deal", "CONTACT_ID"): "integer",
        ("deal", "SOURCE_ID"): "string",
        ("deal", "STAGE_ID"): "string",
    }
    for (entity, code), value_type in relationship_shapes.items():
        facts[(entity, code)] = BitrixGraphFieldFact(
            entity_type=entity,
            field_code=code,
            value_type=value_type,
            multiple=False,
            mandatory=entity == "activity" and code == "responsibleId",
            read_only=False,
            searchable=False,
        )
    return tuple(facts[key] for key in sorted(facts))


def _unsealed_snapshot(
    manifest: BitrixGraphMappingManifest,
) -> BitrixGraphSchemaSnapshot:
    requests = {
        operation: _request(operation, manifest.declared_manifest_hash)
        for operation in (COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE)
    }
    return BitrixGraphSchemaSnapshot(
        snapshot_version=GRAPH_SCHEMA_SNAPSHOT_VERSION,
        evidence_mode=GRAPH_MAPPING_EVIDENCE_MODE,
        portal_identity=manifest.portal_identity,
        captured_at_utc="2026-08-21T09:00:00Z",
        mapping_manifest_hash=manifest.declared_manifest_hash,
        inventory_complete=True,
        fields=_field_facts(manifest),
        route=BitrixGraphRouteFact(
            deal_category_id=manifest.route.deal_category_id,
            deal_stage_id=manifest.route.deal_stage_id,
            stage_category_id=manifest.route.deal_category_id,
            deal_assigned_by_id=manifest.route.deal_assigned_by_id,
            deal_assignee_active=True,
            activity_responsible_id=manifest.route.activity_responsible_id,
            activity_responsible_active=True,
            available_source_ids=("LF_OTHER", "LF_TENDERPLAN"),
        ),
        capabilities=tuple(
            BitrixGraphCapabilityFact(capability, True)
            for capability in _CAPABILITIES
        ),
        probes=tuple(
            BitrixGraphCorrelationProbe(
                entity,
                operation,
                requests[operation].lf_entity_id,
                requests[operation].correlation_token,
                0,
                (),
                False,
            )
            for entity, operation in (
                ("company", COMPANY_CREATE),
                ("contact", CONTACT_CREATE),
                ("deal", DEAL_CREATE),
            )
        ),
        evidence_ref="fixture:bitrix_graph_schema:v1",
    )


def _seal_snapshot(
    snapshot: BitrixGraphSchemaSnapshot,
) -> BitrixGraphSchemaSnapshot:
    raw = replace(snapshot, declared_snapshot_hash="")
    return replace(raw, declared_snapshot_hash=graph_schema_snapshot_hash(raw))


class BitrixGraphMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = _manifest()
        self.mapper = BitrixGraphMapper(self.manifest)

    def test_exact_sealed_manifest_and_hash(self) -> None:
        digest = graph_mapping_manifest_hash(self.manifest)

        self.assertEqual(validate_graph_mapping_manifest(self.manifest), digest)
        self.assertEqual(self.manifest.declared_manifest_hash, digest)
        self.assertEqual(digest, _EXPECTED_MANIFEST_HASH)
        self.assertEqual(len(digest), 64)
        self.assertEqual(self.mapper.manifest_hash, digest)

        changed = replace(self.manifest, mapping_version="1.0.1")
        with self.assertRaises(BitrixGraphManifestMismatch):
            BitrixGraphMapper(changed)

    def test_offline_preflight_prepares_only_a_non_activatable_canary_1_to_5(self) -> None:
        binding = BitrixGraphBridgeBinding(
            self.manifest, _SOURCE_ID, "2026-08-22T09:00:00Z"
        )
        report = run_bitrix_graph_offline_preflight(
            self.manifest, _seal_snapshot(_unsealed_snapshot(self.manifest))
        )
        plan = prepare_bitrix_graph_offline_canary(binding, report)

        self.assertEqual(plan.steps, (1, 2, 3, 4, 5))
        self.assertTrue(plan.offline_preflight_ok)
        self.assertEqual(plan.live_calls_performed, 0)
        self.assertEqual(plan.external_writes_performed, 0)
        self.assertFalse(plan.live_preflight_ok)
        self.assertTrue(plan.owner_approval_required)
        self.assertFalse(plan.activation_permitted)
        with self.assertRaises(BitrixGraphCanaryActivationDenied):
            plan.activate()
        with self.assertRaises(BitrixGraphCanaryError):
            prepare_bitrix_graph_offline_canary(
                binding, replace(report, canary_ready=True)
            )

    def test_compiles_exact_four_operation_graph(self) -> None:
        requests = {
            operation: _request(operation, self.mapper.manifest_hash)
            for operation in (
                COMPANY_CREATE,
                CONTACT_CREATE,
                DEAL_CREATE,
                ACTIVITY_CREATE,
            )
        }
        plans = {
            operation: self.mapper.compile_create(request)
            for operation, request in requests.items()
        }

        company = json.loads(plans[COMPANY_CREATE].payload_json)
        contact = json.loads(plans[CONTACT_CREATE].payload_json)
        deal = json.loads(plans[DEAL_CREATE].payload_json)
        activity = json.loads(plans[ACTIVITY_CREATE].payload_json)

        self.assertEqual(plans[COMPANY_CREATE].create_method, "crm.company.add")
        self.assertEqual(plans[CONTACT_CREATE].create_method, "crm.contact.add")
        self.assertEqual(plans[DEAL_CREATE].create_method, "crm.deal.add")
        self.assertEqual(
            plans[ACTIVITY_CREATE].create_method, "crm.activity.todo.add"
        )
        for plan in plans.values():
            self.assertEqual(plan.mapping_manifest_hash, self.mapper.manifest_hash)
            self.assertEqual(plan.payload_hash, payload_hash(json.loads(plan.payload_json)))
            self.assertEqual(len(plan.plan_hash), 64)
            self.assertEqual(
                plan.expectation.owned_fields_hash,
                payload_hash(json.loads(plan.expectation.owned_fields_json)),
            )

        self.assertEqual(company["fields"]["UF_CRM_LF_COMPANY_ID"], _COMPANY_ID)
        self.assertEqual(
            company["fields"]["UF_CRM_LF_CORRELATION_COMPANY"],
            requests[COMPANY_CREATE].correlation_token,
        )
        self.assertEqual(
            contact["fields"]["EMAIL"],
            [{"VALUE": "sales@example.test", "VALUE_TYPE": "WORK"}],
        )
        self.assertEqual(
            contact["fields"]["PHONE"],
            [{"VALUE": "+79990000000", "VALUE_TYPE": "WORK"}],
        )
        self.assertEqual(contact["fields"]["COMPANY_ID"], "101")

        deal_fields = deal["fields"]
        self.assertEqual(deal_fields["COMPANY_ID"], "101")
        self.assertEqual(deal_fields["CONTACT_ID"], "202")
        self.assertEqual(deal_fields["CATEGORY_ID"], "7")
        self.assertEqual(deal_fields["STAGE_ID"], "C7:NEW")
        self.assertEqual(deal_fields["ASSIGNED_BY_ID"], "10")
        self.assertEqual(deal_fields["SOURCE_ID"], "LF_TENDERPLAN")
        self.assertEqual(
            deal_fields["UF_CRM_LF_SOURCE_EVENT_ID"], _SOURCE_EVENT_ID
        )
        self.assertEqual(deal_fields["UF_CRM_LF_SOURCE_ID"], _SOURCE_ID)
        self.assertEqual(
            deal_fields["UF_CRM_LF_OPPORTUNITY_ID"], _OPPORTUNITY_ID
        )

        marker = plans[ACTIVITY_CREATE].expectation.activity_marker
        self.assertEqual(activity["ownerTypeId"], 2)
        self.assertEqual(activity["ownerId"], 303)
        self.assertEqual(activity["responsibleId"], 11)
        self.assertEqual(activity["pingOffsets"], [0, 60])
        self.assertEqual(activity["colorId"], "3")
        self.assertTrue(activity["description"].endswith("\n" + marker))
        self.assertIn(f"opportunity={_OPPORTUNITY_ID}", marker)
        self.assertIn(
            f"correlation={requests[ACTIVITY_CREATE].correlation_token}", marker
        )

    def test_actual_outbox_requests_compile_and_complete_in_dependency_order(self) -> None:
        mapper = self.mapper

        class MapperFixtureTransport:
            def __init__(self) -> None:
                self.operation_types: list[str] = []
                self.remote_ids = {
                    "company": "101",
                    "contact": "202",
                    "deal": "303",
                    "activity": "404",
                }

            def create_entity(self, request: CrmGraphCreateRequest):
                plan = mapper.compile_create(request)
                self.operation_types.append(request.operation_type)
                result = {
                    **json.loads(plan.expectation.owned_fields_json),
                    "ID": self.remote_ids[request.remote_entity_type],
                }
                if request.remote_entity_type == "deal":
                    result["CONTACT_IDS"] = [plan.expectation.contact_remote_id]
                elif request.remote_entity_type == "activity":
                    result["OWNER_TYPE_ID"] = "2"
                    result["OWNER_ID"] = plan.expectation.deal_remote_id
                return mapper.verify_readback(plan, result)

            def find_by_correlation(self, remote_entity_type, correlation_token):
                raise AssertionError("fixture create path must not reconcile")

        with tempfile.TemporaryDirectory() as temp_dir:
            store = FactoryStore(Path(temp_dir) / "graph.sqlite3")
            store.init()
            company, _ = store.create_company(
                name="ООО АлюмКомплект", inn="7707083893"
            )
            contact, _ = store.create_contact(
                lf_company_id=company["lf_company_id"],
                email="sales@example.test",
                name="Иван Иванов",
            )
            project, _ = store.create_project(
                lf_company_id=company["lf_company_id"],
                source="fixture",
                external_key="project-1",
                title="Поставка алюминиевого профиля",
            )
            opportunity, _ = store.create_opportunity(
                lf_company_id=company["lf_company_id"],
                lf_contact_id=contact["lf_contact_id"],
                lf_project_id=project["lf_project_id"],
                source="fixture",
                external_key="opportunity-1",
            )
            outbox = CrmGraphOutbox(store)
            outbox.stage_graph(
                company_id=company["lf_company_id"],
                contact_id=contact["lf_contact_id"],
                project_id=project["lf_project_id"],
                opportunity_id=opportunity["lf_opportunity_id"],
                external_event_id=_SOURCE_EVENT_ID,
                company_payload={
                    "TITLE": "ООО АлюмКомплект",
                    "UF_CRM_LF_COMPANY_ID": company["lf_company_id"],
                    "UF_CRM_LF_INN": "7707083893",
                },
                contact_payload={
                    "NAME": "Иван Иванов",
                    "EMAIL": "sales@example.test",
                    "UF_CRM_LF_CONTACT_ID": contact["lf_contact_id"],
                },
                deal_payload={
                    "TITLE": "Поставка алюминиевого профиля",
                    "UF_CRM_LF_OPPORTUNITY_ID": opportunity["lf_opportunity_id"],
                    "UF_CRM_LF_PROJECT_ID": project["lf_project_id"],
                    "UF_CRM_LF_PRODUCT_KEY": "aluminium_profile",
                    "UF_CRM_LF_SOURCE_EVENT_ID": _SOURCE_EVENT_ID,
                    "UF_CRM_LF_SOURCE_ID": _SOURCE_ID,
                },
                activity_payload={
                    "SUBJECT": "Связаться с заказчиком",
                    "DESCRIPTION": "Проверить спецификацию",
                    "DEADLINE": "2026-08-22T09:00:00Z",
                    "UF_CRM_LF_OPPORTUNITY_ID": opportunity["lf_opportunity_id"],
                },
                mapping_manifest_hash=mapper.manifest_hash,
                lf_source_id=_SOURCE_ID,
            )
            with store.transaction() as con:
                con.execute(
                    "UPDATE schema_meta SET value='1' "
                    "WHERE key='external_writers_enabled'"
                )
            transport = MapperFixtureTransport()
            results = [
                outbox.process_next(transport, worker_id="mapping-fixture")
                for _ in range(4)
            ]

        self.assertEqual([result.state for result in results], ["SENT"] * 4)
        self.assertEqual(
            transport.operation_types,
            [COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE, ACTIVITY_CREATE],
        )

    def test_lookup_candidate_requires_exact_page_then_exact_readback(self) -> None:
        request = _request(DEAL_CREATE, self.mapper.manifest_hash)
        create = self.mapper.compile_create(request)
        lookup = self.mapper.compile_lookup(create)
        row = {
            **json.loads(create.expectation.owned_fields_json),
            "ID": "303",
            "CONTACT_IDS": ["202"],
        }

        candidate = self.mapper.verify_lookup_page(
            lookup, {"result": [row], "total": 1, "next": None}
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.remote_entity_type, "deal")
        self.assertEqual(candidate.remote_id, "303")
        self.assertEqual(candidate.get_method, "crm.deal.get")
        self.assertEqual(json.loads(candidate.get_payload_json), {"id": "303"})
        self.assertEqual(candidate.mapping_manifest_hash, self.mapper.manifest_hash)
        self.assertEqual(lookup.source_create_plan_hash, create.plan_hash)
        self.assertEqual(len(lookup.plan_hash), 64)

        readback = self.mapper.verify_readback(create, row)
        self.assertEqual(readback.remote_entity_type, "deal")
        self.assertEqual(readback.remote_id, "303")
        self.assertTrue(readback.readback_verified)
        self.assertEqual(readback.company_remote_id, "101")
        self.assertEqual(readback.contact_remote_id, "202")

        with self.assertRaises(BitrixGraphMappingError):
            self.mapper.compile_lookup(replace(create, payload_hash="0" * 64))
        with self.assertRaises(BitrixGraphMappingError):
            self.mapper.verify_lookup_page(
                replace(lookup, list_method="crm.company.list"),
                {"result": [row], "total": 1, "next": None},
            )
        with self.assertRaises(BitrixGraphProviderConflict):
            self.mapper.verify_readback(
                create,
                replace_dict(row, TITLE="Подменённая сделка"),
            )
        with self.assertRaises(BitrixGraphProviderConflict):
            self.mapper.verify_lookup_page(
                lookup,
                {
                    "result": [replace_dict(row, CONTACT_ID="999")],
                    "total": 1,
                    "next": None,
                },
            )

    def test_activity_lookup_is_explicitly_unsupported(self) -> None:
        create = self.mapper.compile_create(
            _request(ACTIVITY_CREATE, self.mapper.manifest_hash)
        )

        with self.assertRaises(SafeReconciliationUnsupported):
            self.mapper.compile_lookup(create)

    def test_manifest_request_and_payload_tampering_fail_closed(self) -> None:
        company = _request(COMPANY_CREATE, self.mapper.manifest_hash)
        contact = _request(CONTACT_CREATE, self.mapper.manifest_hash)
        deal = _request(DEAL_CREATE, self.mapper.manifest_hash)

        cases = {
            "manifest_hash": replace(company, mapping_manifest_hash="0" * 64),
            "command_hash": replace(company, command_payload_hash="0" * 63),
            "remote_type": replace(company, remote_entity_type="contact"),
            "unicode_id": replace(company, operation_id="операция"),
            "leading_zero_parent": replace(
                contact, dependency_remote_ids=(("company", "0101"),)
            ),
            "relationship_field": replace(
                contact, payload={**contact.payload, "COMPANY_ID": "101"}
            ),
            "unknown_field": replace(
                company, payload={**company.payload, "UNKNOWN_FIELD": "x"}
            ),
            "unicode_key": replace(
                company, payload={**company.payload, "ＴITLE": "x"}
            ),
            "wrong_runtime_type": replace(
                contact, dependency_remote_ids=(("company", True),)
            ),
            "event_anchor": replace(deal, source_event_id="evt_graph_attack"),
            "source_anchor": replace(deal, lf_source_id="wave1:saby_trade"),
        }
        for label, request in cases.items():
            with self.subTest(label=label):
                expected = (
                    BitrixGraphManifestMismatch
                    if label == "manifest_hash"
                    else BitrixGraphMappingError
                )
                with self.assertRaises(expected):
                    self.mapper.compile_create(request)

    def test_full_length_command_hash_and_post_seal_mutation_fail_closed(self) -> None:
        company = _request(COMPANY_CREATE, self.mapper.manifest_hash)

        with self.assertRaises(BitrixGraphMappingError):
            self.mapper.compile_create(
                replace(company, command_payload_hash="f" * 64)
            )
        with self.assertRaises(BitrixGraphMappingError):
            self.mapper.compile_create(
                replace(
                    company,
                    payload={**company.payload, "TITLE": "Изменено после seal"},
                )
            )

    def test_graph_project_identity_and_activity_source_are_exactly_bound(self) -> None:
        deal = _request(DEAL_CREATE, self.mapper.manifest_hash)
        wrong_project = _reseal_request(
            replace(
                deal,
                payload={
                    **deal.payload,
                    "UF_CRM_LF_PROJECT_ID": "prj_other",
                },
            )
        )
        activity = _request(ACTIVITY_CREATE, self.mapper.manifest_hash)
        unknown_source = _reseal_request(
            replace(activity, lf_source_id="wave1:unknown")
        )

        for label, request in {
            "project": wrong_project,
            "activity_source": unknown_source,
        }.items():
            with self.subTest(label=label):
                with self.assertRaises(BitrixGraphMappingError):
                    self.mapper.compile_create(request)

    def test_resealed_create_token_must_match_lf_identity(self) -> None:
        create = self.mapper.compile_create(
            _request(COMPANY_CREATE, self.mapper.manifest_hash)
        )
        forged_token = "lf_graph_v1_" + "b" * 40
        provider = json.loads(create.payload_json)
        provider["fields"][create.expectation.correlation_field] = forged_token
        owned = dict(provider["fields"])
        expectation = replace(
            create.expectation,
            correlation_token=forged_token,
            owned_fields_json=graph_mapping.canonical_json(owned),
            owned_fields_hash=payload_hash(owned),
        )
        forged = replace(
            create,
            payload_json=graph_mapping.canonical_json(provider),
            payload_hash=payload_hash(provider),
            expectation=expectation,
            plan_hash="",
        )
        forged = replace(
            forged,
            plan_hash=payload_hash(graph_mapping._create_plan_body(forged)),
        )

        with self.assertRaises(BitrixGraphMappingError):
            self.mapper.compile_lookup(forged)

    def test_resealed_lookup_token_must_match_lf_identity(self) -> None:
        create = self.mapper.compile_create(
            _request(COMPANY_CREATE, self.mapper.manifest_hash)
        )
        lookup = self.mapper.compile_lookup(create)
        forged_token = "lf_graph_v1_" + "c" * 40
        payload = json.loads(lookup.payload_json)
        payload["filter"] = {
            f"={lookup.expectation.correlation_field}": forged_token
        }
        expectation = replace(
            lookup.expectation,
            correlation_token=forged_token,
        )
        forged = replace(
            lookup,
            payload_json=graph_mapping.canonical_json(payload),
            payload_hash=payload_hash(payload),
            expectation=expectation,
            source_create_plan_hash="d" * 64,
            plan_hash="",
        )
        forged = replace(
            forged,
            plan_hash=payload_hash(graph_mapping._lookup_plan_body(forged)),
        )

        with self.assertRaises(BitrixGraphMappingError):
            self.mapper.verify_lookup_page(
                forged,
                {
                    "result": [
                        {
                            "ID": "99",
                            expectation.correlation_field: forged_token,
                        }
                    ],
                    "total": 1,
                    "next": None,
                },
            )

    def test_resealed_lookup_cannot_change_get_method_or_source_plan(self) -> None:
        create = self.mapper.compile_create(
            _request(COMPANY_CREATE, self.mapper.manifest_hash)
        )
        lookup = self.mapper.compile_lookup(create)
        expectation = replace(
            lookup.expectation,
            get_method="crm.company.delete",
        )
        unsafe = replace(
            lookup,
            get_method="crm.company.delete",
            expectation=expectation,
            plan_hash="",
        )
        unsafe = replace(
            unsafe,
            plan_hash=payload_hash(graph_mapping._lookup_plan_body(unsafe)),
        )
        wrong_source = replace(
            lookup,
            source_create_plan_hash="e" * 64,
            plan_hash="",
        )
        wrong_source = replace(
            wrong_source,
            plan_hash=payload_hash(graph_mapping._lookup_plan_body(wrong_source)),
        )
        unsafe_id = replace(lookup, operation_id="unsafe operation", plan_hash="")
        unsafe_id = replace(
            unsafe_id,
            plan_hash=payload_hash(graph_mapping._lookup_plan_body(unsafe_id)),
        )

        for label, plan in {
            "method": unsafe,
            "source": wrong_source,
            "operation_id": unsafe_id,
        }.items():
            with self.subTest(label=label):
                with self.assertRaises(BitrixGraphMappingError):
                    self.mapper.verify_lookup_page(
                        plan,
                        {"result": [], "total": 0, "next": None},
                    )

    def test_resealed_activity_plan_cannot_diverge_from_manifest_route(self) -> None:
        create = self.mapper.compile_create(
            _request(ACTIVITY_CREATE, self.mapper.manifest_hash)
        )
        provider = json.loads(create.payload_json)
        provider["responsibleId"] = 999
        forged = replace(
            create,
            payload_json=graph_mapping.canonical_json(provider),
            payload_hash=payload_hash(provider),
            plan_hash="",
        )
        forged = replace(
            forged,
            plan_hash=payload_hash(graph_mapping._create_plan_body(forged)),
        )
        result = {
            **json.loads(create.expectation.owned_fields_json),
            "ID": "404",
            "OWNER_TYPE_ID": "2",
            "OWNER_ID": create.expectation.deal_remote_id,
        }

        with self.assertRaises(BitrixGraphMappingError):
            self.mapper.verify_readback(forged, result)

    def test_deal_readback_rechecks_every_mapping_owned_field(self) -> None:
        create = self.mapper.compile_create(
            _request(DEAL_CREATE, self.mapper.manifest_hash)
        )
        row = {
            **json.loads(create.expectation.owned_fields_json),
            "ID": "303",
            "CONTACT_IDS": ["202"],
        }

        cases = {
            "title": ("TITLE", "Другая сделка"),
            "stage": ("STAGE_ID", "C9:LOST"),
            "category": ("CATEGORY_ID", "9"),
            "assignee": ("ASSIGNED_BY_ID", "999"),
            "source": ("SOURCE_ID", "OTHER"),
        }
        for label, (field, value) in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(BitrixGraphProviderConflict):
                    self.mapper.verify_readback(
                        create,
                        replace_dict(row, **{field: value}),
                    )

    def test_provider_remote_id_requires_positive_ascii_canonical_form(self) -> None:
        create = self.mapper.compile_create(
            _request(COMPANY_CREATE, self.mapper.manifest_hash)
        )
        fields = json.loads(create.expectation.owned_fields_json)

        for value in (True, 1.0, " 1 ", "01", "٠١", "１", "+1", "-1", "0"):
            with self.subTest(value=value):
                with self.assertRaises(BitrixGraphProviderConflict):
                    self.mapper.verify_readback(create, {**fields, "ID": value})

    def test_unknown_manifest_binding_and_relationship_target_are_rejected(self) -> None:
        bindings = list(self.manifest.field_bindings)
        bindings.append(BitrixGraphFieldBinding("company", "UNKNOWN", "UF_CRM_X"))
        unknown = replace(
            self.manifest,
            field_bindings=tuple(sorted(bindings, key=lambda item: (item.entity_type, item.payload_key))),
            declared_manifest_hash="",
        )
        relationship = replace(
            self.manifest,
            field_bindings=tuple(
                replace(item, remote_field="COMPANY_ID")
                if (
                    item.entity_type == "company"
                    and item.payload_key == "UF_CRM_LF_COMPANY_ID"
                )
                else item
                for item in self.manifest.field_bindings
            ),
            declared_manifest_hash="",
        )

        for value in (unknown, relationship):
            with self.subTest(manifest=value):
                with self.assertRaises(BitrixGraphMappingError):
                    graph_mapping_manifest_hash(value)

    def test_sensitive_objects_have_redacted_repr(self) -> None:
        request = _request(DEAL_CREATE, self.mapper.manifest_hash)
        create = self.mapper.compile_create(request)
        lookup = self.mapper.compile_lookup(create)
        candidate = self.mapper.verify_lookup_page(
            lookup,
            {
                "result": [
                    {
                        "ID": "303",
                        create.expectation.correlation_field: request.correlation_token,
                        "COMPANY_ID": "101",
                        "CONTACT_ID": "202",
                    }
                ],
                "total": 1,
                "next": None,
            },
        )
        snapshot = _seal_snapshot(_unsealed_snapshot(self.manifest))
        objects = (
            self.manifest.field_bindings[0],
            self.manifest.correlation_fields[0],
            self.manifest.source_bindings[0],
            self.manifest.route,
            self.manifest,
            self.mapper,
            request,
            create.expectation,
            create,
            lookup,
            candidate,
            snapshot.fields[0],
            snapshot.route,
            snapshot.capabilities[0],
            snapshot.probes[0],
            snapshot,
        )

        for value in objects:
            with self.subTest(type=type(value).__name__):
                self.assertEqual(repr(value), f"<{type(value).__name__} redacted>")
                self.assertNotIn(_OPPORTUNITY_ID, repr(value))
                self.assertNotIn("sales@example.test", repr(value))


class BitrixGraphOfflinePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = _manifest()
        self.snapshot = _seal_snapshot(_unsealed_snapshot(self.manifest))

    def test_exact_offline_snapshot_passes_without_live_claims(self) -> None:
        snapshot_hash = validate_graph_schema_snapshot(self.snapshot)
        report = run_bitrix_graph_offline_preflight(self.manifest, self.snapshot)

        self.assertTrue(report.offline_contract_ok)
        self.assertEqual(report.error_code, "")
        self.assertEqual(
            report.checks,
            (
                "MANIFEST_VALID",
                "SNAPSHOT_VALID",
                "SNAPSHOT_BOUND",
                "FIELDS_COMPATIBLE",
                "ROUTE_COMPATIBLE",
                "READBACK_CAPABILITIES_PROVEN",
                "CORRELATION_TOKENS_UNUSED",
            ),
        )
        self.assertEqual(report.manifest_hash, self.manifest.declared_manifest_hash)
        self.assertEqual(report.snapshot_hash, snapshot_hash)
        self.assertEqual(snapshot_hash, _EXPECTED_SNAPSHOT_HASH)
        self.assertEqual(report.live_calls_performed, 0)
        self.assertEqual(report.external_writes_performed, 0)
        self.assertFalse(report.live_preflight_ok)
        self.assertFalse(report.canary_ready)
        self.assertEqual(
            report.report_hash,
            payload_hash(
                {
                    "offline_contract_ok": True,
                    "checks": list(report.checks),
                    "error_code": "",
                    "manifest_hash": report.manifest_hash,
                    "snapshot_hash": report.snapshot_hash,
                    "live_calls_performed": 0,
                    "external_writes_performed": 0,
                    "live_preflight_ok": False,
                    "canary_ready": False,
                }
            ),
        )

    def test_snapshot_hash_tamper_fails_closed(self) -> None:
        report = run_bitrix_graph_offline_preflight(
            self.manifest,
            replace(self.snapshot, declared_snapshot_hash="0" * 64),
        )

        self.assertFalse(report.offline_contract_ok)
        self.assertEqual(report.error_code, "SNAPSHOT_INVALID")
        self.assertEqual(report.live_calls_performed, 0)
        self.assertEqual(report.external_writes_performed, 0)

    def test_probe_token_is_derived_from_exact_operation_and_lf_identity(self) -> None:
        company = self.snapshot.probes[0]
        contact = self.snapshot.probes[1]
        cases = {
            "token": replace(
                company,
                correlation_token=contact.correlation_token,
            ),
            "operation": replace(company, operation_type=CONTACT_CREATE),
            "identity": replace(company, lf_identity_id="cmp_other"),
        }

        for label, probe in cases.items():
            with self.subTest(label=label):
                snapshot = replace(
                    self.snapshot,
                    probes=(probe, *self.snapshot.probes[1:]),
                )
                with self.assertRaises(BitrixGraphPreflightError):
                    graph_schema_snapshot_hash(snapshot)
                report = run_bitrix_graph_offline_preflight(
                    self.manifest,
                    snapshot,
                )
                self.assertFalse(report.offline_contract_ok)
                self.assertEqual(report.error_code, "SNAPSHOT_INVALID")
                self.assertEqual(report.live_calls_performed, 0)

    def test_resealed_field_route_capability_and_probe_tamper_fail(self) -> None:
        title_index = next(
            index
            for index, fact in enumerate(self.snapshot.fields)
            if fact.entity_type == "company" and fact.field_code == "TITLE"
        )
        changed_fields = list(self.snapshot.fields)
        changed_fields[title_index] = replace(
            changed_fields[title_index], value_type="integer"
        )
        changed_capabilities = tuple(
            replace(fact, proven=False)
            if fact.capability_id == "deal.company_contact_readback"
            else fact
            for fact in self.snapshot.capabilities
        )
        changed_probes = tuple(
            replace(probe, total=1, returned_remote_ids=("999",))
            if probe.entity_type == "deal"
            else probe
            for probe in self.snapshot.probes
        )
        cases = {
            "field": (
                _seal_snapshot(replace(self.snapshot, fields=tuple(changed_fields))),
                "FIELD_SHAPE",
            ),
            "route": (
                _seal_snapshot(
                    replace(
                        self.snapshot,
                        route=replace(self.snapshot.route, deal_stage_id="C7:WON"),
                    )
                ),
                "ROUTE_STAGE_MISMATCH",
            ),
            "capability": (
                _seal_snapshot(
                    replace(self.snapshot, capabilities=changed_capabilities)
                ),
                "RELATION_READBACK_UNPROVEN",
            ),
            "probe": (
                _seal_snapshot(replace(self.snapshot, probes=changed_probes)),
                "CORRELATION_TOKEN_NOT_UNUSED",
            ),
        }

        for label, (snapshot, error_code) in cases.items():
            with self.subTest(label=label):
                report = run_bitrix_graph_offline_preflight(
                    self.manifest, snapshot
                )
                self.assertFalse(report.offline_contract_ok)
                self.assertEqual(report.error_code, error_code)
                self.assertEqual(report.live_calls_performed, 0)
                self.assertEqual(report.external_writes_performed, 0)
                self.assertFalse(report.live_preflight_ok)
                self.assertFalse(report.canary_ready)

    def test_snapshot_manifest_route_is_bound_exactly(self) -> None:
        mismatched = _seal_snapshot(
            replace(self.snapshot, mapping_manifest_hash="2" * 64)
        )
        report = run_bitrix_graph_offline_preflight(self.manifest, mismatched)

        self.assertFalse(report.offline_contract_ok)
        self.assertEqual(report.error_code, "SNAPSHOT_MAPPING_MISMATCH")


def replace_dict(source: dict[str, object], **changes: object) -> dict[str, object]:
    return {**source, **changes}


if __name__ == "__main__":
    unittest.main()
