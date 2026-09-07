from __future__ import annotations

import ast
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn
from unittest.mock import patch

import pytest

from lead_factory.mdos_v7 import authority
from lead_factory.mdos_v7 import manual_egress


ROOT = Path(__file__).resolve().parent.parent
BOUNDARY_INVENTORY = {
    "eis_client.py": {"legacy.source.eis"},
    "lead_factory/imap_canary_runtime.py": {"lead_factory.imap.canary"},
    "lead_factory/tenderplan_isolated_transport.py": {
        "lead_factory.source.tenderplan.shadow_canary"
    },
    "lead_factory/tenderplan_shadow_canary.py": {
        "lead_factory.source.tenderplan.shadow_canary"
    },
    "tb_ai.py": {"legacy.ai.openrouter"},
    "tb_attach_export.py": {"legacy.imap.attach_export"},
    "tb_bitrix_readonly.py": {"legacy.bitrix.read"},
    "tb_damia.py": {"legacy.source.damia"},
    "tb_dealers_2gis.py": {
        "legacy.bitrix.dealer_dedup",
        "legacy.source.2gis.dealer_catalog",
    },
    "tb_dealers_email.py": {
        "legacy.bitrix.dealer_dedup",
        "legacy.source.duckduckgo.dealer_search",
        "legacy.source.public_site.dealer_scrape",
    },
    "tb_dealers_pool.py": {
        "legacy.bitrix.dealer_dedup",
        "legacy.source.2gis.dealer_catalog",
        "legacy.source.bing.dealer_search",
        "legacy.source.duckduckgo.dealer_search",
        "legacy.source.public_site.dealer_scrape",
    },
    "tb_dealers_serper.py": {"legacy.source.serper.dealer_search"},
    "tb_dealers_yandex.py": {
        "legacy.source.yandex.operation_poll",
        "legacy.source.yandex.search_submit",
    },
    "tb_docs.py": {"legacy.source.procurement.document_download"},
    "tb_eisdocs.py": {"legacy.source.eis.document_download"},
    "tb_exportbase_site_enrich.py": {
        "legacy.bitrix.exportbase_dedup",
        "legacy.source.exportbase.site_scrape",
    },
    "tb_facade.py": {"legacy.imap.facade"},
    "tb_inbox_export.py": {"legacy.imap.inbox_export"},
    "tb_fetch_kp.py": {
        "legacy.bitrix.kp_download",
        "legacy.bitrix.kp_export",
    },
    "tb_leaddocs.py": {
        "legacy.bitrix.leaddocs.attach",
        "legacy.imap.leaddocs",
        "legacy.telegram.leaddocs.contact",
    },
    "tb_probe_2gis.py": {"legacy.source.2gis.dealer_catalog"},
    "tb_probe_bing.py": {"legacy.source.bing.dealer_search"},
    "tb_probe_damia_br.py": {"legacy.source.damia.probe"},
    "tb_probe_net.py": {"legacy.diagnostic.network_probe"},
    "tb_probe_scrape.py": {
        "legacy.source.duckduckgo.dealer_search",
        "legacy.source.public_site.dealer_scrape",
    },
    "tb_retail_pool.py": {
        "legacy.bitrix.dealer_dedup",
        "legacy.source.public_site.dealer_scrape",
    },
    "tb_webhook.py": {
        "legacy.webhook.public_health",
        "legacy.webhook.telegram.alert",
        "legacy.webhook.tunnel.cloudflared",
        "legacy.webhook.tunnel.serveo",
        "legacy.webhook.unisender.read",
        "legacy.webhook.unisender.verify",
        "legacy.webhook.unisender.write",
    },
    "tb_webhook_watchdog.py": {
        "legacy.webhook.public_health",
        "legacy.webhook.unisender.read",
        "legacy.webhook.watchdog.restart",
    },
    "taskbot/bitrix.py": {"taskbot.bitrix.read", "taskbot.bitrix.write"},
    "taskbot/openrouter.py": {"taskbot.openrouter"},
    "taskbot/telegram.py": {
        "taskbot.telegram.contact",
        "taskbot.telegram.read",
    },
}
EXPECTED_REGISTRY_METADATA = {
    "legacy.ai.openrouter": ("spend", "openrouter"),
    "legacy.bitrix.read": ("external_read", "bitrix24"),
    "legacy.imap.attach_export": ("external_read", "imap"),
    "legacy.imap.facade": ("external_read", "imap"),
    "legacy.imap.inbox_export": ("external_read", "imap"),
    "legacy.source.damia": ("external_read", "damia"),
    "legacy.source.eis": ("external_read", "eis"),
    "taskbot.bitrix.read": ("external_read", "bitrix24"),
    "taskbot.bitrix.write": ("external_write", "bitrix24"),
    "taskbot.openrouter": ("spend", "openrouter"),
    "taskbot.telegram.contact": ("contact", "telegram"),
    "taskbot.telegram.read": ("external_read", "telegram"),
}
EXPECTED_PRIMARY_REGISTRY_BINDINGS = {
    "legacy.ai.openrouter": (
        {"POST /api/v1/chat/completions"},
        {"host:openrouter.ai"},
    ),
    "legacy.bitrix.read": (
        {
            f"POST /rest/{{user}}/{{token}}/{method}.json"
            for method in {
                "crm.activity.list",
                "crm.company.list",
                "crm.contact.list",
                "crm.deal.fields",
                "crm.deal.get",
                "crm.deal.list",
                "crm.dealcategory.list",
                "crm.dealcategory.stage.list",
                "crm.lead.list",
                "crm.quote.list",
                "crm.timeline.comment.list",
                "disk.file.get",
            }
        },
        {"bitrix24:webhook"},
    ),
    "legacy.imap.attach_export": (
        {
            "connect",
            "credential.read",
            "fetch.message",
            "id.command",
            "id.response",
            "list",
            "login",
            "logout",
            "search",
            "select.readonly",
        },
        {"env:manager_imap", "imap:manager_mailbox"},
    ),
    "legacy.imap.facade": (
        {
            "connect",
            "credential.read",
            "fetch.message",
            "id.command",
            "id.response",
            "login",
            "logout",
            "search",
            "select.readonly",
        },
        {"config:legacy_secrets", "imap:manager_mailbox"},
    ),
    "legacy.imap.inbox_export": (
        {
            "connect",
            "credential.read",
            "fetch.message",
            "id.command",
            "id.response",
            "list",
            "login",
            "logout",
            "search",
            "select.readonly",
        },
        {"env:manager_imap", "imap:manager_mailbox"},
    ),
    "legacy.source.damia": (
        {
            "GET /zakupki/contracts",
            "GET /zakupki/eruz",
            "GET /zakupki/rnp",
            "GET /zakupki/zakupka",
            "GET /zakupki/zsearch",
        },
        {"host:api.damia.ru"},
    ),
    "legacy.source.eis": (
        {
            "GET /epz/contract/contractCard/common-info.html",
            "GET /epz/contract/search/results.html",
        },
        {"host:zakupki.gov.ru"},
    ),
    "taskbot.bitrix.read": (
        {
            "POST /rest/{user}/{token}/app.info.json",
            "POST /rest/{user}/{token}/tasks.task.get.json",
            "POST /rest/{user}/{token}/tasks.task.list.json",
        },
        {"bitrix24:webhook"},
    ),
    "taskbot.bitrix.write": (
        {
            "POST /rest/api/{user}/{token}/tasks.task.result.add",
            "POST /rest/{user}/{token}/tasks.task.add.json",
            "POST /rest/{user}/{token}/tasks.task.complete.json",
            "POST /rest/{user}/{token}/tasks.task.delete.json",
            "POST /rest/{user}/{token}/tasks.task.start.json",
            "POST /rest/{user}/{token}/tasks.task.update.json",
        },
        {"bitrix24:webhook"},
    ),
    "taskbot.openrouter": (
        {
            "POST /api/v1/audio/transcriptions",
            "POST /api/v1/chat/completions",
        },
        {"host:openrouter.ai"},
    ),
    "taskbot.telegram.contact": (
        {
            "POST /bot{token}/answerCallbackQuery",
            "POST /bot{token}/editMessageText",
            "POST /bot{token}/sendMessage",
        },
        {"host:api.telegram.org"},
    ),
    "taskbot.telegram.read": (
        {
            "GET /file/bot{token}/{path...}",
            "POST /bot{token}/getFile",
            "POST /bot{token}/getMe",
            "POST /bot{token}/getUpdates",
        },
        {"host:api.telegram.org"},
    ),
}
EXPECTED_EXTENDED_REGISTRY_METADATA = {
    "legacy.diagnostic.network_probe": (
        "external_read",
        "network_diagnostic",
        {"credential.read", "GET", "POST"},
        {
            "env:proxy_presence",
            "host:alcon-city.ru",
            "host:alumkomplekt.bitrix24.ru",
            "host:html.duckduckgo.com",
            "host:www.bing.com",
        },
    ),
    "lead_factory.imap.canary": (
        "external_read",
        "imap",
        {"credential.read", "connect", "login", "logout"},
        {"imap:canary_mailbox"},
    ),
    "lead_factory.source.tenderplan.shadow_canary": (
        "external_read",
        "tenderplan",
        {"credential.read", "POST /api/search/v2/list"},
        {"authref:tenderplan_pat", "host:tenderplan.ru"},
    ),
    "legacy.bitrix.dealer_dedup": (
        "external_read",
        "bitrix24",
        {
            "credential.read",
            "client_keys",
            "known_contacts",
            "crm.company.list",
            "crm.contact.list",
            "crm.lead.list",
        },
        {"bitrix24:legacy_crm"},
    ),
    "legacy.bitrix.exportbase_dedup": (
        "external_read",
        "bitrix24",
        {"known_contacts"},
        {"bitrix24:legacy_crm"},
    ),
    "legacy.bitrix.kp_download": (
        "external_read",
        "bitrix24",
        {"GET"},
        {"public_http:bitrix_download"},
    ),
    "legacy.bitrix.kp_export": (
        "external_read",
        "bitrix24",
        {
            "credential.read",
            "crm.deal.list",
            "crm.timeline.comment.list",
            "disk.file.get",
        },
        {"bitrix24:legacy_crm"},
    ),
    "legacy.bitrix.leaddocs.attach": (
        "external_write",
        "bitrix24",
        {"credential.read", "crm.timeline.comment.add"},
        {"bitrix24:legacy_crm"},
    ),
    "legacy.imap.leaddocs": (
        "external_read",
        "imap",
        {
            "credential.read",
            "connect",
            "login",
            "list",
            "select.readonly",
            "search",
            "fetch.header",
            "fetch.message",
            "logout",
        },
        {"imap:manager_mailbox"},
    ),
    "legacy.source.2gis.dealer_catalog": (
        "external_read",
        "2gis",
        {"credential.read", "GET /3.0/items"},
        {"host:catalog.api.2gis.com"},
    ),
    "legacy.source.bing.dealer_search": (
        "external_read",
        "bing",
        {"GET /search"},
        {"host:www.bing.com"},
    ),
    "legacy.source.damia.probe": (
        "external_read",
        "damia",
        {
            "credential.read",
            "GET /br/br",
            "GET /br/sug",
            "GET /br/search",
            "GET /org/search",
        },
        {"host:api.damia.ru"},
    ),
    "legacy.source.duckduckgo.dealer_search": (
        "external_read",
        "duckduckgo",
        {"POST /html/"},
        {"host:html.duckduckgo.com"},
    ),
    "legacy.source.eis.document_download": (
        "external_read",
        "eis",
        {"GET"},
        {"host:zakupki.gov.ru"},
    ),
    "legacy.source.exportbase.site_scrape": (
        "external_read",
        "public_site",
        {"GET"},
        {"public_http:exportbase_site"},
    ),
    "legacy.source.procurement.document_download": (
        "external_read",
        "procurement_document",
        {"GET"},
        {"public_http:procurement_document"},
    ),
    "legacy.source.public_site.dealer_scrape": (
        "external_read",
        "public_site",
        {"GET"},
        {"public_http:dealer_site"},
    ),
    "legacy.source.serper.dealer_search": (
        "external_read",
        "serper",
        {"credential.read", "POST /search"},
        {"host:google.serper.dev"},
    ),
    "legacy.source.yandex.operation_poll": (
        "external_read",
        "yandex_search",
        {"GET /operations/{id}"},
        {"host:operation.api.cloud.yandex.net"},
    ),
    "legacy.source.yandex.search_submit": (
        "external_read",
        "yandex_search",
        {"credential.read", "POST /v2/web/search"},
        {"host:searchapi.api.cloud.yandex.net"},
    ),
    "legacy.telegram.leaddocs.contact": (
        "contact",
        "telegram",
        {"credential.read", "sendMessage"},
        {"telegram:manager_alert"},
    ),
    "legacy.webhook.public_health": (
        "external_read",
        "webhook_health",
        {"GET"},
        {"public_http:webhook_health"},
    ),
    "legacy.webhook.telegram.alert": (
        "contact",
        "telegram",
        {"credential.read", "sendMessage"},
        {"telegram:delivery_alert"},
    ),
    "legacy.webhook.tunnel.cloudflared": (
        "external_write",
        "cloudflare_tunnel",
        {"start"},
        {"tunnel:trycloudflare"},
    ),
    "legacy.webhook.tunnel.serveo": (
        "external_write",
        "ssh_tunnel",
        {"start"},
        {"tunnel:serveo"},
    ),
    "legacy.webhook.unisender.read": (
        "external_read",
        "unisender",
        {"credential.read", "webhook/list.json"},
        {"unisender:webhook_api"},
    ),
    "legacy.webhook.unisender.verify": (
        "external_read",
        "unisender",
        {"credential.read"},
        {"env:UNISENDER_GO_API_KEY"},
    ),
    "legacy.webhook.unisender.write": (
        "external_write",
        "unisender",
        {"credential.read", "webhook/delete.json", "webhook/set.json"},
        {"unisender:webhook_api"},
    ),
    "legacy.webhook.watchdog.restart": (
        "external_write",
        "scheduled_task",
        {"end", "run"},
        {"task:ALT_DeliveryWebhook"},
    ),
}


@pytest.fixture
def isolated_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest_path = tmp_path / "contract-manifest.json"
    freeze_path = tmp_path / "external-freeze.json"
    manifest_path.write_text(
        json.dumps(
            {
                "contract_id": authority.CONTRACT_ID,
                "package_version": authority.PACKAGE_VERSION,
                "package_root_sha256": authority.PACKAGE_ROOT_SHA256,
                "active_beachhead_profile": None,
                "ratification": None,
                "defaults_pending_ratification": {
                    "external_reads_enabled": False,
                    "external_writers_enabled": False,
                    "contact_enabled": False,
                    "spend_enabled": False,
                },
            }
        ),
        encoding="utf-8",
    )
    freeze_path.write_text(
        json.dumps(
            {
                "contract_id": authority.CONTRACT_ID,
                "package_version": authority.PACKAGE_VERSION,
                "package_root_sha256": authority.PACKAGE_ROOT_SHA256,
                "external_reads_enabled": False,
                "external_writers_enabled": False,
                "contact_enabled": False,
                "spend_enabled": False,
                "live_bitrix_writes_enabled": False,
                "legacy_campaigns_enabled": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(authority, "_MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(authority, "_FREEZE_PATH", freeze_path)


def _unexpected_effect(*_args: object, **_kwargs: object) -> NoReturn:
    pytest.fail("manual egress reached a transport or credential lookup")


def test_registry_is_exact_immutable_and_unknown_operations_fail_closed(
    isolated_authority: None,
) -> None:
    del isolated_authority
    expected = set().union(*BOUNDARY_INVENTORY.values())
    assert set(manual_egress.MANUAL_EGRESS_OPERATIONS) == expected
    assert manual_egress.MANUAL_EGRESS_SAFE_HTTP_SOURCES == frozenset()
    assert {
        operation_id: (metadata.authority_flag, metadata.channel)
        for operation_id, metadata in manual_egress.MANUAL_EGRESS_OPERATIONS.items()
        if operation_id in EXPECTED_REGISTRY_METADATA
    } == EXPECTED_REGISTRY_METADATA
    assert {
        operation_id: (set(metadata.methods), set(metadata.sources))
        for operation_id, metadata in manual_egress.MANUAL_EGRESS_OPERATIONS.items()
        if operation_id in EXPECTED_PRIMARY_REGISTRY_BINDINGS
    } == EXPECTED_PRIMARY_REGISTRY_BINDINGS
    assert {
        operation_id: (
            metadata.authority_flag,
            metadata.channel,
            set(metadata.methods),
            set(metadata.sources),
        )
        for operation_id, metadata in manual_egress.MANUAL_EGRESS_OPERATIONS.items()
        if operation_id in EXPECTED_EXTENDED_REGISTRY_METADATA
    } == EXPECTED_EXTENDED_REGISTRY_METADATA
    assert (
        set(EXPECTED_REGISTRY_METADATA) | set(EXPECTED_EXTENDED_REGISTRY_METADATA)
        == expected
    )
    assert set(EXPECTED_PRIMARY_REGISTRY_BINDINGS) == set(EXPECTED_REGISTRY_METADATA)
    for metadata in manual_egress.MANUAL_EGRESS_OPERATIONS.values():
        assert metadata.methods
        assert metadata.sources
        assert metadata.bindings
        assert {method for method, _source in metadata.bindings} == set(
            metadata.methods
        )
        assert {source for _method, source in metadata.bindings} == set(
            metadata.sources
        )
    assert (
        "credential.read",
        "imap:manager_mailbox",
    ) not in manual_egress.MANUAL_EGRESS_OPERATIONS[
        "legacy.imap.attach_export"
    ].bindings
    assert (
        "connect",
        "env:manager_imap",
    ) not in manual_egress.MANUAL_EGRESS_OPERATIONS["legacy.imap.inbox_export"].bindings
    assert (
        "credential.read",
        "imap:manager_mailbox",
    ) not in manual_egress.MANUAL_EGRESS_OPERATIONS["legacy.imap.facade"].bindings
    assert (
        "POST",
        "host:www.bing.com",
    ) not in manual_egress.MANUAL_EGRESS_OPERATIONS[
        "legacy.diagnostic.network_probe"
    ].bindings
    assert dict(manual_egress.MANUAL_EGRESS_BOUNDARY_MODULES) == {
        module: frozenset(operations)
        for module, operations in BOUNDARY_INVENTORY.items()
    }
    with pytest.raises(TypeError):
        manual_egress.MANUAL_EGRESS_OPERATIONS["unknown"] = object()  # type: ignore[index]
    with pytest.raises(TypeError):
        manual_egress.MANUAL_EGRESS_BOUNDARY_MODULES["future.py"] = frozenset()  # type: ignore[index]
    with pytest.raises(ValueError, match="non-empty"):
        manual_egress.ManualEgressOperation(
            "external_read",
            "fixture",
            frozenset(),
            frozenset({"host:fixture.invalid"}),
        )
    with pytest.raises(ValueError, match="exactly cover"):
        manual_egress.ManualEgressOperation(
            "external_read",
            "fixture",
            frozenset({"GET"}),
            frozenset({"host:fixture.invalid"}),
            frozenset({("POST", "host:fixture.invalid")}),
        )
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_OPERATION"):
        manual_egress.assert_manual_egress_allowed("legacy.source.future")
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_OPERATION"):
        manual_egress.guarded_manual_egress_call(
            "legacy.source.future",
            _unexpected_effect,
        )
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_METHOD"):
        manual_egress.guarded_manual_egress_call(
            "legacy.source.eis",
            _unexpected_effect,
        )

    for operation_id in sorted(EXPECTED_REGISTRY_METADATA):
        method, source = sorted(
            manual_egress.MANUAL_EGRESS_OPERATIONS[operation_id].bindings
        )[0]
        with pytest.raises(authority.ExternalAuthorityError) as error:
            manual_egress.assert_manual_egress_allowed(
                operation_id,
                method=method,
                source=source,
            )
        denial = str(error.value)
        assert "MDOS_V7_UNRATIFIED_DEFAULT_DENY" in denial
        assert operation_id in denial
        assert "http" not in denial.casefold()
        assert "@" not in denial

    for operation_id, (_, _, _methods, _sources) in sorted(
        EXPECTED_EXTENDED_REGISTRY_METADATA.items()
    ):
        method, source = sorted(
            manual_egress.MANUAL_EGRESS_OPERATIONS[operation_id].bindings
        )[0]
        with pytest.raises(authority.ExternalAuthorityError) as error:
            manual_egress.assert_manual_egress_allowed(
                operation_id,
                method=method,
                source=source,
            )
        denial = str(error.value)
        assert "MDOS_V7_UNRATIFIED_DEFAULT_DENY" in denial
        assert operation_id in denial


def test_exact_method_source_and_public_url_validation_fail_before_transport(
    isolated_authority: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del isolated_authority
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_METHOD"):
        manual_egress.assert_manual_egress_allowed(
            "legacy.source.2gis.dealer_catalog",
            method="POST /3.0/items",
            source="host:catalog.api.2gis.com",
        )
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_SOURCE"):
        manual_egress.assert_manual_egress_allowed(
            "legacy.source.2gis.dealer_catalog",
            method="GET /3.0/items",
            source="host:future.example",
        )
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_BINDING"):
        manual_egress.assert_manual_egress_allowed(
            "legacy.imap.attach_export",
            method="credential.read",
            source="imap:manager_mailbox",
        )

    monkeypatch.setattr(
        manual_egress, "assert_external_allowed", lambda _operation: None
    )
    rejected = {
        "file:///fixture": "UNKNOWN_SOURCE",
        "http://127.0.0.1/private": "UNKNOWN_SCHEME",
        "http://localhost/private": "UNKNOWN_SCHEME",
        "https://user:secret@example.test/private": "UNKNOWN_SOURCE",
    }
    for url, reason in rejected.items():
        with pytest.raises(authority.ExternalAuthorityError, match=reason):
            manual_egress.guarded_manual_http_call(
                "legacy.source.public_site.dealer_scrape",
                "GET",
                "public_http:dealer_site",
                url,
                _unexpected_effect,
            )

    bad_bing_urls = {
        "http://www.bing.com:4444/not-search": "UNKNOWN_SCHEME",
        "https://www.bing.com:4444/search": "UNKNOWN_PORT",
        "https://www.bing.com/not-search": "UNKNOWN_PATH",
        "https://evil.example/search": "UNKNOWN_SOURCE",
    }
    for url, reason in bad_bing_urls.items():
        with pytest.raises(authority.ExternalAuthorityError, match=reason):
            manual_egress.guarded_manual_http_call(
                "legacy.source.bing.dealer_search",
                "GET /search",
                "host:www.bing.com",
                url,
                _unexpected_effect,
            )

    marker = object()
    assert (
        manual_egress.guarded_manual_http_call(
            "legacy.source.bing.dealer_search",
            "GET /search",
            "host:www.bing.com",
            "https://www.bing.com:443/search?q=fixture",
            lambda _url, **_kwargs: marker,
            allow_redirects=False,
        )
        is marker
    )


def test_static_boundary_inventory_uses_only_registered_operation_ids() -> None:
    delegated_default_off_module = "lead_factory/tenderplan_isolated_transport.py"
    for relative, expected_operations in BOUNDARY_INVENTORY.items():
        path = ROOT / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        constants = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        guard_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id
            in {
                "assert_manual_egress_allowed",
                "guarded_manual_egress_attempt",
                "guarded_manual_egress_call",
                "guarded_manual_http_call",
            }
        ]
        if relative == delegated_default_off_module:
            delegated_guard_calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_assert_live_admission"
            ]
            assert delegated_guard_calls, relative
            assert (
                expected_operations
                == BOUNDARY_INVENTORY["lead_factory/tenderplan_shadow_canary.py"]
            )
        else:
            assert guard_calls, relative
            assert expected_operations <= constants, relative
        assert expected_operations <= set(manual_egress.MANUAL_EGRESS_OPERATIONS), (
            relative
        )

    assert dict(manual_egress.MANUAL_EGRESS_LOCAL_EXEMPTIONS) == {
        "lead_factory/imap_canary_runtime.py": frozenset(
            {
                "injected config mapping does not read process credentials; factory transport remains guarded",
            }
        ),
        "lead_factory/tenderplan_isolated_transport.py": frozenset(
            {
                "child worker remains hard default-off; parent shadow canary owns the exact egress guard",
            }
        ),
        "tb_webhook.py": frozenset(
            {
                "127.0.0.1 ThreadingHTTPServer listener",
                "local report/file IO",
                "local tunnel-process cleanup after a guarded start",
            }
        ),
        "tb_webhook_watchdog.py": frozenset({"127.0.0.1 health GET"}),
    }


def test_initial_http_boundaries_disable_redirects_on_every_guarded_call() -> None:
    modules = {
        "eis_client.py",
        "taskbot/bitrix.py",
        "taskbot/openrouter.py",
        "taskbot/telegram.py",
        "tb_ai.py",
        "tb_bitrix_readonly.py",
        "tb_damia.py",
    }
    guarded_calls = 0
    for relative in modules:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "guarded_manual_http_call"
            ):
                continue
            guarded_calls += 1
            redirects = [
                keyword.value
                for keyword in node.keywords
                if keyword.arg == "allow_redirects"
            ]
            assert len(redirects) == 1, relative
            assert isinstance(redirects[0], ast.Constant), relative
            assert redirects[0].value is False, relative
    assert guarded_calls == 9


def test_residual_raw_transport_inventory_is_exactly_local_only() -> None:
    target_modules = {
        relative
        for relative in BOUNDARY_INVENTORY
        if relative in manual_egress.MANUAL_EGRESS_BOUNDARY_MODULES
        and relative
        not in {
            "eis_client.py",
            "taskbot/bitrix.py",
            "taskbot/openrouter.py",
            "taskbot/telegram.py",
            "tb_ai.py",
            "tb_attach_export.py",
            "tb_bitrix_readonly.py",
            "tb_damia.py",
            "tb_facade.py",
            "tb_inbox_export.py",
        }
    }

    def dotted(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{dotted(node.value)}.{node.attr}".lstrip(".")
        return ""

    raw_names = {
        "requests.get",
        "requests.post",
        "_session.get",
        "self._session.post",
        "session.post",
        "_rq.get",
        "subprocess.run",
        "subprocess.Popen",
        "imaplib.IMAP4_SSL",
        "ThreadingHTTPServer",
    }
    discovered: set[tuple[str, str, str]] = set()
    guarded_http_calls = 0
    for relative in target_modules:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = dotted(node.func)
            if call_name == "guarded_manual_http_call":
                guarded_http_calls += 1
                redirect_keywords = [
                    keyword
                    for keyword in node.keywords
                    if keyword.arg == "allow_redirects"
                ]
                assert len(redirect_keywords) == 1, relative
                assert isinstance(redirect_keywords[0].value, ast.Constant), relative
                assert redirect_keywords[0].value.value is False, relative
            if call_name not in raw_names and not call_name.endswith(".serve_forever"):
                continue
            owner = "<module>"
            current: ast.AST = node
            while current in parents:
                current = parents[current]
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = current.name
                    break
            discovered.add((relative, owner, call_name))

    assert discovered == {
        (
            "lead_factory/tenderplan_isolated_transport.py",
            "_perform_worker_post",
            "session.post",
        ),
        (
            "lead_factory/tenderplan_isolated_transport.py",
            "_start_process",
            "subprocess.Popen",
        ),
        (
            "lead_factory/tenderplan_shadow_canary.py",
            "post_json",
            "self._session.post",
        ),
        ("tb_webhook.py", "serve", "ThreadingHTTPServer"),
        ("tb_webhook.py", "serve", "srv.serve_forever"),
        ("tb_webhook.py", "run", "ThreadingHTTPServer"),
        ("tb_webhook.py", "run_serveo", "ThreadingHTTPServer"),
        ("tb_webhook_watchdog.py", "_local_ok", "requests.get"),
    }
    assert guarded_http_calls == 26
    watchdog_source = (ROOT / "tb_webhook_watchdog.py").read_text(encoding="utf-8")
    webhook_source = (ROOT / "tb_webhook.py").read_text(encoding="utf-8")
    assert "http://127.0.0.1:{WEBHOOK_PORT}/health" in watchdog_source
    assert 'ThreadingHTTPServer(("127.0.0.1", port), _Handler)' in webhook_source


def test_residual_modules_are_import_safe_without_credentials_or_transport() -> None:
    modules = (
        "lead_factory.imap_canary_runtime",
        "tb_dealers_2gis",
        "tb_dealers_email",
        "tb_dealers_pool",
        "tb_dealers_serper",
        "tb_dealers_yandex",
        "tb_docs",
        "tb_eisdocs",
        "tb_exportbase_site_enrich",
        "tb_fetch_kp",
        "tb_leaddocs",
        "tb_probe_2gis",
        "tb_probe_bing",
        "tb_probe_damia_br",
        "tb_probe_net",
        "tb_probe_scrape",
        "tb_retail_pool",
        "tb_webhook_watchdog",
        "tb_webhook",
    )
    with (
        patch("dotenv.load_dotenv", _unexpected_effect),
        patch("imaplib.IMAP4_SSL", _unexpected_effect),
        patch("requests.get", _unexpected_effect),
        patch("requests.post", _unexpected_effect),
    ):
        for module_name in modules:
            importlib.import_module(module_name)


def test_residual_direct_helpers_deny_before_any_transport(
    isolated_authority: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    del isolated_authority
    import tb_dealers_2gis
    import tb_dealers_email
    import tb_dealers_pool
    import tb_dealers_serper
    import tb_dealers_yandex
    import tb_docs
    import tb_eisdocs
    import tb_exportbase_site_enrich
    import tb_fetch_kp
    import tb_leaddocs
    import tb_probe_2gis
    import tb_probe_bing
    import tb_probe_damia_br
    import tb_probe_net
    import tb_probe_scrape
    import tb_retail_pool
    import tb_webhook
    import tb_webhook_watchdog

    monkeypatch.setattr(requests := tb_dealers_2gis.requests, "get", _unexpected_effect)
    monkeypatch.setattr(requests, "post", _unexpected_effect)
    monkeypatch.setattr(tb_webhook_watchdog, "_load_state", lambda: {})
    monkeypatch.setattr(tb_webhook, "_find_cloudflared", lambda: "fixture-cloudflared")

    calls = (
        lambda: tb_dealers_2gis.fetch("fixture", "fixture", set(), key="fixture"),
        lambda: tb_dealers_email.ddg("fixture", tries=1),
        lambda: tb_dealers_email.site_emails_and_name("example.test"),
        lambda: tb_dealers_pool.ddg("fixture"),
        lambda: tb_dealers_pool.bing("fixture"),
        lambda: tb_dealers_pool.twogis_names("fixture", "fixture", key="fixture"),
        lambda: tb_dealers_pool.emails_and_name("example.test"),
        lambda: tb_dealers_serper.serper("fixture", tries=1, key="fixture"),
        lambda: tb_dealers_yandex.api_search(
            "fixture", key="fixture", folder="fixture"
        ),
        lambda: tb_docs._download_one("https://example.test/doc", "doc", 100, 1),
        lambda: tb_eisdocs._get("https://zakupki.gov.ru/fixture", timeout=1),
        lambda: tb_exportbase_site_enrich._crawl_one(
            {"site_url": "https://example.test", "site_key": "example.test"}
        ),
        lambda: tb_fetch_kp.download("fixture", "fixture.pdf", "1"),
        lambda: tb_leaddocs._bitrix_attach("1", "fixture", b"x", "fixture", "fixture"),
        lambda: tb_leaddocs._imap_call("search", _unexpected_effect),
        lambda: tb_leaddocs._telegram_alert("fixture"),
        lambda: tb_probe_2gis.test("", key="fixture"),
        tb_probe_bing.main,
        lambda: tb_probe_damia_br.hit(
            "https://api.damia.ru/br/br", {"inn": "fixture"}, key="fixture"
        ),
        tb_probe_net.main,
        lambda: tb_probe_scrape.ddg("fixture"),
        lambda: tb_probe_scrape.emails_from_site("https://example.test"),
        lambda: tb_retail_pool.fetch_all("example.test"),
        lambda: tb_webhook_watchdog._public_ok("https://example.test"),
        tb_webhook_watchdog._active_urls,
        lambda: tb_webhook_watchdog._restart("fixture"),
        lambda: tb_webhook.register("https://example.test"),
        lambda: tb_webhook._alert("fixture"),
        lambda: tb_webhook._verify(b"{}"),
        lambda: tb_webhook.run(18765),
    )
    for call in calls:
        with pytest.raises(authority.ExternalAuthorityError):
            call()
    assert not tmp_path.joinpath("unexpected").exists()


def test_new_http_retries_recheck_authority_before_every_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tb_dealers_serper
    import tb_eisdocs

    authority_calls: list[str] = []
    monkeypatch.setattr(
        manual_egress,
        "assert_external_allowed",
        lambda operation: authority_calls.append(operation),
    )
    monkeypatch.setattr(tb_dealers_serper.time, "sleep", lambda _seconds: None)
    serper_transport_calls = 0

    def serper_post(*_args, **_kwargs):
        nonlocal serper_transport_calls
        serper_transport_calls += 1
        return SimpleNamespace(status_code=503, text="fixture")

    monkeypatch.setattr(tb_dealers_serper.requests, "post", serper_post)
    assert tb_dealers_serper.serper("fixture", tries=3, key="fixture") == (
        None,
        "net/limit",
    )
    assert serper_transport_calls == 3
    assert (
        authority_calls
        == ["manual_egress:external_read:serper:legacy.source.serper.dealer_search"] * 3
    )

    authority_calls.clear()
    monkeypatch.setattr(tb_eisdocs.time, "sleep", lambda _seconds: None)
    eis_transport_calls = 0

    def eis_get(*_args, **_kwargs):
        nonlocal eis_transport_calls
        eis_transport_calls += 1
        if eis_transport_calls < 3:
            raise tb_eisdocs.requests.ConnectionError("fixture")
        return SimpleNamespace(status_code=200, text="fixture")

    monkeypatch.setattr(tb_eisdocs.requests, "get", eis_get)
    assert (
        tb_eisdocs._get("https://zakupki.gov.ru/fixture", timeout=1).text == "fixture"
    )
    assert eis_transport_calls == 3
    assert (
        authority_calls
        == ["manual_egress:external_read:eis:legacy.source.eis.document_download"] * 3
    )


def test_http_retries_recheck_authority_before_every_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import eis_client
    import tb_damia

    authority_calls: list[str] = []
    monkeypatch.setattr(
        manual_egress,
        "assert_external_allowed",
        lambda operation: authority_calls.append(operation),
    )
    monkeypatch.setattr(eis_client.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(tb_damia.time, "sleep", lambda _seconds: None)

    eis_responses = [
        SimpleNamespace(status_code=500, text="first"),
        SimpleNamespace(status_code=503, text="second"),
        SimpleNamespace(status_code=200, text="ok"),
    ]
    eis = eis_client.EisClient(timeout=1, pause=0)
    eis_transport_calls: list[int] = []

    def eis_get(*_args, **_kwargs):
        eis_transport_calls.append(1)
        return eis_responses.pop(0)

    monkeypatch.setattr(eis.session, "get", eis_get)
    assert eis._get(eis_client.SEARCH_URL) == "ok"
    assert len(eis_transport_calls) == 3
    assert eis.request_count == 1
    assert authority_calls == ["manual_egress:external_read:eis:legacy.source.eis"] * 3

    authority_calls.clear()
    damia_responses = [
        SimpleNamespace(status_code=500, text="first", json=lambda: {}),
        SimpleNamespace(status_code=503, text="second", json=lambda: {}),
        SimpleNamespace(status_code=200, text="{}", json=lambda: {}),
    ]
    damia = tb_damia.DamiaClient("fixture-key", timeout=1, pause=0)
    damia_transport_calls: list[int] = []

    def damia_get(*_args, **_kwargs):
        damia_transport_calls.append(1)
        return damia_responses.pop(0)

    monkeypatch.setattr(damia.session, "get", damia_get)
    assert damia._get("zsearch", {}) == {}
    assert len(damia_transport_calls) == 3
    assert damia.request_count == 1
    assert (
        authority_calls == ["manual_egress:external_read:damia:legacy.source.damia"] * 3
    )


def test_authority_change_between_retries_blocks_the_next_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import eis_client

    checks = 0
    transport_calls = 0

    def changing_authority(_operation: str) -> None:
        nonlocal checks
        checks += 1
        if checks == 2:
            raise authority.ExternalAuthorityError("fixture authority changed")

    def failing_transport(*_args, **_kwargs):
        nonlocal transport_calls
        transport_calls += 1
        raise eis_client.requests.ConnectionError("fixture")

    monkeypatch.setattr(manual_egress, "assert_external_allowed", changing_authority)
    monkeypatch.setattr(eis_client.time, "sleep", lambda _seconds: None)
    client = eis_client.EisClient(timeout=1, pause=0)
    monkeypatch.setattr(client.session, "get", failing_transport)

    with pytest.raises(authority.ExternalAuthorityError, match="authority changed"):
        client._get(eis_client.SEARCH_URL)
    assert checks == 2
    assert transport_calls == 1
    assert client.request_count == 1


def test_taskbot_method_inventories_are_exact_and_unknown_fails_before_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import taskbot.bitrix as bitrix_module
    import taskbot.telegram as telegram_module

    assert bitrix_module._TASK_READ_ONLY_BITRIX_METHODS == {
        "app.info",
        "tasks.task.get",
        "tasks.task.list",
    }
    assert bitrix_module._TASK_WRITE_BITRIX_METHODS == {
        "tasks.task.add",
        "tasks.task.complete",
        "tasks.task.delete",
        "tasks.task.start",
        "tasks.task.update",
    }
    assert bitrix_module._TASK_V3_WRITE_BITRIX_METHODS == {"tasks.task.result.add"}
    assert telegram_module._TELEGRAM_READ_METHODS == {
        "getFile",
        "getMe",
        "getUpdates",
    }
    assert telegram_module._TELEGRAM_CONTACT_METHODS == {
        "answerCallbackQuery",
        "editMessageText",
        "sendMessage",
    }

    bitrix = bitrix_module.BitrixTasks("https://fixture.bitrix24.ru/rest/1/token")
    telegram = telegram_module.Telegram("fixture-token")
    monkeypatch.setattr(bitrix._http, "post", _unexpected_effect)
    monkeypatch.setattr(telegram._http, "post", _unexpected_effect)
    with pytest.raises(
        bitrix_module.BitrixMethodRejected,
        match="TASKBOT_BITRIX_METHOD_REJECTED",
    ):
        bitrix._call("tasks.future.inspect", {})
    with pytest.raises(
        bitrix_module.BitrixMethodRejected,
        match="TASKBOT_BITRIX_METHOD_REJECTED",
    ):
        bitrix._call_v3("tasks.task.get", {})
    with pytest.raises(
        telegram_module.TelegramMethodRejected,
        match="TASKBOT_TELEGRAM_METHOD_REJECTED",
    ):
        telegram._call("getupdates", {})


def test_imap_helpers_and_secret_loaders_are_guarded_when_called_directly(
    isolated_authority: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del isolated_authority
    import tb_attach_export
    import tb_facade
    import tb_inbox_export

    fake_imap = SimpleNamespace(
        fetch=_unexpected_effect,
        list=_unexpected_effect,
        logout=_unexpected_effect,
        search=_unexpected_effect,
        select=_unexpected_effect,
    )
    with pytest.raises(
        authority.ExternalAuthorityError, match="legacy.imap.attach_export"
    ):
        tb_attach_export._find_folders(fake_imap)
    with pytest.raises(
        authority.ExternalAuthorityError, match="legacy.imap.attach_export"
    ):
        tb_attach_export.harvest(fake_imap, "INBOX", set(), [])
    with pytest.raises(
        authority.ExternalAuthorityError, match="legacy.imap.inbox_export"
    ):
        tb_inbox_export._find_sent(fake_imap)

    monkeypatch.setattr(tb_facade, "_imap", lambda: fake_imap)
    monkeypatch.setattr(tb_facade, "_processed", lambda: {"fixture-existing"})
    monkeypatch.setattr(tb_facade, "_save_processed", lambda _seen: None)
    assert tb_facade.poll({}, {}) == 0

    monkeypatch.setattr(tb_attach_export, "load_dotenv", _unexpected_effect)
    monkeypatch.setattr(tb_inbox_export, "load_dotenv", _unexpected_effect)
    monkeypatch.setattr(tb_attach_export.os, "getenv", _unexpected_effect)
    with pytest.raises(
        authority.ExternalAuthorityError, match="legacy.imap.attach_export"
    ):
        tb_attach_export._load_runtime_config()
    with pytest.raises(
        authority.ExternalAuthorityError, match="legacy.imap.inbox_export"
    ):
        tb_inbox_export._load_runtime_config()
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_METHOD"):
        tb_attach_export._imap_call("future", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="UNKNOWN_SOURCE"):
        tb_facade._imap_call(
            "search",
            "imap:future_mailbox",
            _unexpected_effect,
        )


def test_imap_export_modules_are_import_safe_before_authority() -> None:
    import tb_attach_export
    import tb_inbox_export

    with (
        patch("dotenv.load_dotenv", _unexpected_effect),
        patch("os.getenv", _unexpected_effect),
    ):
        importlib.reload(tb_attach_export)
        importlib.reload(tb_inbox_export)

    # Restore their imported loader references for tests which explicitly
    # exercise a future-authorized local configuration path.
    importlib.reload(tb_attach_export)
    importlib.reload(tb_inbox_export)


def test_shared_http_ai_and_imap_boundaries_stop_before_transport(
    isolated_authority: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    del isolated_authority
    import eis_client
    import tb_ai
    import tb_attach_export
    import tb_bitrix_readonly
    import tb_damia
    import tb_facade
    import tb_inbox_export
    from taskbot.bitrix import BitrixTasks
    from taskbot.openrouter import OpenRouter
    from taskbot.telegram import Telegram

    eis = eis_client.EisClient(timeout=1, pause=0)
    monkeypatch.setattr(eis.session, "get", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="legacy.source.eis"):
        eis._get(eis_client.SEARCH_URL)
    assert eis.request_count == 0

    damia = tb_damia.DamiaClient("fixture-key", timeout=1, pause=0)
    monkeypatch.setattr(damia.session, "get", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="legacy.source.damia"):
        damia._get("zsearch", {})
    assert damia.request_count == 0

    monkeypatch.setattr(tb_ai.requests, "post", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="legacy.ai.openrouter"):
        tb_ai._post_openrouter(headers={}, payload={}, timeout=1)

    monkeypatch.setattr(tb_bitrix_readonly.requests, "post", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="legacy.bitrix.read"):
        tb_bitrix_readonly.call(
            "https://fixture.bitrix24.ru/rest/1/token",
            "crm.lead.list",
            {},
            allowed_methods={"crm.lead.list"},
        )

    bitrix = BitrixTasks("https://fixture.bitrix24.ru/rest/1/token")
    monkeypatch.setattr(bitrix._http, "post", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="taskbot.bitrix.read"):
        bitrix._call("tasks.task.get", {"taskId": 1})
    with pytest.raises(authority.ExternalAuthorityError, match="taskbot.bitrix.write"):
        bitrix._call("tasks.task.add", {"fields": {}})

    openrouter = OpenRouter("fixture-key", "fixture-model", "fixture-speech")
    monkeypatch.setattr(openrouter._http, "post", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="taskbot.openrouter"):
        openrouter._post("chat/completions", {})

    telegram = Telegram("fixture-token")
    monkeypatch.setattr(telegram._http, "post", _unexpected_effect)
    monkeypatch.setattr(telegram._http, "get", _unexpected_effect)
    with pytest.raises(authority.ExternalAuthorityError, match="taskbot.telegram.read"):
        telegram._call("getUpdates", {})
    with pytest.raises(
        authority.ExternalAuthorityError, match="taskbot.telegram.contact"
    ):
        telegram._call("sendMessage", {})
    with pytest.raises(authority.ExternalAuthorityError, match="taskbot.telegram.read"):
        telegram.download_file("fixture", tmp_path / "fixture.ogg")

    monkeypatch.setattr(tb_attach_export.imaplib, "IMAP4_SSL", _unexpected_effect)
    monkeypatch.setattr(tb_inbox_export.imaplib, "IMAP4_SSL", _unexpected_effect)
    monkeypatch.setattr(tb_facade.imaplib, "IMAP4_SSL", _unexpected_effect)
    monkeypatch.setattr(tb_facade.tb_config, "load_secrets", _unexpected_effect)
    with pytest.raises(
        authority.ExternalAuthorityError, match="legacy.imap.attach_export"
    ):
        tb_attach_export.main()
    with pytest.raises(
        authority.ExternalAuthorityError, match="legacy.imap.inbox_export"
    ):
        tb_inbox_export.main()
    with pytest.raises(authority.ExternalAuthorityError, match="legacy.imap.facade"):
        tb_facade._imap()


def test_exact_initial_http_bindings_reach_only_reviewed_routes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import tb_ai
    import tb_bitrix_readonly
    import taskbot.bitrix as bitrix_module
    import taskbot.openrouter as openrouter_module
    import taskbot.telegram as telegram_module

    authority_calls: list[str] = []
    transport_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        manual_egress,
        "assert_external_allowed",
        lambda operation: authority_calls.append(operation),
    )

    class Response:
        def __init__(self, body: dict[str, object], content: bytes = b"") -> None:
            self._body = body
            self.content = content

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self._body

    def transport(label: str, body: dict[str, object], content: bytes = b""):
        def call(url: str, **kwargs: object) -> Response:
            assert kwargs["allow_redirects"] is False
            transport_calls.append((label, url))
            return Response(body, content)

        return call

    monkeypatch.setattr(
        tb_ai.requests,
        "post",
        transport("legacy-ai", {"choices": []}),
    )
    tb_ai._post_openrouter(headers={}, payload={}, timeout=1)

    monkeypatch.setattr(
        tb_bitrix_readonly.requests,
        "post",
        transport("readonly-bitrix", {"result": []}),
    )
    assert tb_bitrix_readonly.call(
        "https://fixture.bitrix24.ru/rest/1/token",
        "crm.lead.list",
        {},
        allowed_methods={"crm.lead.list"},
    ) == {"result": []}

    bitrix = bitrix_module.BitrixTasks("https://fixture.bitrix24.ru/rest/1/token")
    monkeypatch.setattr(
        bitrix._http,
        "post",
        transport("taskbot-bitrix", {"result": {"task": {"id": "1"}}}),
    )
    assert bitrix._call("tasks.task.get", {"taskId": 1}) == {"task": {"id": "1"}}

    openrouter = openrouter_module.OpenRouter("key", "model", "speech")
    monkeypatch.setattr(
        openrouter._http,
        "post",
        transport("taskbot-openrouter", {"choices": []}),
    )
    assert openrouter._post("chat/completions", {}) == {"choices": []}

    telegram = telegram_module.Telegram("fixture-token")
    monkeypatch.setattr(
        telegram._http,
        "post",
        transport("telegram-read", {"ok": True, "result": {"id": 1}}),
    )
    assert telegram._call("getMe", {}) == {"id": 1}
    monkeypatch.setattr(
        telegram._http,
        "get",
        transport("telegram-file", {}, b"fixture"),
    )
    destination = tmp_path / "fixture.bin"
    telegram.download_file("documents/fixture.bin", destination)
    assert destination.read_bytes() == b"fixture"

    assert len(authority_calls) == len(transport_calls) == 6
    assert all(url.startswith("https://") for _label, url in transport_calls)


def test_authority_drift_cannot_open_registered_manual_egress(
    isolated_authority: None,
) -> None:
    del isolated_authority
    freeze = json.loads(authority._FREEZE_PATH.read_text(encoding="utf-8"))
    freeze["external_reads_enabled"] = True
    authority._FREEZE_PATH.write_text(json.dumps(freeze), encoding="utf-8")
    with pytest.raises(authority.ExternalAuthorityError, match="AUTHORITY_INVALID"):
        manual_egress.assert_manual_egress_allowed(
            "legacy.source.eis",
            method="GET /epz/contract/search/results.html",
            source="host:zakupki.gov.ru",
        )
