"""Closed registry for legacy/manual network boundaries under MDOS v7.1 RC1.

The registry is deliberately code-owned and contains only stable, non-secret
operation identifiers.  It is not an enable switch.  Every registered
operation delegates to the immutable RC1 authority boundary, which denies all
external reads, writes, contact and spend while the beachhead is unratified.

Callers use :func:`guarded_manual_egress_call` at the last local point before
each transport attempt, and :func:`assert_manual_egress_allowed` before a
credential lookup. Unknown operation identifiers fail closed and never become
an implicit route. Residual HTTP callers disable requests-managed redirects;
a future redirect hop requires its own separately guarded attempt.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from types import MappingProxyType
from typing import Callable, Final, ParamSpec, TypeVar
from urllib.parse import urlparse

from .authority import ExternalAuthorityError, assert_external_allowed


@dataclass(frozen=True)
class ManualEgressOperation:
    authority_flag: str
    channel: str
    methods: frozenset[str]
    sources: frozenset[str]
    bindings: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self) -> None:
        """Reject incomplete registries and seal exact method/source pairs."""

        if not self.methods or not self.sources:
            raise ValueError("manual egress methods and sources must be non-empty")
        bindings = self.bindings or frozenset(
            (method, source) for method in self.methods for source in self.sources
        )
        if (
            not bindings
            or {method for method, _source in bindings} != set(self.methods)
            or {source for _method, source in bindings} != set(self.sources)
            or any(
                method not in self.methods or source not in self.sources
                for method, source in bindings
            )
        ):
            raise ValueError(
                "manual egress bindings must exactly cover methods and sources"
            )
        object.__setattr__(self, "bindings", frozenset(bindings))


MANUAL_EGRESS_OPERATIONS: Final = MappingProxyType(
    {
        "legacy.ai.openrouter": ManualEgressOperation(
            "spend",
            "openrouter",
            frozenset({"POST /api/v1/chat/completions"}),
            frozenset({"host:openrouter.ai"}),
        ),
        "legacy.bitrix.read": ManualEgressOperation(
            "external_read",
            "bitrix24",
            frozenset(
                {
                    "POST /rest/{user}/{token}/crm.activity.list.json",
                    "POST /rest/{user}/{token}/crm.company.list.json",
                    "POST /rest/{user}/{token}/crm.contact.list.json",
                    "POST /rest/{user}/{token}/crm.deal.fields.json",
                    "POST /rest/{user}/{token}/crm.deal.get.json",
                    "POST /rest/{user}/{token}/crm.deal.list.json",
                    "POST /rest/{user}/{token}/crm.dealcategory.list.json",
                    "POST /rest/{user}/{token}/crm.dealcategory.stage.list.json",
                    "POST /rest/{user}/{token}/crm.lead.list.json",
                    "POST /rest/{user}/{token}/crm.quote.list.json",
                    "POST /rest/{user}/{token}/crm.timeline.comment.list.json",
                    "POST /rest/{user}/{token}/disk.file.get.json",
                }
            ),
            frozenset({"bitrix24:webhook"}),
        ),
        "legacy.diagnostic.network_probe": ManualEgressOperation(
            "external_read",
            "network_diagnostic",
            frozenset({"credential.read", "GET", "POST"}),
            frozenset(
                {
                    "env:proxy_presence",
                    "host:alcon-city.ru",
                    "host:alumkomplekt.bitrix24.ru",
                    "host:html.duckduckgo.com",
                    "host:www.bing.com",
                }
            ),
            frozenset(
                {
                    ("credential.read", "env:proxy_presence"),
                    ("GET", "host:alcon-city.ru"),
                    ("GET", "host:alumkomplekt.bitrix24.ru"),
                    ("GET", "host:www.bing.com"),
                    ("POST", "host:html.duckduckgo.com"),
                }
            ),
        ),
        "legacy.imap.attach_export": ManualEgressOperation(
            "external_read",
            "imap",
            frozenset(
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
                }
            ),
            frozenset({"env:manager_imap", "imap:manager_mailbox"}),
            frozenset(
                {("credential.read", "env:manager_imap")}
                | {
                    (method, "imap:manager_mailbox")
                    for method in {
                        "connect",
                        "fetch.message",
                        "id.command",
                        "id.response",
                        "list",
                        "login",
                        "logout",
                        "search",
                        "select.readonly",
                    }
                }
            ),
        ),
        "legacy.imap.facade": ManualEgressOperation(
            "external_read",
            "imap",
            frozenset(
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
                }
            ),
            frozenset({"config:legacy_secrets", "imap:manager_mailbox"}),
            frozenset(
                {("credential.read", "config:legacy_secrets")}
                | {
                    (method, "imap:manager_mailbox")
                    for method in {
                        "connect",
                        "fetch.message",
                        "id.command",
                        "id.response",
                        "login",
                        "logout",
                        "search",
                        "select.readonly",
                    }
                }
            ),
        ),
        "legacy.imap.inbox_export": ManualEgressOperation(
            "external_read",
            "imap",
            frozenset(
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
                }
            ),
            frozenset({"env:manager_imap", "imap:manager_mailbox"}),
            frozenset(
                {("credential.read", "env:manager_imap")}
                | {
                    (method, "imap:manager_mailbox")
                    for method in {
                        "connect",
                        "fetch.message",
                        "id.command",
                        "id.response",
                        "list",
                        "login",
                        "logout",
                        "search",
                        "select.readonly",
                    }
                }
            ),
        ),
        "legacy.source.damia": ManualEgressOperation(
            "external_read",
            "damia",
            frozenset(
                {
                    "GET /zakupki/contracts",
                    "GET /zakupki/eruz",
                    "GET /zakupki/rnp",
                    "GET /zakupki/zakupka",
                    "GET /zakupki/zsearch",
                }
            ),
            frozenset({"host:api.damia.ru"}),
        ),
        "legacy.source.eis": ManualEgressOperation(
            "external_read",
            "eis",
            frozenset(
                {
                    "GET /epz/contract/contractCard/common-info.html",
                    "GET /epz/contract/search/results.html",
                }
            ),
            frozenset({"host:zakupki.gov.ru"}),
        ),
        "taskbot.bitrix.read": ManualEgressOperation(
            "external_read",
            "bitrix24",
            frozenset(
                {
                    "POST /rest/{user}/{token}/app.info.json",
                    "POST /rest/{user}/{token}/tasks.task.get.json",
                    "POST /rest/{user}/{token}/tasks.task.list.json",
                }
            ),
            frozenset({"bitrix24:webhook"}),
        ),
        "taskbot.bitrix.write": ManualEgressOperation(
            "external_write",
            "bitrix24",
            frozenset(
                {
                    "POST /rest/api/{user}/{token}/tasks.task.result.add",
                    "POST /rest/{user}/{token}/tasks.task.add.json",
                    "POST /rest/{user}/{token}/tasks.task.complete.json",
                    "POST /rest/{user}/{token}/tasks.task.delete.json",
                    "POST /rest/{user}/{token}/tasks.task.start.json",
                    "POST /rest/{user}/{token}/tasks.task.update.json",
                }
            ),
            frozenset({"bitrix24:webhook"}),
        ),
        "taskbot.openrouter": ManualEgressOperation(
            "spend",
            "openrouter",
            frozenset(
                {
                    "POST /api/v1/audio/transcriptions",
                    "POST /api/v1/chat/completions",
                }
            ),
            frozenset({"host:openrouter.ai"}),
        ),
        "taskbot.telegram.contact": ManualEgressOperation(
            "contact",
            "telegram",
            frozenset(
                {
                    "POST /bot{token}/answerCallbackQuery",
                    "POST /bot{token}/editMessageText",
                    "POST /bot{token}/sendMessage",
                }
            ),
            frozenset({"host:api.telegram.org"}),
        ),
        "taskbot.telegram.read": ManualEgressOperation(
            "external_read",
            "telegram",
            frozenset(
                {
                    "GET /file/bot{token}/{path...}",
                    "POST /bot{token}/getFile",
                    "POST /bot{token}/getMe",
                    "POST /bot{token}/getUpdates",
                }
            ),
            frozenset({"host:api.telegram.org"}),
        ),
        "lead_factory.imap.canary": ManualEgressOperation(
            "external_read",
            "imap",
            frozenset({"credential.read", "connect", "login", "logout"}),
            frozenset({"imap:canary_mailbox"}),
        ),
        "lead_factory.source.tenderplan.shadow_canary": ManualEgressOperation(
            "external_read",
            "tenderplan",
            frozenset({"credential.read", "POST /api/search/v2/list"}),
            frozenset({"authref:tenderplan_pat", "host:tenderplan.ru"}),
            frozenset(
                {
                    ("credential.read", "authref:tenderplan_pat"),
                    ("POST /api/search/v2/list", "host:tenderplan.ru"),
                }
            ),
        ),
        "legacy.bitrix.dealer_dedup": ManualEgressOperation(
            "external_read",
            "bitrix24",
            frozenset(
                {
                    "credential.read",
                    "client_keys",
                    "known_contacts",
                    "crm.company.list",
                    "crm.contact.list",
                    "crm.lead.list",
                }
            ),
            frozenset({"bitrix24:legacy_crm"}),
        ),
        "legacy.bitrix.exportbase_dedup": ManualEgressOperation(
            "external_read",
            "bitrix24",
            frozenset({"known_contacts"}),
            frozenset({"bitrix24:legacy_crm"}),
        ),
        "legacy.bitrix.kp_export": ManualEgressOperation(
            "external_read",
            "bitrix24",
            frozenset(
                {
                    "credential.read",
                    "crm.deal.list",
                    "crm.timeline.comment.list",
                    "disk.file.get",
                }
            ),
            frozenset({"bitrix24:legacy_crm"}),
        ),
        "legacy.bitrix.kp_download": ManualEgressOperation(
            "external_read",
            "bitrix24",
            frozenset({"GET"}),
            frozenset({"public_http:bitrix_download"}),
        ),
        "legacy.bitrix.leaddocs.attach": ManualEgressOperation(
            "external_write",
            "bitrix24",
            frozenset({"credential.read", "crm.timeline.comment.add"}),
            frozenset({"bitrix24:legacy_crm"}),
        ),
        "legacy.imap.leaddocs": ManualEgressOperation(
            "external_read",
            "imap",
            frozenset(
                {
                    "credential.read",
                    "connect",
                    "list",
                    "select.readonly",
                    "search",
                    "fetch.header",
                    "fetch.message",
                    "login",
                    "logout",
                }
            ),
            frozenset({"imap:manager_mailbox"}),
        ),
        "legacy.source.2gis.dealer_catalog": ManualEgressOperation(
            "external_read",
            "2gis",
            frozenset({"credential.read", "GET /3.0/items"}),
            frozenset({"host:catalog.api.2gis.com"}),
        ),
        "legacy.source.bing.dealer_search": ManualEgressOperation(
            "external_read",
            "bing",
            frozenset({"GET /search"}),
            frozenset({"host:www.bing.com"}),
        ),
        "legacy.source.damia.probe": ManualEgressOperation(
            "external_read",
            "damia",
            frozenset(
                {
                    "credential.read",
                    "GET /br/br",
                    "GET /br/search",
                    "GET /br/sug",
                    "GET /org/search",
                }
            ),
            frozenset({"host:api.damia.ru"}),
        ),
        "legacy.source.duckduckgo.dealer_search": ManualEgressOperation(
            "external_read",
            "duckduckgo",
            frozenset({"POST /html/"}),
            frozenset({"host:html.duckduckgo.com"}),
        ),
        "legacy.source.eis.document_download": ManualEgressOperation(
            "external_read",
            "eis",
            frozenset({"GET"}),
            frozenset({"host:zakupki.gov.ru"}),
        ),
        "legacy.source.exportbase.site_scrape": ManualEgressOperation(
            "external_read",
            "public_site",
            frozenset({"GET"}),
            frozenset({"public_http:exportbase_site"}),
        ),
        "legacy.source.procurement.document_download": ManualEgressOperation(
            "external_read",
            "procurement_document",
            frozenset({"GET"}),
            frozenset({"public_http:procurement_document"}),
        ),
        "legacy.source.public_site.dealer_scrape": ManualEgressOperation(
            "external_read",
            "public_site",
            frozenset({"GET"}),
            frozenset({"public_http:dealer_site"}),
        ),
        "legacy.source.serper.dealer_search": ManualEgressOperation(
            "external_read",
            "serper",
            frozenset({"credential.read", "POST /search"}),
            frozenset({"host:google.serper.dev"}),
        ),
        "legacy.source.yandex.operation_poll": ManualEgressOperation(
            "external_read",
            "yandex_search",
            frozenset({"GET /operations/{id}"}),
            frozenset({"host:operation.api.cloud.yandex.net"}),
        ),
        "legacy.source.yandex.search_submit": ManualEgressOperation(
            "external_read",
            "yandex_search",
            frozenset({"credential.read", "POST /v2/web/search"}),
            frozenset({"host:searchapi.api.cloud.yandex.net"}),
        ),
        "legacy.telegram.leaddocs.contact": ManualEgressOperation(
            "contact",
            "telegram",
            frozenset({"credential.read", "sendMessage"}),
            frozenset({"telegram:manager_alert"}),
        ),
        "legacy.webhook.public_health": ManualEgressOperation(
            "external_read",
            "webhook_health",
            frozenset({"GET"}),
            frozenset({"public_http:webhook_health"}),
        ),
        "legacy.webhook.telegram.alert": ManualEgressOperation(
            "contact",
            "telegram",
            frozenset({"credential.read", "sendMessage"}),
            frozenset({"telegram:delivery_alert"}),
        ),
        "legacy.webhook.tunnel.cloudflared": ManualEgressOperation(
            "external_write",
            "cloudflare_tunnel",
            frozenset({"start"}),
            frozenset({"tunnel:trycloudflare"}),
        ),
        "legacy.webhook.tunnel.serveo": ManualEgressOperation(
            "external_write",
            "ssh_tunnel",
            frozenset({"start"}),
            frozenset({"tunnel:serveo"}),
        ),
        "legacy.webhook.unisender.read": ManualEgressOperation(
            "external_read",
            "unisender",
            frozenset({"credential.read", "webhook/list.json"}),
            frozenset({"unisender:webhook_api"}),
        ),
        "legacy.webhook.unisender.verify": ManualEgressOperation(
            "external_read",
            "unisender",
            frozenset({"credential.read"}),
            frozenset({"env:UNISENDER_GO_API_KEY"}),
        ),
        "legacy.webhook.unisender.write": ManualEgressOperation(
            "external_write",
            "unisender",
            frozenset({"credential.read", "webhook/delete.json", "webhook/set.json"}),
            frozenset({"unisender:webhook_api"}),
        ),
        "legacy.webhook.watchdog.restart": ManualEgressOperation(
            "external_write",
            "scheduled_task",
            frozenset({"end", "run"}),
            frozenset({"task:ALT_DeliveryWebhook"}),
        ),
    }
)

# Exact code-owned inventory.  This map is evidence only: membership never
# enables an operation and every entry still passes through RC1 authority.
MANUAL_EGRESS_BOUNDARY_MODULES: Final = MappingProxyType(
    {
        "eis_client.py": frozenset({"legacy.source.eis"}),
        "lead_factory/imap_canary_runtime.py": frozenset({"lead_factory.imap.canary"}),
        "lead_factory/tenderplan_isolated_transport.py": frozenset(
            {
                "lead_factory.source.tenderplan.shadow_canary",
            }
        ),
        "lead_factory/tenderplan_shadow_canary.py": frozenset(
            {
                "lead_factory.source.tenderplan.shadow_canary",
            }
        ),
        "taskbot/bitrix.py": frozenset({"taskbot.bitrix.read", "taskbot.bitrix.write"}),
        "taskbot/openrouter.py": frozenset({"taskbot.openrouter"}),
        "taskbot/telegram.py": frozenset(
            {
                "taskbot.telegram.contact",
                "taskbot.telegram.read",
            }
        ),
        "tb_ai.py": frozenset({"legacy.ai.openrouter"}),
        "tb_attach_export.py": frozenset({"legacy.imap.attach_export"}),
        "tb_bitrix_readonly.py": frozenset({"legacy.bitrix.read"}),
        "tb_damia.py": frozenset({"legacy.source.damia"}),
        "tb_dealers_2gis.py": frozenset(
            {
                "legacy.bitrix.dealer_dedup",
                "legacy.source.2gis.dealer_catalog",
            }
        ),
        "tb_dealers_email.py": frozenset(
            {
                "legacy.bitrix.dealer_dedup",
                "legacy.source.duckduckgo.dealer_search",
                "legacy.source.public_site.dealer_scrape",
            }
        ),
        "tb_dealers_pool.py": frozenset(
            {
                "legacy.bitrix.dealer_dedup",
                "legacy.source.2gis.dealer_catalog",
                "legacy.source.bing.dealer_search",
                "legacy.source.duckduckgo.dealer_search",
                "legacy.source.public_site.dealer_scrape",
            }
        ),
        "tb_dealers_serper.py": frozenset({"legacy.source.serper.dealer_search"}),
        "tb_dealers_yandex.py": frozenset(
            {
                "legacy.source.yandex.operation_poll",
                "legacy.source.yandex.search_submit",
            }
        ),
        "tb_docs.py": frozenset({"legacy.source.procurement.document_download"}),
        "tb_eisdocs.py": frozenset({"legacy.source.eis.document_download"}),
        "tb_exportbase_site_enrich.py": frozenset(
            {
                "legacy.bitrix.exportbase_dedup",
                "legacy.source.exportbase.site_scrape",
            }
        ),
        "tb_facade.py": frozenset({"legacy.imap.facade"}),
        "tb_fetch_kp.py": frozenset(
            {
                "legacy.bitrix.kp_download",
                "legacy.bitrix.kp_export",
            }
        ),
        "tb_inbox_export.py": frozenset({"legacy.imap.inbox_export"}),
        "tb_leaddocs.py": frozenset(
            {
                "legacy.bitrix.leaddocs.attach",
                "legacy.imap.leaddocs",
                "legacy.telegram.leaddocs.contact",
            }
        ),
        "tb_probe_2gis.py": frozenset({"legacy.source.2gis.dealer_catalog"}),
        "tb_probe_bing.py": frozenset({"legacy.source.bing.dealer_search"}),
        "tb_probe_damia_br.py": frozenset({"legacy.source.damia.probe"}),
        "tb_probe_net.py": frozenset({"legacy.diagnostic.network_probe"}),
        "tb_probe_scrape.py": frozenset(
            {
                "legacy.source.duckduckgo.dealer_search",
                "legacy.source.public_site.dealer_scrape",
            }
        ),
        "tb_retail_pool.py": frozenset(
            {
                "legacy.bitrix.dealer_dedup",
                "legacy.source.public_site.dealer_scrape",
            }
        ),
        "tb_webhook.py": frozenset(
            {
                "legacy.webhook.public_health",
                "legacy.webhook.telegram.alert",
                "legacy.webhook.tunnel.cloudflared",
                "legacy.webhook.tunnel.serveo",
                "legacy.webhook.unisender.read",
                "legacy.webhook.unisender.verify",
                "legacy.webhook.unisender.write",
            }
        ),
        "tb_webhook_watchdog.py": frozenset(
            {
                "legacy.webhook.public_health",
                "legacy.webhook.unisender.read",
                "legacy.webhook.watchdog.restart",
            }
        ),
    }
)

MANUAL_EGRESS_LOCAL_EXEMPTIONS: Final = MappingProxyType(
    {
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
)

_P = ParamSpec("_P")
_R = TypeVar("_R")


def assert_manual_egress_allowed(
    operation_id: str,
    *,
    method: str | None = None,
    source: str | None = None,
) -> None:
    """Require exact RC1 authority for one inventoried manual egress.

    The operation identifier is never derived from a URL, credential, payload
    or contact value, so denial messages cannot disclose those values.
    """

    operation = _validate_manual_binding(operation_id, method=method, source=source)
    assert_external_allowed(
        f"manual_egress:{operation.authority_flag}:{operation.channel}:{operation_id}"
    )


def _validate_manual_binding(
    operation_id: str,
    *,
    method: str | None,
    source: str | None,
) -> ManualEgressOperation:
    """Return registry metadata only for one exact code-owned binding."""

    operation = MANUAL_EGRESS_OPERATIONS.get(operation_id)
    if operation is None:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_OPERATION")
    if method not in operation.methods:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_METHOD")
    if source not in operation.sources:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SOURCE")
    if (method, source) not in operation.bindings:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_BINDING")
    return operation


def guarded_manual_egress_call(
    operation_id: str,
    transport: Callable[_P, _R],
    /,
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _R:
    """Legacy unbound helper retained only as a fail-closed compatibility API.

    All operations now require an exact method/source pair, so this function
    cannot authorize a registered transport. Callers must use one of the exact
    attempt helpers below. The callable's identity is deliberately not treated
    as authority evidence.
    """

    assert_manual_egress_allowed(operation_id)
    return transport(*args, **kwargs)


def guarded_manual_egress_attempt(
    operation_id: str,
    method: str,
    source: str,
    transport: Callable[_P, _R],
    /,
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _R:
    """Validate an exact method/source pair before one non-HTTP attempt."""

    assert_manual_egress_allowed(operation_id, method=method, source=source)
    return transport(*args, **kwargs)


_HTTP_METHOD_RE: Final = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD)(?: (/.+))?$")
_PATH_TEMPLATE_RE: Final = re.compile(r"\{([a-z][a-z0-9_]*)(\.\.\.)?\}")

# No external clear-text HTTP source is ratified in RC1. This explicit set is
# intentionally empty; adding an entry is a reviewed contract change.
MANUAL_EGRESS_SAFE_HTTP_SOURCES: Final[frozenset[str]] = frozenset()


def _path_matches_template(path: str, template: str) -> bool:
    """Match a code-owned path template without decoding attacker input."""

    parts: list[str] = []
    cursor = 0
    for match in _PATH_TEMPLATE_RE.finditer(template):
        parts.append(re.escape(template[cursor : match.start()]))
        parts.append(r".+" if match.group(2) else r"[^/]+")
        cursor = match.end()
    parts.append(re.escape(template[cursor:]))
    return re.fullmatch("".join(parts), path) is not None


def _assert_http_source(url: str, source: str) -> str:
    parsed = urlparse(str(url or ""))
    host = (parsed.hostname or "").casefold().rstrip(".")
    if not host or parsed.username or parsed.password:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SOURCE")
    scheme = parsed.scheme.casefold()
    if scheme != "https" and not (
        scheme == "http" and source in MANUAL_EGRESS_SAFE_HTTP_SOURCES
    ):
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SCHEME")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_PORT") from exc
    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_PORT")
    if source.startswith("host:"):
        if host != source.removeprefix("host:").casefold():
            raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SOURCE")
        return parsed.path or "/"
    if source == "bitrix24:webhook":
        if not host.endswith(".bitrix24.ru") or host == "bitrix24.ru":
            raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SOURCE")
        return parsed.path or "/"
    if not source.startswith("public_http:"):
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SOURCE")
    if host == "localhost" or host.endswith(".local") or "." not in host:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SOURCE")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return parsed.path or "/"
    if not address.is_global:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_SOURCE")
    return parsed.path or "/"


def _assert_http_method_path(method: str, path: str) -> None:
    match = _HTTP_METHOD_RE.fullmatch(method)
    if match is None:
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_HTTP_METHOD")
    template = match.group(2)
    if template is not None and not _path_matches_template(path, template):
        raise ExternalAuthorityError("MDOS_V7_MANUAL_EGRESS_UNKNOWN_PATH")


def guarded_manual_http_call(
    operation_id: str,
    method: str,
    source: str,
    url: str,
    transport: Callable[_P, _R],
    /,
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _R:
    """Validate source/path and re-check authority before one HTTP attempt.

    ``method`` is a code-owned HTTP method/path template. The callable itself
    is not introspected and is not accepted as proof of the requested method;
    reviewed call sites bind it explicitly and disable managed redirects.
    """

    operation = _validate_manual_binding(operation_id, method=method, source=source)
    path = _assert_http_source(url, source)
    _assert_http_method_path(method, path)
    assert_external_allowed(
        f"manual_egress:{operation.authority_flag}:{operation.channel}:{operation_id}"
    )
    return transport(url, *args, **kwargs)


__all__ = [
    "MANUAL_EGRESS_OPERATIONS",
    "MANUAL_EGRESS_BOUNDARY_MODULES",
    "MANUAL_EGRESS_LOCAL_EXEMPTIONS",
    "ManualEgressOperation",
    "MANUAL_EGRESS_SAFE_HTTP_SOURCES",
    "assert_manual_egress_allowed",
    "guarded_manual_egress_attempt",
    "guarded_manual_egress_call",
    "guarded_manual_http_call",
]
