"""Emit deterministic evidence for the RC1 Python egress freeze inventory."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.mdos_v7.authority import authority_snapshot  # noqa: E402
from lead_factory.mdos_v7.contracts import (  # noqa: E402
    ContractRegistry,
    value_sha256,
)
from lead_factory.mdos_v7.manual_egress import (  # noqa: E402
    MANUAL_EGRESS_BOUNDARY_MODULES,
    MANUAL_EGRESS_LOCAL_EXEMPTIONS,
    MANUAL_EGRESS_OPERATIONS,
)


DEFAULT_OUTPUT = (
    ROOT / "reports" / "market_demand_os_v7" / "g2-manual-egress-evidence.json"
)
EVALUATED_AT = datetime(2026, 8, 26, 0, 0, 0, tzinfo=timezone.utc)

# These pre-existing modules are frozen by the immutable authority boundary or
# an unconditional RC1 default-deny return. They remain separate from the new
# exact manual-egress registry so this report does not pretend they were
# migrated to a PermitDecision-capable adapter.
LEGACY_FROZEN_BOUNDARIES = {
    "tb_bitrix.py": "unconditional_rc1_default_deny",
    "tb_email.py": "immutable_authority_assertion_before_smtp",
    "tb_mail.py": "immutable_authority_assertion_before_smtp_or_imap",
    "tb_telegram.py": "unconditional_rc1_default_deny",
    "tb_unisender.py": "unconditional_rc1_default_deny",
}

# Injected callables do not expose a direct ``requests.*`` signature. They are
# inventoried separately and fenced at the concrete sink or immediately before
# an abstract dispatch, so an injected real transport cannot bypass RC1.
INJECTED_FROZEN_BOUNDARIES = {
    "lead_factory/bitrix_activity.py": "early_and_jit_rc1_bitrix_dispatch_fence",
    "lead_factory/bitrix_canary.py": "early_and_jit_rc1_bitrix_dispatch_fence",
    "lead_factory/bitrix_graph_canary_executor.py": "exact_sealed_executor_type",
    "lead_factory/bitrix_rest.py": "concrete_rc1_read_write_sink_fence",
    "lead_factory/canary_executor.py": "rc1_abstract_dispatch_fence",
    "lead_factory/crm_graph_outbox.py": "rc1_graph_dispatch_fence",
    "lead_factory/crm_outbox.py": "rc1_outbox_dispatch_fence",
    "lead_factory/imap_readonly_boundary.py": "per_attempt_rc1_imap_sink_fence",
    "lead_factory/mdos_v7/bitrix_projection.py": "exact_permit_service_and_jit_fence",
    "lead_factory/migrate_v15_cutover.py": "restore_delegates_to_fenced_provider",
    "lead_factory/openrouter_gateway.py": "early_and_jit_rc1_spend_fence",
    "lead_factory/source_adapter.py": "exact_offline_type_or_rc1_read_fence",
    "lead_factory/unified_inbound_worker.py": "jit_rc1_injected_fetch_fence",
    "lead_factory/unisender_go_transport.py": "early_and_jit_rc1_contact_fence",
    "lead_factory/windows_canary_provider.py": "active_restore_rc1_fence",
}

# These two modules belong to the separately owner-authorized Mail -> Bitrix
# recovery route added after the v7.1 RC1 freeze.  They MUST NOT be described
# as legacy/default-denied boundaries: the worker can perform narrowly scoped
# live reads and Bitrix lead writes after its own exact bootstrap and cap-one
# canary.  Conversely, merely listing a module here grants no MDOS v7
# authority.  It only keeps the repository-wide transport inventory truthful
# while recording the route's exact allowed and denied surfaces.
OWNER_SCOPED_LIVE_BOUNDARIES = {
    "lead_factory/live_mail_bitrix.py": {
        "authority_source": "separate_exact_owner_bootstrap_and_connection_scope",
        "classification": "owner_scoped_mail_to_bitrix_recovery_route",
        "mdos_v7_authority_effect": False,
        "permitted_transports": [
            "bitrix.crm.lead.fields_list_add_get",
            "imap.inbox.readonly",
            "smtp.login_noop_only",
        ],
        "denied_transports": [
            "smtp.send",
            "tenderplan.any",
            "unisender.send",
        ],
    },
    "scripts/run_live_inbound.py": {
        "authority_source": "separate_exact_owner_bootstrap_and_cap_one_canary",
        "classification": "operator_cli_and_unisender_connection_preflight",
        "mdos_v7_authority_effect": False,
        "permitted_transports": [
            "unisender.domain.list",
            "unisender.template.list",
            "unisender.webhook.list",
        ],
        "denied_transports": [
            "smtp.send",
            "tenderplan.any",
            "unisender.send",
        ],
    },
}

_EXCLUDED_SCAN_ROOTS = frozenset(
    {
        ".git",
        ".pytest_cache",
        ".venv",
        "_diagnostics",
        "outputs",
        "pool",
        "state",
        "tests",
    }
)
_RAW_TRANSPORT_SIGNATURE = re.compile(
    r"requests\.(?:get|post|put|delete|request)|"
    r"(?:self\.)?_session\.(?:get|post|put|delete|request)|"
    r"(?<![\w.])session\.post\(|"
    r"httpx\.|urllib\.request|urlopen\(|imaplib\.|smtplib\.|"
    r"aiohttp\.|websocket|selenium"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _registry_snapshot() -> dict[str, Any]:
    return {
        "operations": {
            operation_id: {
                "authority_flag": metadata.authority_flag,
                "channel": metadata.channel,
                "bindings": [
                    [method, source] for method, source in sorted(metadata.bindings)
                ],
                "methods": sorted(metadata.methods),
                "sources": sorted(metadata.sources),
            }
            for operation_id, metadata in sorted(MANUAL_EGRESS_OPERATIONS.items())
        },
        "boundary_modules": {
            module: sorted(operations)
            for module, operations in sorted(MANUAL_EGRESS_BOUNDARY_MODULES.items())
        },
        "local_exemptions": {
            module: sorted(exemptions)
            for module, exemptions in sorted(MANUAL_EGRESS_LOCAL_EXEMPTIONS.items())
        },
    }


def _raw_transport_signature_modules() -> list[str]:
    discovered: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        if path.resolve() == Path(__file__).resolve():
            continue
        relative = path.relative_to(ROOT)
        if any(part in _EXCLUDED_SCAN_ROOTS for part in relative.parts):
            continue
        source = path.read_text(encoding="utf-8", errors="strict")
        if _RAW_TRANSPORT_SIGNATURE.search(source):
            discovered.append(relative.as_posix())
    return discovered


def build_report() -> dict[str, Any]:
    contracts = ContractRegistry(ROOT)
    manifest = contracts.manifest
    authority = authority_snapshot()
    freeze = authority["freeze"]
    registry = _registry_snapshot()
    signature_modules = _raw_transport_signature_modules()
    default_deny_modules = (
        set(MANUAL_EGRESS_BOUNDARY_MODULES)
        | set(LEGACY_FROZEN_BOUNDARIES)
        | set(INJECTED_FROZEN_BOUNDARIES)
    )
    inventoried_modules = default_deny_modules | set(OWNER_SCOPED_LIVE_BOUNDARIES)
    unknown_signature_modules = sorted(set(signature_modules) - inventoried_modules)
    if unknown_signature_modules:
        raise RuntimeError(
            "uninventoried raw transport signatures: "
            + ", ".join(unknown_signature_modules)
        )

    boundary_paths = {
        module: ROOT / Path(module) for module in sorted(inventoried_modules)
    }
    missing = [module for module, path in boundary_paths.items() if not path.is_file()]
    if missing:
        raise RuntimeError("missing egress boundary modules: " + ", ".join(missing))

    artifact_paths = {
        "manual_egress_module": ROOT / "lead_factory" / "mdos_v7" / "manual_egress.py",
        "manual_egress_tests": ROOT / "tests" / "test_mdos_v7_manual_egress.py",
        "legacy_freeze_tests": ROOT / "tests" / "test_mdos_v7_legacy_freeze.py",
        "legacy_boundary_tests": ROOT
        / "tests"
        / "test_mdos_v7_legacy_boundary_hardening.py",
        "core_injected_freeze_tests": ROOT
        / "tests"
        / "test_mdos_v7_core_injected_freeze.py",
        "read_projection_freeze_tests": ROOT
        / "tests"
        / "test_mdos_v7_read_projection_freeze.py",
        "dispatch_restore_freeze_tests": ROOT
        / "tests"
        / "test_mdos_v7_dispatch_restore_freeze.py",
        "runner": Path(__file__).resolve(),
        "runner_tests": ROOT / "tests" / "test_mdos_v7_manual_egress_runner.py",
    }
    return {
        "schema_version": "1.0.0",
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "classification": "LOCAL_CODE_EGRESS_INVENTORY_NON_AUTHORITY",
        "evaluated_at_utc": EVALUATED_AT.isoformat().replace("+00:00", "Z"),
        "package_binding": {
            "contract_id": manifest["contract_id"],
            "package_version": manifest["package_version"],
            "package_root_sha256": manifest["package_root_sha256"],
            "artifact_count": contracts.artifact_count,
            "active_beachhead_profile": manifest["active_beachhead_profile"],
            "ratification": manifest["ratification"],
        },
        "authority": {
            "external_reads_enabled": freeze["external_reads_enabled"],
            "external_writers_enabled": freeze["external_writers_enabled"],
            "contact_enabled": freeze["contact_enabled"],
            "spend_enabled": freeze["spend_enabled"],
            "live_bitrix_writes_enabled": freeze["live_bitrix_writes_enabled"],
            "authority_mutation_allowed": False,
        },
        "inventory": {
            "manual_registry_operation_count": len(MANUAL_EGRESS_OPERATIONS),
            "manual_registry_module_count": len(MANUAL_EGRESS_BOUNDARY_MODULES),
            "legacy_frozen_module_count": len(LEGACY_FROZEN_BOUNDARIES),
            "injected_frozen_module_count": len(INJECTED_FROZEN_BOUNDARIES),
            "default_deny_code_boundary_module_count": len(default_deny_modules),
            "owner_scoped_live_module_count": len(OWNER_SCOPED_LIVE_BOUNDARIES),
            "inventoried_code_boundary_module_count": len(inventoried_modules),
            "raw_transport_signature_module_count": len(signature_modules),
            "raw_transport_signature_modules": signature_modules,
            "unknown_signature_modules": unknown_signature_modules,
            "registry_snapshot_sha256": value_sha256(registry),
            "legacy_frozen_boundaries": dict(sorted(LEGACY_FROZEN_BOUNDARIES.items())),
            "injected_frozen_boundaries": dict(
                sorted(INJECTED_FROZEN_BOUNDARIES.items())
            ),
            "owner_scoped_live_boundaries": dict(
                sorted(OWNER_SCOPED_LIVE_BOUNDARIES.items())
            ),
            "boundary_module_sha256": {
                module: _sha256(path) for module, path in boundary_paths.items()
            },
            "local_exemptions": registry["local_exemptions"],
        },
        "outcome": {
            "inventoried_python_boundary_status": "INVENTORIED_DEFAULT_DENY",
            "owner_scoped_live_boundary_status": (
                "SEPARATELY_INVENTORIED_NOT_GRANTED_BY_MDOS_V7"
            ),
            "owner_scoped_live_routes_present": True,
            "external_transport_attempt_count": 0,
            "external_effect_count": 0,
            "contact_count": 0,
            "spend_count": 0,
            "raw_credentials_or_pii_included": False,
            "live_activation_allowed": False,
            "owner_scoped_activation_granted_by_this_report": False,
        },
        "artifact_digests": {
            name: _sha256(path) for name, path in sorted(artifact_paths.items())
        },
        "requirement_refs": [
            "MDOS-ASR-001",
            "MDOS-ASR-002",
            "MDOS-ASR-004",
            "MDOS-AUT-002",
            "MDOS-AUT-005",
            "MDOS-LGL-001",
            "MDOS-LGL-003",
            "MDOS-REL-001",
            "MDOS-REL-002",
            "MDOS-SEC-002",
        ],
        "acceptance_refs": [
            "AT-ASR-03",
            "AT-ASR-04",
            "AT-ASR-12",
            "AT-SRC7-04",
            "AT-SRC7-07",
        ],
        "independent_evidence_verifier": None,
        "limitations": [
            "This is a static Python boundary inventory, not live authority.",
            "The Mail-to-Bitrix recovery route uses separate owner-scoped runtime authority and does not mutate or inherit MDOS v7 authority.",
            "The owner-scoped route keeps SMTP send, UniSender send and TenderPlan access denied.",
            "Manual browser, phone and operator actions remain organizational controls.",
            "Dynamic public-host classes are not an owner-ratified literal domain roster.",
            "HTTP redirects remain unsupported and fail closed pending a per-hop adapter.",
            "The signature scan does not prove absence of every possible native transport.",
            "A successor controlled release and independent review are required for live use.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report()
    _write_atomic(args.output.resolve(), report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
