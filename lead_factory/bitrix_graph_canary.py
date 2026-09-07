"""Fail-closed offline preparation for the future Bitrix graph canary 1→5.

This is deliberately a planning gate, not a controller.  It accepts only the
offline graph preflight proof and returns an immutable, non-activatable plan.
No database, HTTP, credential, environment, worker, or writer capability is
present here.  A live run remains impossible until a separate owner-approved
controller and live read-only preflight are introduced.
"""

from __future__ import annotations

from dataclasses import dataclass

from .bitrix_graph_mapping import (
    BitrixGraphBridgeBinding,
    BitrixGraphMappingError,
    validate_graph_bridge_binding,
)
from .bitrix_graph_preflight import BitrixGraphPreflightReport
from .ids import payload_hash


class BitrixGraphCanaryError(ValueError):
    """The offline-only graph canary input is not exact enough."""


class BitrixGraphCanaryActivationDenied(RuntimeError):
    """Offline preparation cannot activate a provider canary."""


_STEPS = (1, 2, 3, 4, 5)


@dataclass(frozen=True, slots=True)
class BitrixGraphOfflineCanaryPlan:
    """One evidence-only progressive rollout plan with no write authority."""

    manifest_hash: str
    lf_source_id: str
    activity_deadline_utc: str
    steps: tuple[int, ...]
    offline_preflight_ok: bool
    live_calls_performed: int
    external_writes_performed: int
    live_preflight_ok: bool
    owner_approval_required: bool
    activation_permitted: bool
    plan_hash: str

    def activate(self) -> None:
        """Always deny: this object carries no live activation authority."""

        raise BitrixGraphCanaryActivationDenied(
            "offline graph canary plan cannot activate Bitrix"
        )


def prepare_bitrix_graph_offline_canary(
    binding: BitrixGraphBridgeBinding,
    preflight: BitrixGraphPreflightReport,
) -> BitrixGraphOfflineCanaryPlan:
    """Bind the fixed 1→5 sequence to one offline graph preflight report."""

    if type(preflight) is not BitrixGraphPreflightReport:
        raise BitrixGraphCanaryError("offline graph preflight report is invalid")
    try:
        manifest_hash = validate_graph_bridge_binding(binding)
    except BitrixGraphMappingError:
        raise BitrixGraphCanaryError("offline graph binding is invalid") from None
    if (
        preflight.offline_contract_ok is not True
        or preflight.manifest_hash != manifest_hash
        or preflight.live_calls_performed != 0
        or preflight.external_writes_performed != 0
        or preflight.live_preflight_ok is not False
        or preflight.canary_ready is not False
    ):
        raise BitrixGraphCanaryError("offline graph preflight cannot authorize canary")
    body = {
        "manifest_hash": manifest_hash,
        "lf_source_id": binding.lf_source_id,
        "activity_deadline_utc": binding.activity_deadline_utc,
        "steps": list(_STEPS),
        "offline_preflight_ok": True,
        "live_calls_performed": 0,
        "external_writes_performed": 0,
        "live_preflight_ok": False,
        "owner_approval_required": True,
        "activation_permitted": False,
    }
    return BitrixGraphOfflineCanaryPlan(
        manifest_hash=manifest_hash,
        lf_source_id=binding.lf_source_id,
        activity_deadline_utc=binding.activity_deadline_utc,
        steps=_STEPS,
        offline_preflight_ok=True,
        live_calls_performed=0,
        external_writes_performed=0,
        live_preflight_ok=False,
        owner_approval_required=True,
        activation_permitted=False,
        plan_hash=payload_hash(body),
    )


__all__ = [
    "BitrixGraphCanaryActivationDenied",
    "BitrixGraphCanaryError",
    "BitrixGraphOfflineCanaryPlan",
    "prepare_bitrix_graph_offline_canary",
]
