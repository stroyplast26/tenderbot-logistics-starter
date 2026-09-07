"""Stable operator-facing import for the Mail-to-Bitrix live service.

The implementation lives in :mod:`lead_factory.live_mail_bitrix`; this narrow
module lets Windows operator scripts keep one durable import path.
"""

from .live_mail_bitrix import (
    BITRIX_CANARY_CONFIRMATION,
    OWNER_AUTHORITY_CONFIRMATION,
    BootstrapRequired,
    BitrixWriteNotVerified,
    ConcurrentRun,
    CredentialContractError,
    LiveMailBitrixError,
    LiveMailBitrixWorker,
    ORIGINATOR_ID,
    RemotePreflightError,
    UidValidityMismatch,
    build_runtime_from_credentials,
)


__all__ = [
    "BITRIX_CANARY_CONFIRMATION",
    "OWNER_AUTHORITY_CONFIRMATION",
    "BootstrapRequired",
    "BitrixWriteNotVerified",
    "ConcurrentRun",
    "CredentialContractError",
    "LiveMailBitrixError",
    "LiveMailBitrixWorker",
    "ORIGINATOR_ID",
    "RemotePreflightError",
    "UidValidityMismatch",
    "build_runtime_from_credentials",
]
