from __future__ import annotations

import sqlite3
from pathlib import Path

from tests.test_live_inbound_status_contract import _run_authority_probe
from tests.test_native_bitrix_mail_observer import (
    FakeBitrix,
    FakeImap,
    MutableClock,
    bootstrap,
    make_observer,
)


def test_protected_status_probe_accepts_read_only_observer_authority(
    tmp_path: Path,
) -> None:
    observer = make_observer(
        tmp_path,
        FakeImap({10: b"historical"}),
        FakeBitrix(),
        MutableClock(),
    )
    result = bootstrap(observer)

    observed = _run_authority_probe(tmp_path / "live_mail_bitrix.sqlite3")

    assert result["ok"] is True
    assert observed["authority_state"] == "ACTIVE"
    assert observed["authority_mode"] == "NATIVE_BITRIX_MAIL_OBSERVER"
    assert observed["external_writes_enabled"] is False
    assert observed["release_sha256"] == "1" * 64
    assert observed["runtime_sha256"] == "2" * 64
    assert observed["authority_generation"] == result["authority_generation"]

    database = tmp_path / "live_mail_bitrix.sqlite3"
    for invalid_expiry in (
        "not-a-timestamp",
        "2000-01-01T00:00:00Z",
        "2999-01-01T00:00:00",
    ):
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scoped_authority SET authority_expires_at_utc=? "
                "WHERE singleton=1",
                (invalid_expiry,),
            )
        rejected = _run_authority_probe(database)
        assert rejected["authority_state"] == "UNKNOWN"
        assert rejected["authority_mode"] == "UNKNOWN"
        assert rejected["external_writes_enabled"] is None
