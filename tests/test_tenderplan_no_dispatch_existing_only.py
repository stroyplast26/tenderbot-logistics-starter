"""A disappearing admission ledger must never be replaced by an empty file."""

import gc
from unittest.mock import Mock

import pytest

from lead_factory import tenderplan_read_only_store as native
from tests.test_lead_factory_tenderplan_no_dispatch_admission import make_admission_fixture


@pytest.mark.parametrize("apply", [False, True])
def test_disappearance_before_admission_writer_open_does_not_create_replacement(
    tmp_path, monkeypatch, apply,
):
    forbidden = Mock(side_effect=AssertionError("external action forbidden"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    path, arguments, _, _ = make_admission_fixture(tmp_path, monkeypatch)
    preview = native.preview_tenderplan_no_dispatch_admission(**arguments)
    # SQLite context managers in the imported synthetic fixture end transactions
    # but rely on GC to close their read handles on Windows.
    gc.collect()
    original_connect = native.sqlite3.connect
    removed = []

    def disappear_at_writer_connect(database, *args, **kwargs):
        if str(database) in {str(path), path.as_uri() + "?mode=rw"}:
            path.unlink()
            removed.append(True)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(native.sqlite3, "connect", disappear_at_writer_connect)
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        if apply:
            native.apply_tenderplan_no_dispatch_admission(
                **arguments, expected_preview_sha256=preview["preview_sha256"],
                confirmation=native.TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION,
            )
        else:
            native.preview_tenderplan_no_dispatch_admission(**arguments)
    assert removed == [True]
    assert not path.exists()
    assert not list(path.parent.glob(path.name + "-*"))
    forbidden.assert_not_called()
