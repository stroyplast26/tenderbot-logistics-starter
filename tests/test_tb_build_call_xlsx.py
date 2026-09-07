from pathlib import Path

import pytest

import tb_build_call_xlsx as call_xlsx


def test_build_honors_both_explicit_output_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rows = [{"prio": 1}, {"prio": 2}]
    written: list[tuple[list[dict[str, int]], Path]] = []

    monkeypatch.setattr(call_xlsx, "collect", lambda _base_dir: rows)

    def fake_write(data: list[dict[str, int]], path: Path) -> None:
        target = Path(path)
        target.write_text(str(len(data)), encoding="ascii")
        written.append((data, target))

    monkeypatch.setattr(call_xlsx, "_write", fake_write)
    first = tmp_path / "owner" / "first.xlsx"
    second = tmp_path / "partner" / "second.xlsx"

    call_xlsx.build(first, second, tmp_path)

    assert first.read_text(encoding="ascii") == "1"
    assert second.read_text(encoding="ascii") == "1"
    assert written == [([rows[0]], first), ([rows[1]], second)]
    rendered = capsys.readouterr().out
    assert str(first) in rendered
    assert str(second) in rendered


def test_build_rejects_same_output_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        call_xlsx,
        "collect",
        lambda _base_dir: (_ for _ in ()).throw(
            AssertionError("same-path validation must precede collection")
        ),
    )
    output = tmp_path / "same.xlsx"

    with pytest.raises(ValueError, match="must be different"):
        call_xlsx.build(output, output, tmp_path)
