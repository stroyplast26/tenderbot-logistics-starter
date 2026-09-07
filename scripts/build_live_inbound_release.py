"""Build one deterministic live-inbound app plus a private stdlib runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Final
import zipfile


WORKSPACE_ROOT: Final = Path(__file__).resolve(strict=True).parents[1]
ARTIFACT_NAME: Final = "live-inbound.pyz"
MANIFEST_NAME: Final = "release.json"
RUNTIME_DIR_NAME: Final = "runtime"
RUNTIME_EXECUTABLE: Final = "python.exe"
LAUNCHER_NAME: Final = "verify-and-run.ps1"
STATUS_NAME: Final = "read-status.ps1"
MANDATORY_LABEL_READER_NAME: Final = "mandatory-label-reader.dll"
_MAX_SOURCE_BYTES: Final = 4 * 1024 * 1024
_SOURCE_FILES: Final = (
    "lead_factory/facade_inquiry_parser.py",
    "lead_factory/live_connection_credentials.py",
    "lead_factory/mail_bitrix_projection.py",
    "lead_factory/mail_threading.py",
    "lead_factory/live_mail_bitrix.py",
    "lead_factory/native_bitrix_mail_observer.py",
    "scripts/run_live_inbound.py",
    "scripts/run_native_bitrix_observer.py",
)
_LAUNCHER_SOURCE: Final = "scripts/live_inbound_launcher.ps1"
_BUILDER_SOURCE: Final = "scripts/build_live_inbound_release.py"
_INSTALLER_SOURCE: Final = "scripts/install_live_inbound_task_admin.ps1"
_INSTALL_BOOTSTRAP_SOURCE: Final = "scripts/install_live_inbound_task.ps1"
_STATUS_SOURCE: Final = "scripts/live_inbound_task_status.ps1"
_MANDATORY_LABEL_READER_SOURCE: Final = "scripts/mandatory_label_reader.cs"
_MANDATORY_LABEL_READER_BINARY: Final = "scripts/mandatory_label_reader.dll"
_RELEASE_SOURCE_FILES: Final = (
    *_SOURCE_FILES,
    _LAUNCHER_SOURCE,
    _BUILDER_SOURCE,
    _INSTALLER_SOURCE,
    _INSTALL_BOOTSTRAP_SOURCE,
    _STATUS_SOURCE,
    _MANDATORY_LABEL_READER_SOURCE,
    _MANDATORY_LABEL_READER_BINARY,
)
_GENERATED_FILES: Final = {
    "__main__.py": (
        "from scripts.run_native_bitrix_observer import live_inbound_main\n"
        "raise SystemExit(live_inbound_main())\n"
    ).encode("utf-8"),
    "lead_factory/__init__.py": b'"""Pinned live-inbound runtime package."""\n',
    "scripts/__init__.py": b'"""Pinned live-inbound command package."""\n',
}
_RUNTIME_TOP_LEVEL: Final = (
    "LICENSE.txt",
    "python.exe",
    "python3.dll",
    "python311.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
)
_RUNTIME_EXCLUDED_PARTS: Final = frozenset({"__pycache__", "site-packages", "test"})
_RUNTIME_EXCLUDED_SUFFIXES: Final = frozenset({".pyc", ".pyo"})
_RUNTIME_POLICY: Final = "cpython-stdlib-copy-no-site-v2"


class LiveInboundReleaseBuildError(RuntimeError):
    """The release could not be built without weakening its pinning contract."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attributes & 0x400)


def _default_release_root() -> Path:
    if os.name == "nt" and (program_files := os.environ.get("ProgramFiles", "").strip()):
        return (
            Path(program_files) / "TenderBot" / "LiveInbound" / "releases"
        ).resolve(strict=False)
    profile_value = os.environ.get("USERPROFILE", "").strip()
    profile = Path(profile_value) if profile_value else Path.home()
    return (profile / ".tenderbot" / "releases" / "mail-inbound").resolve(strict=False)


def _validate_release_root(path: Path) -> Path:
    candidate = path.resolve(strict=False)
    workspace = WORKSPACE_ROOT.resolve(strict=True)
    one_drive_roots = [
        Path(value).resolve(strict=False)
        for key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")
        if (value := os.environ.get(key, "").strip())
    ]
    if candidate == workspace or workspace in candidate.parents:
        raise LiveInboundReleaseBuildError("release root must be outside the workspace")
    if any(candidate == root or root in candidate.parents for root in one_drive_roots):
        raise LiveInboundReleaseBuildError("release root must be outside OneDrive")
    if any(part.casefold().startswith("onedrive") for part in candidate.parts):
        raise LiveInboundReleaseBuildError("release root must be outside OneDrive")
    for parent in (candidate, *candidate.parents):
        if parent.exists() and (parent.is_symlink() or _is_reparse_point(parent)):
            raise LiveInboundReleaseBuildError("release root cannot contain a reparse point")
    return candidate


def _read_sources() -> dict[str, bytes]:
    payloads = dict(_GENERATED_FILES)
    for relative in _SOURCE_FILES:
        source = (WORKSPACE_ROOT / relative).resolve(strict=True)
        if (
            not source.is_file()
            or source.is_symlink()
            or _is_reparse_point(source)
            or WORKSPACE_ROOT.resolve(strict=True) not in source.parents
        ):
            raise LiveInboundReleaseBuildError("release source contract is invalid")
        data = source.read_bytes()
        if not data or len(data) > _MAX_SOURCE_BYTES:
            raise LiveInboundReleaseBuildError("release source size is invalid")
        payloads[relative.replace("\\", "/")] = data
    return payloads


def _read_release_source(relative: str) -> bytes:
    source = (WORKSPACE_ROOT / relative).resolve(strict=True)
    if (
        not source.is_file()
        or source.is_symlink()
        or _is_reparse_point(source)
        or WORKSPACE_ROOT.resolve(strict=True) not in source.parents
    ):
        raise LiveInboundReleaseBuildError("release source contract is invalid")
    data = source.read_bytes()
    if not data or len(data) > _MAX_SOURCE_BYTES:
        raise LiveInboundReleaseBuildError("release source size is invalid")
    return data


def _zip_entry(name: str, data: bytes) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o444) << 16
    info.flag_bits = 0
    info.file_size = len(data)
    return info


def _source_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=WORKSPACE_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    value = result.stdout.strip().casefold()
    return (
        value
        if len(value) == 40 and all(character in "0123456789abcdef" for character in value)
        else ""
    )


def _source_git_status(relative: str) -> str:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", relative],
            cwd=WORKSPACE_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LiveInboundReleaseBuildError("source provenance is unavailable") from exc
    lines = [line for line in result.stdout.splitlines() if line]
    if not lines:
        return "tracked_clean"
    if len(lines) != 1:
        raise LiveInboundReleaseBuildError("source provenance is ambiguous")
    code = lines[0][:2]
    if code == "??":
        return "untracked"
    if code == "!!":
        return "ignored"
    return f"git_porcelain_{code.replace(' ', '_')}"


def _source_head_sha256(relative: str, git_head: str) -> str:
    if not git_head:
        return ""
    head_ref = git_head + ":" + relative.replace(os.sep, "/")
    try:
        result = subprocess.run(
            ["git", "show", head_ref],
            cwd=WORKSPACE_ROOT,
            check=True,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return _sha256_bytes(result.stdout)


def _source_provenance(sources: dict[str, bytes]) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    status_receipt: list[str] = []
    git_head = _source_commit()
    for relative in _RELEASE_SOURCE_FILES:
        normalized = relative.replace("\\", "/")
        status = _source_git_status(relative)
        data = sources[normalized]
        worktree_sha256 = _sha256_bytes(data)
        head_sha256 = _source_head_sha256(relative, git_head)
        entries.append(
            {
                "git_head_sha256": head_sha256,
                "git_state": status,
                "path": normalized,
                "size": len(data),
                "worktree_sha256": worktree_sha256,
            }
        )
        status_receipt.append(
            f"{normalized}\0{status}\0{head_sha256}\0{worktree_sha256}\n"
        )
    clean = bool(
        git_head
        and all(
            entry["git_state"] == "tracked_clean"
            and entry["git_head_sha256"] == entry["worktree_sha256"]
            for entry in entries
        )
    )
    return {
        "builder_sha256": _sha256_bytes(sources[_BUILDER_SOURCE]),
        "git_head": git_head,
        "git_status_snapshot_sha256": _sha256_bytes("".join(status_receipt).encode("utf-8")),
        "reproducible_from_git_head": clean,
        "source_kind": "git_head" if clean else "workspace_snapshot",
        "sources": entries,
    }


def _runtime_source_root() -> Path:
    root = Path(sys.base_prefix).resolve(strict=True)
    if not root.is_dir() or root.is_symlink() or _is_reparse_point(root):
        raise LiveInboundReleaseBuildError("base runtime contract is invalid")
    for relative in (*_RUNTIME_TOP_LEVEL, "DLLs", "Lib"):
        candidate = root / relative
        if not candidate.exists() or candidate.is_symlink() or _is_reparse_point(candidate):
            raise LiveInboundReleaseBuildError("base runtime is incomplete")
    return root


def _copy_runtime_file(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink() or _is_reparse_point(source):
        raise LiveInboundReleaseBuildError("runtime source contains a link or reparse point")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _copy_runtime_tree(source_root: Path, destination_root: Path) -> None:
    destination_root.mkdir(parents=True, exist_ok=False)
    for relative in _RUNTIME_TOP_LEVEL:
        _copy_runtime_file(source_root / relative, destination_root / relative)
    for directory_name in ("DLLs", "Lib"):
        source_directory = source_root / directory_name
        for current_root, directories, filenames in os.walk(source_directory, followlinks=False):
            current = Path(current_root)
            if current.is_symlink() or _is_reparse_point(current):
                raise LiveInboundReleaseBuildError("runtime source contains a reparse point")
            directories[:] = sorted(
                name
                for name in directories
                if name.casefold() not in _RUNTIME_EXCLUDED_PARTS
            )
            for filename in sorted(filenames):
                source = current / filename
                relative = source.relative_to(source_root)
                if any(part.casefold() in _RUNTIME_EXCLUDED_PARTS for part in relative.parts):
                    continue
                if source.suffix.casefold() in _RUNTIME_EXCLUDED_SUFFIXES:
                    continue
                if source.suffix.casefold() in {".pth", ".egg-link"}:
                    raise LiveInboundReleaseBuildError("runtime cannot contain path startup hooks")
                _copy_runtime_file(source, destination_root / relative)
    (destination_root / "python311._pth").write_bytes(b"Lib\nDLLs\n.\n")


def _runtime_entries(runtime_root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    casefolded: set[str] = set()
    for path in sorted(
        (candidate for candidate in runtime_root.rglob("*") if candidate.is_file()),
        key=lambda candidate: candidate.relative_to(runtime_root).as_posix().encode("utf-8"),
    ):
        if path.is_symlink() or _is_reparse_point(path) or path.stat().st_nlink != 1:
            raise LiveInboundReleaseBuildError("runtime payload contains a linked file")
        relative = path.relative_to(runtime_root).as_posix()
        folded = relative.casefold()
        if folded in casefolded or ".." in Path(relative).parts:
            raise LiveInboundReleaseBuildError("runtime payload path is ambiguous")
        casefolded.add(folded)
        if path.suffix.casefold() in {".pth", ".egg-link", ".pyc", ".pyo"}:
            raise LiveInboundReleaseBuildError("runtime payload contains a forbidden startup file")
        stat_result = path.stat()
        entries.append(
            {
                "path": relative,
                "sha256": _sha256_file(path),
                "size": int(stat_result.st_size),
            }
        )
    if not entries:
        raise LiveInboundReleaseBuildError("runtime payload is empty")
    return entries


def _runtime_tree_sha256(entries: list[dict[str, object]]) -> str:
    receipt = {"files": entries, "format": "TenderBot.LiveInbound.RuntimeTree.v1"}
    return _sha256_bytes(_canonical_json(receipt))


def _cleanup_staging(staging: Path, release_root: Path) -> None:
    try:
        resolved = staging.resolve(strict=False)
        if (
            resolved.parent == release_root
            and resolved.name.startswith(".build-")
            and resolved.exists()
            and not resolved.is_symlink()
            and not _is_reparse_point(resolved)
        ):
            shutil.rmtree(resolved)
    except OSError:
        pass


def _verify_existing_release(
    target: Path,
    *,
    manifest_bytes: bytes,
    artifact_sha256: str,
    launcher_sha256: str,
    status_sha256: str,
    mandatory_label_reader_sha256: str,
    runtime_entries: list[dict[str, object]],
) -> None:
    if target.is_symlink() or _is_reparse_point(target):
        raise LiveInboundReleaseBuildError("existing release is a reparse point")
    top_level = tuple(target.iterdir())
    expected_top_level = {
        ARTIFACT_NAME,
        MANDATORY_LABEL_READER_NAME,
        MANIFEST_NAME,
        RUNTIME_DIR_NAME,
        STATUS_NAME,
        LAUNCHER_NAME,
    }
    if (
        {entry.name for entry in top_level} != expected_top_level
        or len(top_level) != len(expected_top_level)
        or any(entry.is_symlink() or _is_reparse_point(entry) for entry in top_level)
    ):
        raise LiveInboundReleaseBuildError(
            "existing release top-level contract is invalid"
        )
    artifact = target / ARTIFACT_NAME
    manifest = target / MANIFEST_NAME
    launcher = target / LAUNCHER_NAME
    status = target / STATUS_NAME
    mandatory_label_reader = target / MANDATORY_LABEL_READER_NAME
    runtime = target / RUNTIME_DIR_NAME
    if (
        not artifact.is_file()
        or _sha256_file(artifact) != artifact_sha256
        or not manifest.is_file()
        or manifest.read_bytes() != manifest_bytes
        or not launcher.is_file()
        or _sha256_file(launcher) != launcher_sha256
        or not status.is_file()
        or _sha256_file(status) != status_sha256
        or not mandatory_label_reader.is_file()
        or _sha256_file(mandatory_label_reader) != mandatory_label_reader_sha256
        or not runtime.is_dir()
        or _runtime_entries(runtime) != runtime_entries
    ):
        raise LiveInboundReleaseBuildError("existing release does not match its digest")


def build_release(
    output_root: str | os.PathLike[str] | None = None,
    *,
    require_clean_git_head: bool = False,
) -> dict[str, object]:
    release_root = _validate_release_root(
        Path(output_root) if output_root is not None else _default_release_root()
    )
    release_root.mkdir(parents=True, exist_ok=True)
    if release_root.is_symlink() or _is_reparse_point(release_root):
        raise LiveInboundReleaseBuildError("release root cannot be a reparse point")
    sources = _read_sources()
    launcher_bytes = _read_release_source(_LAUNCHER_SOURCE)
    builder_bytes = _read_release_source(_BUILDER_SOURCE)
    installer_bytes = _read_release_source(_INSTALLER_SOURCE)
    bootstrap_bytes = _read_release_source(_INSTALL_BOOTSTRAP_SOURCE)
    status_bytes = _read_release_source(_STATUS_SOURCE)
    mandatory_label_reader_source_bytes = _read_release_source(
        _MANDATORY_LABEL_READER_SOURCE
    )
    mandatory_label_reader_bytes = _read_release_source(
        _MANDATORY_LABEL_READER_BINARY
    )
    provenance_sources = {
        **sources,
        _LAUNCHER_SOURCE: launcher_bytes,
        _BUILDER_SOURCE: builder_bytes,
        _INSTALLER_SOURCE: installer_bytes,
        _INSTALL_BOOTSTRAP_SOURCE: bootstrap_bytes,
        _STATUS_SOURCE: status_bytes,
        _MANDATORY_LABEL_READER_SOURCE: mandatory_label_reader_source_bytes,
        _MANDATORY_LABEL_READER_BINARY: mandatory_label_reader_bytes,
    }
    source_provenance = _source_provenance(provenance_sources)
    if require_clean_git_head and not bool(
        source_provenance["reproducible_from_git_head"]
    ):
        raise LiveInboundReleaseBuildError(
            "production release requires a clean committed Git HEAD"
        )
    staging = Path(tempfile.mkdtemp(prefix=".build-", dir=release_root))
    artifact = staging / ARTIFACT_NAME
    runtime = staging / RUNTIME_DIR_NAME
    launcher = staging / LAUNCHER_NAME
    status = staging / STATUS_NAME
    mandatory_label_reader = staging / MANDATORY_LABEL_READER_NAME
    manifest_path = staging / MANIFEST_NAME
    try:
        with zipfile.ZipFile(artifact, mode="w", compression=zipfile.ZIP_STORED) as archive:
            for name in sorted(sources):
                archive.writestr(_zip_entry(name, sources[name]), sources[name])
        artifact_sha256 = _sha256_file(artifact)
        launcher.write_bytes(launcher_bytes)
        launcher_sha256 = _sha256_file(launcher)
        status.write_bytes(status_bytes)
        status_sha256 = _sha256_file(status)
        mandatory_label_reader.write_bytes(mandatory_label_reader_bytes)
        mandatory_label_reader_sha256 = _sha256_file(mandatory_label_reader)
        _copy_runtime_tree(_runtime_source_root(), runtime)
        runtime_entries = _runtime_entries(runtime)
        runtime_sha256 = _runtime_tree_sha256(runtime_entries)
        manifest_core: dict[str, object] = {
            "artifact": ARTIFACT_NAME,
            "artifact_sha256": artifact_sha256,
            "format": "TenderBot.LiveInbound.Release.v2",
            "launcher": LAUNCHER_NAME,
            "launcher_sha256": launcher_sha256,
            "status_script": STATUS_NAME,
            "status_script_sha256": status_sha256,
            "mandatory_label_reader": MANDATORY_LABEL_READER_NAME,
            "mandatory_label_reader_sha256": mandatory_label_reader_sha256,
            "installer_sha256": _sha256_bytes(installer_bytes),
            "python_version": sys.version.split()[0],
            "runtime_dependency_contract": _RUNTIME_POLICY,
            "runtime_executable": f"{RUNTIME_DIR_NAME}/{RUNTIME_EXECUTABLE}",
            "runtime_files": runtime_entries,
            "runtime_sha256": runtime_sha256,
            "source_provenance": source_provenance,
            "source_sha256": {
                name: _sha256_bytes(data) for name, data in sorted(sources.items())
            },
        }
        release_sha256 = _sha256_bytes(_canonical_json(manifest_core))
        manifest = {**manifest_core, "release_sha256": release_sha256}
        manifest_bytes = _canonical_json(manifest) + b"\n"
        manifest_path.write_bytes(manifest_bytes)
        manifest_sha256 = _sha256_bytes(manifest_bytes)
        target = release_root / release_sha256
        if target.exists():
            _verify_existing_release(
                target,
                manifest_bytes=manifest_bytes,
                artifact_sha256=artifact_sha256,
                launcher_sha256=launcher_sha256,
                status_sha256=status_sha256,
                mandatory_label_reader_sha256=mandatory_label_reader_sha256,
                runtime_entries=runtime_entries,
            )
            _cleanup_staging(staging, release_root)
        else:
            os.replace(staging, target)
        return {
            "artifact_path": str(target / ARTIFACT_NAME),
            "artifact_sha256": artifact_sha256,
            "manifest_path": str(target / MANIFEST_NAME),
            "manifest_sha256": manifest_sha256,
            "launcher_path": str(target / LAUNCHER_NAME),
            "launcher_sha256": launcher_sha256,
            "status_path": str(target / STATUS_NAME),
            "status_sha256": status_sha256,
            "mandatory_label_reader_path": str(
                target / MANDATORY_LABEL_READER_NAME
            ),
            "mandatory_label_reader_sha256": mandatory_label_reader_sha256,
            "installer_sha256": _sha256_bytes(installer_bytes),
            "release_dir": str(target),
            "release_sha256": release_sha256,
            "runtime_path": str(target / RUNTIME_DIR_NAME / RUNTIME_EXECUTABLE),
            "runtime_sha256": runtime_sha256,
            "source_reproducible_from_git_head": bool(
                source_provenance["reproducible_from_git_head"]
            ),
            "source_git_head": str(source_provenance["git_head"]),
            "status": "ready",
        }
    except Exception:
        _cleanup_staging(staging, release_root)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a pinned live-inbound release")
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--require-clean-git-head", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        result = build_release(
            arguments.output_root,
            require_clean_git_head=bool(arguments.require_clean_git_head),
        )
    except Exception:
        print(json.dumps({"status": "error", "error": "live_inbound_release_build_failed"}))
        return 4
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
