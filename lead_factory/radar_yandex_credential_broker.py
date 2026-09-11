"""Load one locally protected Yandex Search key without exposing it to argv/env.

The broker is deliberately small and Windows-only.  Its fixed, repository-local
PowerShell helper validates the DPAPI envelope and its connection metadata.  The
returned key exists only in captured process output and caller memory. TenderBot
does not place it in a child environment, command line, log, persisted artifact,
or exception message.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import NoReturn


_BROKER_ERROR = "YANDEX_CREDENTIAL_BROKER_REJECTED"
_API_KEY_ENVIRONMENT_NAME = "YANDEX_SEARCH_API_KEY"
_FOLDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{2,127}\Z")
_API_KEY_PATTERN = re.compile(r"[A-Za-z0-9._~-]{16,512}\Z")
_BROKER_TIMEOUT_SECONDS = 15
_MAX_CAPTURE_BYTES = 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

_MODULE_PATH = Path(__file__).absolute()
_REPO_ROOT = _MODULE_PATH.parent.parent
_HELPER_PATH = _REPO_ROOT / "scripts" / "read_yandex_credential.ps1"


class YandexCredentialBrokerError(RuntimeError):
    """A deliberately non-diagnostic error that cannot disclose key material."""

    code = _BROKER_ERROR

    def __init__(self) -> None:
        super().__init__(_BROKER_ERROR)


def _reject() -> NoReturn:
    raise YandexCredentialBrokerError() from None


def _windows_powershell_path() -> Path:
    """Resolve WindowsPowerShell from the OS, never from PATH or environment."""
    copied = 0
    windows_directory = ""
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        copied = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        windows_directory = buffer.value
    except Exception:
        pass
    if copied <= 0 or copied >= 32768 or not windows_directory:
        _reject()
    return Path(windows_directory) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def _has_reparse_component(path: Path) -> bool:
    """Reject junctions/symlinks in the complete fixed executable/script path."""
    current = path
    while True:
        attributes = None
        try:
            attributes = int(getattr(os.lstat(current), "st_file_attributes", 0))
        except Exception:
            pass
        if attributes is None:
            _reject()
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _validate_runtime_paths() -> tuple[Path, Path]:
    expected_helper = _REPO_ROOT / "scripts" / "read_yandex_credential.ps1"
    if _HELPER_PATH != expected_helper or not _REPO_ROOT.is_absolute():
        _reject()
    powershell = _windows_powershell_path()
    if not powershell.is_absolute():
        _reject()
    helper_stat = None
    powershell_stat = None
    try:
        helper_stat = os.lstat(_HELPER_PATH)
        powershell_stat = os.lstat(powershell)
    except Exception:
        pass
    if helper_stat is None or powershell_stat is None:
        _reject()
    if not stat.S_ISREG(helper_stat.st_mode) or not stat.S_ISREG(powershell_stat.st_mode):
        _reject()
    if _has_reparse_component(_HELPER_PATH) or _has_reparse_component(powershell):
        _reject()
    return powershell, _HELPER_PATH


def _child_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() != _API_KEY_ENVIRONMENT_NAME
    }


def _validated_secret(stdout: bytes, stderr: bytes, returncode: int) -> str | None:
    if (
        not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or returncode != 0
        or stderr
        or not stdout
        or len(stdout) > _MAX_CAPTURE_BYTES
    ):
        return None
    value = None
    try:
        value = stdout.decode("ascii")
    except Exception:
        pass
    if value is None:
        return None
    if "\r" in value or "\n" in value or not _API_KEY_PATTERN.fullmatch(value):
        return None
    return value


def _load_yandex_api_key(expected_folder_id: str) -> str:
    if os.name != "nt" or not isinstance(expected_folder_id, str):
        _reject()
    if not _FOLDER_ID_PATTERN.fullmatch(expected_folder_id):
        _reject()
    powershell, helper = _validate_runtime_paths()
    argv = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(helper),
        "-ExpectedFolderId",
        expected_folder_id,
    ]
    completed = None
    try:
        completed = subprocess.run(
            argv,
            cwd=str(_REPO_ROOT),
            env=_child_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_BROKER_TIMEOUT_SECONDS,
            check=False,
            shell=False,
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass
    if completed is None:
        _reject()
    stdout = completed.stdout
    stderr = completed.stderr
    returncode = completed.returncode
    completed = None
    value = _validated_secret(stdout, stderr, returncode)
    stdout = b""
    stderr = b""
    if type(value) is not str:
        value = None
        _reject()
    return value


def load_yandex_api_key(*, expected_folder_id: str) -> str:
    """Decrypt and validate the fixed CurrentUser DPAPI credential.

    The caller must already have completed request admission and determined that
    no completed cache entry is available.  This function performs no network,
    CRM, filesystem write, or retry operation.  Every ordinary failure is
    collapsed to one non-diagnostic exception outside the originating handler.
    """
    value = None
    try:
        value = _load_yandex_api_key(expected_folder_id)
    except Exception:
        pass
    if value is None:
        _reject()
    return value


__all__ = ["YandexCredentialBrokerError", "load_yandex_api_key"]
