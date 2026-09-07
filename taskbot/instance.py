from __future__ import annotations

import os


class AlreadyRunning(RuntimeError):
    pass


class SingleInstance:
    """Один процесс long polling на компьютере (Windows и POSIX)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._handle = None
        self._file = None

    def __enter__(self) -> "SingleInstance":
        if os.name == "nt":
            import ctypes

            kernel32 = ctypes.windll.kernel32
            self._handle = kernel32.CreateMutexW(None, True, self.name)
            if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                kernel32.CloseHandle(self._handle)
                raise AlreadyRunning("TaskBot is already running")
            return self
        import fcntl
        from pathlib import Path

        path = Path(__file__).parent / "data" / ".taskbot.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("w")
        try:
            fcntl.flock(self._file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AlreadyRunning("TaskBot is already running") from exc
        return self

    def __exit__(self, *_: object) -> None:
        if self._handle is not None:
            import ctypes
            ctypes.windll.kernel32.ReleaseMutex(self._handle)
            ctypes.windll.kernel32.CloseHandle(self._handle)
        if self._file is not None:
            self._file.close()
