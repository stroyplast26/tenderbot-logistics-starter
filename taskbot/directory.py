from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class User:
    tg_id: int
    bitrix_id: int
    alias: str
    role: str
    display_name: str


class Directory:
    """Локальная явная привязка Telegram-пользователь → пользователь Bitrix24."""

    def __init__(self, path: Path) -> None:
        self._by_tg: dict[int, User] = {}
        self._by_alias: dict[str, User] = {}
        self._by_bitrix: dict[int, User] = {}
        if not path.exists():
            return
        rows = json.loads(path.read_text(encoding="utf-8")).get("users", [])
        for row in rows:
            user = User(
                int(row["tg_id"]),
                int(row["bitrix_id"]),
                str(row["alias"]).lower(),
                str(row["role"]).lower(),
                str(row.get("display_name") or row["alias"]),
            )
            self._by_tg[user.tg_id] = user
            self._by_bitrix[user.bitrix_id] = user
            for alias in [user.alias, *row.get("aliases", [])]:
                self._by_alias[str(alias).lower().lstrip("@")] = user

    def by_tg(self, tg_id: int) -> User | None:
        return self._by_tg.get(tg_id)

    def by_alias(self, alias: str) -> User | None:
        return self._by_alias.get(alias.lower().lstrip("@"))

    def by_bitrix(self, bitrix_id: int) -> User | None:
        return self._by_bitrix.get(bitrix_id)

    def aliases(self) -> list[str]:
        return sorted(self._by_alias)

    def users(self) -> list[User]:
        return list(self._by_tg.values())
