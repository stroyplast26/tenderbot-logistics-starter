from __future__ import annotations

from typing import Any

import requests

from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call


class BitrixError(RuntimeError):
    pass


class BitrixCanaryHold(BitrixError):
    """A live Factory canary owns the Bitrix write lane."""


class BitrixMethodRejected(BitrixError):
    """A raw TaskBot method is absent from the exact reviewed inventory."""


_TASK_READ_ONLY_BITRIX_METHODS = frozenset({
    "app.info",
    "tasks.task.list",
    "tasks.task.get",
})
_TASK_WRITE_BITRIX_METHODS = frozenset({
    "tasks.task.add",
    "tasks.task.complete",
    "tasks.task.delete",
    "tasks.task.start",
    "tasks.task.update",
})
_TASK_V3_WRITE_BITRIX_METHODS = frozenset({"tasks.task.result.add"})
_METHOD_REJECTED = "TASKBOT_BITRIX_METHOD_REJECTED"


def _assert_legacy_bitrix_write_allowed() -> None:
    """Keep TaskBot's old direct REST mutations out of a live canary.

    Reads remain available.  The durable selector is deliberately imported at
    call time so a stopped canary immediately releases the old path without
    caching state in a long-running TaskBot process.
    """
    from lead_factory.legacy_canary_guard import legacy_canary_holds_legacy_outboxes

    if legacy_canary_holds_legacy_outboxes():
        raise BitrixCanaryHold("Bitrix write is held while a Factory canary is active")


def _classify_method(method: object, *, v3: bool = False) -> tuple[str, str]:
    """Return canonical method and authority operation or reject it."""

    canonical_method = str(method or "").strip().casefold()
    if v3:
        if canonical_method not in _TASK_V3_WRITE_BITRIX_METHODS:
            raise BitrixMethodRejected(_METHOD_REJECTED)
        return canonical_method, "taskbot.bitrix.write"
    if canonical_method in _TASK_READ_ONLY_BITRIX_METHODS:
        return canonical_method, "taskbot.bitrix.read"
    if canonical_method in _TASK_WRITE_BITRIX_METHODS:
        return canonical_method, "taskbot.bitrix.write"
    raise BitrixMethodRejected(_METHOD_REJECTED)


class BitrixTasks:
    def __init__(self, webhook: str) -> None:
        self._base = webhook.rstrip("/")
        self._http = requests.Session()

    def _call(self, method: str, payload: dict[str, Any] | None = None) -> Any:
        canonical_method, operation = _classify_method(method)
        if operation == "taskbot.bitrix.write":
            _assert_legacy_bitrix_write_allowed()
        try:
            response = guarded_manual_http_call(
                operation,
                f"POST /rest/{{user}}/{{token}}/{canonical_method}.json",
                "bitrix24:webhook",
                f"{self._base}/{canonical_method}.json",
                self._http.post,
                json=payload or {},
                timeout=30,
                allow_redirects=False,
            )
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            # Исключение requests может содержать URL вебхука, поэтому не пишем его в лог.
            raise BitrixError(f"Bitrix24 temporarily unavailable ({type(exc).__name__})") from exc
        if "error" in body:
            raise BitrixError(body.get("error_description") or body["error"])
        return body.get("result")

    def _call_v3(self, method: str, payload: dict[str, Any] | None = None) -> Any:
        """Call a REST 3.0 task method through the same incoming webhook.

        Most task methods used by the bot still work on the legacy
        ``/rest/{user}/{token}/method.json`` route. Task results are REST 3.0
        and require ``/rest/api/{user}/{token}/method`` instead.
        """
        # TaskBot currently has no inventoried read through the REST 3 route.
        canonical_method, operation = _classify_method(method, v3=True)
        _assert_legacy_bitrix_write_allowed()
        if "/rest/" not in self._base:
            raise BitrixError("Bitrix24 webhook has an unsupported format")
        api_base = self._base.replace("/rest/", "/rest/api/", 1)
        try:
            response = guarded_manual_http_call(
                operation,
                f"POST /rest/api/{{user}}/{{token}}/{canonical_method}",
                "bitrix24:webhook",
                f"{api_base}/{canonical_method}",
                self._http.post,
                json=payload or {},
                timeout=30,
                allow_redirects=False,
            )
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise BitrixError(f"Bitrix24 temporarily unavailable ({type(exc).__name__})") from exc
        if "error" in body:
            error = body["error"]
            if isinstance(error, dict):
                raise BitrixError(str(error.get("message") or error.get("code") or "Bitrix24 API error"))
            raise BitrixError(str(body.get("error_description") or error))
        return body.get("result")

    def app_info(self) -> dict[str, Any]:
        return self._call("app.info")

    def list_my_open_tasks(self, bitrix_user_id: int) -> list[dict[str, Any]]:
        result = self._call(
            "tasks.task.list",
            {
                # tasks.task.list does not accept a list as a STATUS filter.
                # Passing one silently returns no tasks, which used to erase the
                # local task snapshot.  Fetch the user's tasks and filter open
                # states locally instead.
                "filter": {"RESPONSIBLE_ID": bitrix_user_id},
                "select": ["ID", "TITLE", "DEADLINE", "STATUS", "STATUS_COMPLETE", "PRIORITY"],
                "order": {"DEADLINE": "ASC"},
            },
        )
        tasks = list(result.get("tasks", [])) if isinstance(result, dict) else []
        return [task for task in tasks if str(task.get("status", task.get("STATUS", ""))) in {"2", "3", "4", "6"}]

    def get_task(self, task_id: int) -> dict[str, Any]:
        result = self._call(
            "tasks.task.get",
            {"taskId": task_id, "select": ["ID", "TITLE", "DESCRIPTION", "DEADLINE", "PRIORITY", "RESPONSIBLE_ID", "CREATED_BY", "STATUS", "STATUS_COMPLETE", "CREATED_DATE", "CHANGED_DATE"]},
        )
        task = result.get("task", result) if isinstance(result, dict) else result
        if not isinstance(task, dict):
            raise BitrixError("Bitrix24 returned an invalid task")
        return task

    def create_task(self, *, title: str, responsible_id: int, deadline: str | None, priority: str, creator_tg_id: int) -> int:
        _assert_legacy_bitrix_write_allowed()
        priority_value = {"high": "2", "medium": "1", "low": "0"}.get(priority, "1")
        fields: dict[str, Any] = {
            "TITLE": title,
            "RESPONSIBLE_ID": responsible_id,
            "PRIORITY": priority_value,
            "DESCRIPTION": f"Создано через TaskBot. Telegram инициатор: {creator_tg_id}",
        }
        if deadline:
            fields["DEADLINE"] = deadline
        result = self._call(
            "tasks.task.add",
            {"fields": fields},
        )
        task = result.get("task", result) if isinstance(result, dict) else result
        return int(task["id"] if isinstance(task, dict) else task)

    def complete_task(self, task_id: int) -> None:
        _assert_legacy_bitrix_write_allowed()
        self._call("tasks.task.complete", {"taskId": task_id})

    def start_task(self, task_id: int) -> None:
        """Mark a task as accepted/in progress in Bitrix24."""
        _assert_legacy_bitrix_write_allowed()
        self._call("tasks.task.start", {"taskId": task_id})

    def move_deadline(self, task_id: int, deadline: str) -> None:
        self.update_task(task_id, {"DEADLINE": deadline})

    def update_task(self, task_id: int, fields: dict[str, Any]) -> None:
        _assert_legacy_bitrix_write_allowed()
        self._call("tasks.task.update", {"taskId": task_id, "fields": fields})

    def add_result(self, task_id: int, text: str) -> None:
        _assert_legacy_bitrix_write_allowed()
        self._call_v3("tasks.task.result.add", {"fields": {"taskId": task_id, "text": text}})

    def delete_task(self, task_id: int) -> None:
        _assert_legacy_bitrix_write_allowed()
        self._call("tasks.task.delete", {"taskId": task_id})
