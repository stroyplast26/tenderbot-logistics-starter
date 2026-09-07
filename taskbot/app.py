from __future__ import annotations

import logging
import json
import re
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from taskbot.bitrix import BitrixError, BitrixTasks
from taskbot.config import Config
from taskbot.directory import Directory, User
from taskbot.instance import AlreadyRunning, SingleInstance
from taskbot.openrouter import ActionPlan, ChatIntent, OpenRouter, OpenRouterError, TaskIntent
from taskbot.storage import Draft, ManagedTask, Storage, TaskSnapshot
from taskbot.telegram import Telegram, TelegramError

# В России нет сезонного перевода времени; так TaskBot не зависит от tzdata на Windows.
MOSCOW = timezone(timedelta(hours=3), name="Europe/Moscow")
LOG = logging.getLogger("taskbot")
MAIN_MENU = [["🎯 Сейчас", "➕ Добавить"], ["📥 Входящие", "☰ Ещё"]]
DEFAULT_DEADLINE = object()


class App:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.tg = Telegram(config.telegram_token)
        self.bitrix = BitrixTasks(config.bitrix_webhook)
        self.ai = OpenRouter(config.openrouter_api_key, config.text_model, config.speech_model)
        self.users = Directory(config.users_path)
        self.storage = Storage(config.database_path)
        self.offset: int | None = None
        self._next_reminder_sync = 0.0

    @staticmethod
    def _deadline() -> str:
        now = datetime.now(MOSCOW)
        due = now.replace(hour=19, minute=0, second=0, microsecond=0)
        if now >= due:
            due += timedelta(days=1)
        return due.isoformat()

    def _preferred_deadline(self, user: User) -> str:
        for memory in self.storage.memories(user.tg_id):
            value = memory.lower()
            if "без срока" not in value:
                continue
            day = re.search(r"\b(сегодня|завтра)\b", value)
            hour = re.search(r"(?:в\s*)?(\d{1,2})(?::(\d{2}))?", value)
            if not day or not hour:
                continue
            hour_value, minute_value = int(hour.group(1)), int(hour.group(2) or 0)
            if not 0 <= hour_value <= 23 or not 0 <= minute_value <= 59:
                continue
            due = (datetime.now(MOSCOW) + timedelta(days=1 if day.group(1) == "завтра" else 0)).replace(hour=hour_value, minute=minute_value, second=0, microsecond=0)
            if due > datetime.now(MOSCOW):
                return due.isoformat()
        return self._deadline()

    @staticmethod
    def _explicitly_no_deadline(text: str) -> bool:
        """Recognise an explicit request to leave a task without a deadline.

        An omitted deadline still receives the user's preferred default.  This
        small distinction matters: "без срока" must never quietly turn into a
        deadline tonight.
        """
        value = text.lower().replace("ё", "е")
        phrases = (
            "без срока",
            "без дедлайна",
            "срок не ставь",
            "срока не ставь",
            "не ставь срок",
            "не ставь дедлайн",
            "дедлайн не ставь",
        )
        return any(phrase in value for phrase in phrases)

    def _user(self, tg_id: int) -> User | None:
        return self.users.by_tg(tg_id)

    def _require_user(self, chat_id: int, tg_id: int) -> User | None:
        user = self._user(tg_id)
        if not user:
            self.tg.send(chat_id, f"Вы ещё не подключены к TaskBot. Ваш Telegram ID: {tg_id}. Передайте его администратору для привязки к Bitrix24.")
        return user

    def _show_menu(self, chat_id: int, text: str = "Выберите действие или просто напишите/надиктуйте задачу.") -> None:
        self.tg.send(chat_id, text, reply_keyboard=MAIN_MENU)

    def _draft_keyboard(self, draft: Draft) -> list[list[dict[str, str]]]:
        return [
            [{"text": "✅ Создать", "callback_data": f"task:confirm:{draft.id}"}, {"text": "✏️ Исправить", "callback_data": f"draft:edit:{draft.id}"}],
            [{"text": "Отмена", "callback_data": f"task:cancel:{draft.id}"}],
        ]

    def _send_draft_card(self, chat_id: int, draft: Draft, *, transcript: str | None = None) -> None:
        self.storage.set_conversation_state(draft.creator_tg_id, last_draft_id=draft.id)
        responsible = self.users.by_bitrix(draft.responsible_id)
        priority_label = {"high": "Высокий", "medium": "Обычный", "low": "Низкий"}.get(draft.priority, "Обычный")
        prefix = f"🎙 Распознано: {transcript}\n\n" if transcript else ""
        self.tg.send(
            chat_id,
            f"{prefix}Новая задача\n\n{draft.title}\n\n"
            f"👤 {responsible.display_name if responsible else 'Не выбран'}\n"
            f"📅 {draft.deadline[:16] if draft.deadline else 'без срока'}\n🔥 {priority_label}\n\n"
            "Проверьте карточку или исправьте нужное поле.",
            self._draft_keyboard(draft),
        )

    def _draft(self, chat_id: int, actor: User, title: str, responsible: User, *, deadline: str | None | object = DEFAULT_DEADLINE, priority: str = "medium", transcript: str | None = None) -> None:
        title = title.strip()
        if not title:
            self.tg.send(chat_id, "Напишите текст задачи после команды. Например: /task Согласовать смету")
            return
        effective_deadline = self._preferred_deadline(actor) if deadline is DEFAULT_DEADLINE else (deadline or "")
        draft = self.storage.create_draft(title, responsible.bitrix_id, actor.tg_id, effective_deadline, priority)
        self._send_draft_card(chat_id, draft, transcript=transcript)

    def _draft_from_text(self, chat_id: int, actor: User, text: str, *, forced_responsible: User | None = None, transcript: str | None = None) -> None:
        try:
            intents = self.ai.parse_tasks(text, aliases=self.users.aliases(), now=datetime.now(MOSCOW), context=self._conversation_context(actor))
        except OpenRouterError:
            # Интеллектуальный разбор не должен терять задачу при временном сбое AI.
            intents = [TaskIntent(title=text, deadline=None, priority="medium", assignee_alias=None)]
        if len(intents) > 1:
            self.tg.send(chat_id, f"Я понял {len(intents)} отдельные задачи. Проверьте каждую карточку перед созданием.", reply_keyboard=MAIN_MENU)
        for intent in intents:
            responsible = forced_responsible or actor
            if not forced_responsible and actor.role in {"owner", "partner"} and intent.assignee_alias:
                responsible = self.users.by_alias(intent.assignee_alias) or actor
            deadline: str | None | object = None if self._explicitly_no_deadline(text) else (intent.deadline or DEFAULT_DEADLINE)
            self._draft(chat_id, actor, intent.title, responsible, deadline=deadline, priority=intent.priority, transcript=transcript if len(intents) == 1 else None)

    def _split_pending_draft(self, chat_id: int, actor: User, instruction: str) -> bool:
        original = self.storage.latest_pending_draft(actor.tg_id)
        if not original:
            return False
        try:
            intents = self.ai.parse_tasks(
                f"Исходный черновик: {original.title}\n\nУточнение пользователя: {instruction}",
                aliases=self.users.aliases(),
                now=datetime.now(MOSCOW),
                context=self._conversation_context(actor),
            )
        except OpenRouterError:
            self.tg.send(chat_id, "Не смог надёжно разделить черновик. Напишите две задачи отдельными сообщениями — я покажу по карточке на каждую.", reply_keyboard=MAIN_MENU)
            return True
        if len(intents) < 2:
            self.tg.send(chat_id, "Я не понял, на какие отдельные результаты разделить задачу. Скажите, например: «первая — ..., вторая — ...».", reply_keyboard=MAIN_MENU)
            return True
        responsible = self.users.by_bitrix(original.responsible_id) or actor
        self.storage.record_correction(actor.tg_id, original.id, original.title, instruction)
        self.storage.set_status(original.id, "replaced")
        self.tg.send(chat_id, f"Разделил черновик на {len(intents)} задачи. Старый черновик отменён — создадутся только подтверждённые карточки ниже.", reply_keyboard=MAIN_MENU)
        for intent in intents:
            target = responsible
            if actor.role in {"owner", "partner"} and intent.assignee_alias:
                target = self.users.by_alias(intent.assignee_alias) or responsible
            self._draft(
                chat_id,
                actor,
                intent.title,
                target,
                deadline="" if self._explicitly_no_deadline(instruction) else (intent.deadline or original.deadline),
                priority=intent.priority if intent.priority != "medium" else original.priority,
            )
        return True

    def _conversation_context(self, user: User) -> str:
        state = self.storage.conversation_state(user.tg_id)
        rows = self.storage.recent_memory(user.tg_id)
        parts = [f"{role}: {text}" for role, text in rows]
        memories = self.storage.memories(user.tg_id)
        if memories:
            parts.append("Явно сохранённые предпочтения пользователя: " + "; ".join(memories))
        corrections = self.storage.recent_corrections(user.tg_id)
        if corrections:
            parts.append("Недавние исправления пользователя: " + "; ".join(
                f"для «{original or 'черновика'}»: {correction}" for original, correction in corrections
            ))
        projects = self.storage.projects(user.tg_id)
        if projects:
            parts.append("Активные проекты: " + "; ".join(project.title for project in projects[:10]))
        goals = self.storage.goals(user.tg_id)
        if goals:
            parts.append("Активные цели: " + "; ".join(goal.title for goal in goals[:10]))
        draft = (self.storage.get_pending(state.last_draft_id) if state.last_draft_id else None) or self.storage.latest_pending_draft(user.tg_id)
        if draft:
            responsible = self.users.by_bitrix(draft.responsible_id)
            parts.append(f"Активный черновик: «{draft.title}», исполнитель {responsible.display_name if responsible else 'не указан'}, срок {draft.deadline or 'без срока'}, приоритет {draft.priority}.")
        if state.last_task_id:
            snapshot = self.storage.get_snapshot(user.tg_id, state.last_task_id)
            if snapshot:
                parts.append(f"Последняя открытая задача: «{snapshot.title}» (id {snapshot.task_id}).")
                runtime = self.storage.task_runtime(snapshot.task_id)
                if runtime:
                    parts.append(
                        f"Рабочий контекст задачи: состояние {runtime.state}; следующий шаг {runtime.next_step or 'не задан'}; "
                        f"прогресс {runtime.last_progress or 'нет'}; блокер {runtime.blocker or 'нет'}."
                    )
        return "\n".join(parts[-14:])

    def _modify_active_draft(self, chat_id: int, user: User, intent: ChatIntent, text: str) -> bool:
        state = self.storage.conversation_state(user.tg_id)
        draft = (self.storage.get_pending(state.last_draft_id) if state.last_draft_id else None) or self.storage.latest_pending_draft(user.tg_id)
        if not draft:
            return False
        self.storage.record_correction(user.tg_id, draft.id, draft.title, text)
        if intent.field == "split":
            return self._split_pending_draft(chat_id, user, text)
        if intent.field == "deadline" and intent.deadline:
            updated = self.storage.update_draft(draft.id, deadline=intent.deadline)
        elif intent.field == "priority":
            value = (intent.value or text).lower()
            priority = "high" if any(marker in value for marker in ("сроч", "важн", "высок")) else "low" if any(marker in value for marker in ("низк", "несроч")) else "medium"
            updated = self.storage.update_draft(draft.id, priority=priority)
        elif intent.field == "assignee":
            target = self.users.by_alias(intent.value or "")
            updated = self.storage.update_draft(draft.id, responsible_id=target.bitrix_id) if target and user.role in {"owner", "partner"} else None
        elif intent.field == "title" and intent.value:
            updated = self.storage.update_draft(draft.id, title=intent.value)
        else:
            self.tg.send(chat_id, "Я понял, что нужно исправить текущий черновик, но не понял какое поле. Напишите, например: «срок завтра в 15:00», «сделай срочной» или «назови: ...».", reply_keyboard=MAIN_MENU)
            return True
        if not updated:
            self.tg.send(chat_id, "Не удалось применить уточнение к черновику. Попробуйте сформулировать его иначе.", reply_keyboard=MAIN_MENU)
            return True
        self.tg.send(chat_id, "Исправил текущий черновик:", reply_keyboard=MAIN_MENU)
        self._send_draft_card(chat_id, updated)
        return True

    def _voice_to_draft(self, chat_id: int, actor: User, voice: dict, *, forced_responsible: User | None = None) -> None:
        self.tg.send(chat_id, "Распознаю голосовое…")
        try:
            with tempfile.TemporaryDirectory(prefix="taskbot-voice-") as directory:
                local_audio = Path(directory) / "voice.ogg"
                file_path = self.tg.get_file_path(str(voice["file_id"]))
                self.tg.download_file(file_path, local_audio)
                transcript = self.ai.transcribe(local_audio, "ogg")
            if forced_responsible:
                self._draft_from_text(chat_id, actor, transcript, forced_responsible=forced_responsible, transcript=transcript)
            else:
                self._route_free_text(chat_id, actor, transcript, transcript=transcript)
        except (TelegramError, OpenRouterError):
            self.tg.send(chat_id, "Не удалось распознать голосовое. Отправьте его ещё раз или напишите задачу текстом.")

    def _voice_to_runtime(self, chat_id: int, user: User, voice: dict, snapshot: TaskSnapshot, kind: str | None) -> None:
        self.tg.send(chat_id, "Распознаю обновление по задаче…")
        try:
            with tempfile.TemporaryDirectory(prefix="taskbot-voice-") as directory:
                local_audio = Path(directory) / "voice.ogg"
                file_path = self.tg.get_file_path(str(voice["file_id"]))
                self.tg.download_file(file_path, local_audio)
                transcript = self.ai.transcribe(local_audio, "ogg")
            self.tg.send(chat_id, f"🎙 Распознано: {transcript}", reply_keyboard=MAIN_MENU)
            self._apply_runtime_update(chat_id, user, snapshot, transcript, requested_kind=kind)
        except (TelegramError, OpenRouterError):
            self.tg.send(chat_id, "Не удалось распознать голосовое. Отправьте его ещё раз или напишите обновление текстом.", reply_keyboard=MAIN_MENU)

    @staticmethod
    def _fallback_intent(text: str) -> ChatIntent:
        value = text.lower()
        if any(word in value for word in ("перенес", "сдвин", "измени срок", "поставь срок")):
            return ChatIntent("reschedule", text, None)
        if any(word in value for word in ("заверши", "закрой", "выполнил", "готово")):
            return ChatIntent("complete", text, None)
        if any(word in value for word in ("удали", "удалить")):
            return ChatIntent("delete", text, None)
        if any(word in value for word in ("покажи", "открой", "найди", "список")):
            return ChatIntent("search", text, None)
        if "?" in value or any(word in value for word in ("что важ", "что делать", "какая задача")):
            return ChatIntent("focus", None, None)
        return ChatIntent("create", None, None)

    @staticmethod
    def _match_score(title: str, query: str) -> int:
        title_lower = title.lower()
        query_lower = query.lower()
        if query_lower in title_lower or title_lower in query_lower:
            return 100
        ignored = {"задачу", "задача", "пожалуйста", "перенеси", "срок", "на", "до", "заверши", "удали", "покажи", "открой", "найди"}
        query_words = {word for word in query_lower.replace("?", " ").replace(",", " ").split() if len(word) > 2 and word not in ignored}
        title_words = set(title_lower.replace("?", " ").replace(",", " ").split())
        return len(query_words & title_words)

    def _find_task(self, user: User, query: str | None) -> list[TaskSnapshot]:
        try:
            snapshots = self.storage.sync_task_snapshots(user.tg_id, self.bitrix.list_my_open_tasks(user.bitrix_id))
        except BitrixError:
            return []
        if not query:
            return snapshots[:5]
        value = query.lower()
        state = self.storage.conversation_state(user.tg_id)
        if any(marker in value for marker in ("её", "ее", "эту", "последн")) and state.last_task_id:
            current = next((snapshot for snapshot in snapshots if snapshot.task_id == state.last_task_id), None)
            if current:
                return [current]
        if "перв" in value and snapshots:
            return [snapshots[0]]
        if "втор" in value and len(snapshots) > 1:
            return [snapshots[1]]
        scored = [(self._match_score(snapshot.title, query), snapshot) for snapshot in snapshots]
        lexical = [snapshot for score, snapshot in sorted(scored, key=lambda item: item[0], reverse=True) if score > 0][:5]
        if len(lexical) == 1:
            return lexical
        try:
            ids = self.ai.resolve_task_reference(
                query,
                [{"id": snapshot.task_id, "title": snapshot.title, "deadline": snapshot.deadline or ""} for snapshot in snapshots[:25]],
                context=self._conversation_context(user),
            )
        except OpenRouterError:
            return lexical
        resolved = [snapshot for snapshot in snapshots if snapshot.task_id in ids]
        return resolved or lexical

    def _choose_task(self, chat_id: int, tasks: list[TaskSnapshot], text: str) -> None:
        if not tasks:
            self.tg.send(chat_id, "Не нашёл открытую задачу. Напишите несколько слов из её названия или откройте «🎯 Сегодня».", reply_keyboard=MAIN_MENU)
            return
        keyboard = [[{"text": self._button_title(index, task.title), "callback_data": f"view:open:{task.task_id}"}] for index, task in enumerate(tasks, 1)]
        self.tg.send(chat_id, text, keyboard=keyboard)

    def _offer_natural_action(self, chat_id: int, user: User, intent: ChatIntent) -> None:
        tasks = self._find_task(user, intent.task_query)
        if len(tasks) != 1:
            self._choose_task(chat_id, tasks, "Уточните, о какой задаче речь:")
            return
        task = tasks[0]
        if intent.kind == "complete":
            self._request_runtime_input(chat_id, user, task, "finish")
            return
        if intent.kind == "reschedule" and not intent.deadline:
            self.tg.send(chat_id, f"Нашёл задачу «{task.title}». На какой день и время перенести? Например: «перенеси её на пятницу в 15:00».", reply_keyboard=MAIN_MENU)
            return
        if intent.kind == "delete":
            managed = self.storage.managed_task(task.task_id)
            if user.role != "owner" and (not managed or managed.creator_tg_id != user.tg_id):
                self.tg.send(chat_id, "Удаление недоступно: задачу может удалить только её постановщик или владелец TaskBot.", reply_keyboard=MAIN_MENU)
                return
        action = self.storage.create_pending_action(user.tg_id, intent.kind, task.task_id, intent.deadline)
        labels = {
            "reschedule": f"Перенести задачу «{task.title}» на {self._parse_iso(intent.deadline):%d.%m %H:%M}?",
            "complete": f"Завершить задачу «{task.title}»?",
            "delete": f"🗑 Удалить задачу «{task.title}»? Это действие нельзя отменить.",
        }
        self.tg.send(
            chat_id,
            labels[intent.kind],
            keyboard=[[{"text": "✅ Подтвердить", "callback_data": f"act:confirm:{action.id}"}, {"text": "Отмена", "callback_data": f"act:cancel:{action.id}"}]],
        )

    @staticmethod
    def _looks_like_plan(text: str) -> bool:
        value = text.lower()
        verbs = sum(marker in value for marker in ("постав", "создай", "перенес", "сдвин", "заверш", "закрой", "удали", "найди", "покажи"))
        return verbs >= 2 or (verbs >= 1 and any(marker in value for marker in (" а ", " затем ", "после этого")))

    def _offer_action_plan(self, chat_id: int, user: User, plan: ActionPlan) -> bool:
        operations: list[dict[str, str | None]] = []
        lines: list[str] = []
        for item in plan.actions:
            if item.kind == "create" and item.title:
                operations.append({"kind": "create", "title": item.title, "deadline": item.deadline, "priority": item.priority, "assignee_alias": item.assignee_alias, "task_id": None})
                target = self.users.by_alias(item.assignee_alias) if item.assignee_alias else user
                lines.append(f"• Новая: {item.title} → {(target.display_name if target else user.display_name)}")
                continue
            if item.kind not in {"reschedule", "complete", "delete"}:
                continue
            tasks = self._find_task(user, item.task_query)
            if len(tasks) != 1:
                self._choose_task(chat_id, tasks, "Сначала уточните задачу для этого пункта плана:")
                return True
            task = tasks[0]
            if item.kind == "reschedule" and not item.deadline:
                self.tg.send(chat_id, f"Для задачи «{task.title}» не указан новый срок. Уточните его одним сообщением.", reply_keyboard=MAIN_MENU)
                return True
            if item.kind == "delete":
                managed = self.storage.managed_task(task.task_id)
                if user.role != "owner" and (not managed or managed.creator_tg_id != user.tg_id):
                    self.tg.send(chat_id, f"Не могу добавить удаление «{task.title}» в план: у вас нет права удаления.", reply_keyboard=MAIN_MENU)
                    return True
            operations.append({"kind": item.kind, "title": task.title, "deadline": item.deadline, "priority": None, "assignee_alias": None, "task_id": task.task_id})
            label = {"reschedule": f"Перенести: {task.title}", "complete": f"Завершить: {task.title}", "delete": f"Удалить: {task.title}"}[item.kind]
            lines.append("• " + label)
        if len(operations) < 2:
            return False
        action = self.storage.create_pending_action(user.tg_id, "plan_prepare", "0", json.dumps(operations, ensure_ascii=False))
        self.tg.send(
            chat_id,
            "Я понял такой план:\n" + "\n".join(lines) + "\n\nПодготовить карточки действий? Ничего в Bitrix24 пока не изменится.",
            keyboard=[[{"text": "✅ Подготовить", "callback_data": f"act:confirm:{action.id}"}, {"text": "Отмена", "callback_data": f"act:cancel:{action.id}"}]],
        )
        return True

    def _prepare_action_card(self, chat_id: int, user: User, operation: dict[str, str | None]) -> None:
        kind = operation["kind"] or ""
        task_id = operation["task_id"] or ""
        title = operation["title"] or f"Задача #{task_id}"
        action = self.storage.create_pending_action(user.tg_id, kind, task_id, operation.get("deadline"))
        labels = {
            "reschedule": f"Перенести задачу «{title}» на {self._parse_iso(operation.get('deadline')):%d.%m %H:%M}?",
            "complete": f"Завершить задачу «{title}»?",
            "delete": f"🗑 Удалить задачу «{title}»? Это действие нельзя отменить.",
        }
        self.tg.send(chat_id, labels[kind], keyboard=[[{"text": "✅ Подтвердить", "callback_data": f"act:confirm:{action.id}"}, {"text": "Отмена", "callback_data": f"act:cancel:{action.id}"}]])

    def _route_free_text(self, chat_id: int, user: User, text: str, *, transcript: str | None = None) -> None:
        lowered = text.lower()
        if any(lowered.startswith(prefix) for prefix in ("идея:", "мысль:", "сохрани:", "входящие:")):
            self.storage.remember(user.tg_id, "user", text)
            self._capture(chat_id, user, text.split(":", 1)[1].strip())
            return
        if any(marker in lowered for marker in ("раздел", "разедл", "отдельн", "две задач", "два задан")) and self._split_pending_draft(chat_id, user, text):
            return
        state = self.storage.conversation_state(user.tg_id)
        active = self.storage.get_snapshot(user.tg_id, state.last_task_id) if state.last_task_id else None
        if active and self._looks_like_task_update(text) and self._apply_runtime_update(chat_id, user, active, text):
            self.storage.remember(user.tg_id, "user", text)
            return
        context = self._conversation_context(user)
        if self._looks_like_plan(text):
            try:
                plan = self.ai.plan_actions(text, aliases=self.users.aliases(), now=datetime.now(MOSCOW), context=context)
            except OpenRouterError:
                plan = ActionPlan([], None)
            if self._offer_action_plan(chat_id, user, plan):
                self.storage.remember(user.tg_id, "user", text)
                return
        try:
            intent = self.ai.classify_message(text, now=datetime.now(MOSCOW), context=context)
        except OpenRouterError:
            intent = self._fallback_intent(text)
        self.storage.remember(user.tg_id, "user", text)
        if intent.kind == "today":
            self._today(chat_id, user)
        elif intent.kind == "capture":
            self._capture(chat_id, user, text)
        elif intent.kind == "focus":
            self._coach(chat_id, user, text)
        elif intent.kind == "search":
            self._choose_task(chat_id, self._find_task(user, intent.task_query), "Вот подходящие задачи:")
        elif intent.kind in {"reschedule", "complete", "delete"}:
            self._offer_natural_action(chat_id, user, intent)
        elif intent.kind == "modify_draft":
            if not self._modify_active_draft(chat_id, user, intent, text):
                self.tg.send(chat_id, "Не вижу активного черновика. Напишите задачу целиком, и я подготовлю новую карточку.", reply_keyboard=MAIN_MENU)
        elif intent.kind == "clarify":
            self.storage.set_mode(user.tg_id, "clarify_request", text)
            self.tg.send(chat_id, intent.reply or "Уточните, пожалуйста, что именно нужно сделать с задачей.", reply_keyboard=MAIN_MENU)
        elif intent.kind == "help":
            self._show_menu(chat_id, "Напишите, что нужно сделать, спросите о приоритетах или скажите: «перенеси смету на пятницу», «заверши смету», «покажи смету». Бот сначала покажет найденную задачу и попросит подтверждение действия.")
        else:
            self._draft_from_text(chat_id, user, text, transcript=transcript)

    def _offer_update(self, chat_id: int, user: User, task_id: str, fields: dict[str, object], summary: str) -> None:
        snapshot = self.storage.get_snapshot(user.tg_id, task_id)
        if not snapshot:
            self.tg.send(chat_id, "Задача уже изменилась. Откройте её снова через «🎯 Сегодня».", reply_keyboard=MAIN_MENU)
            return
        action = self.storage.create_pending_action(user.tg_id, "update", task_id, json.dumps(fields, ensure_ascii=False))
        self.tg.send(
            chat_id,
            f"Изменить задачу «{snapshot.title}»?\n{summary}",
            keyboard=[[{"text": "✅ Подтвердить", "callback_data": f"act:confirm:{action.id}"}, {"text": "Отмена", "callback_data": f"act:cancel:{action.id}"}]],
        )

    def _task_card(self, snapshot: TaskSnapshot, *, expanded: bool = False) -> tuple[str, list[list[dict[str, str]]]]:
        deadline = self._parse_iso(snapshot.deadline)
        now = datetime.now(MOSCOW)
        if not deadline:
            due = "без срока"
        elif deadline < now:
            due = f"⚠️ просрочена с {deadline:%d.%m %H:%M}"
        elif deadline.date() == now.date():
            due = f"сегодня до {deadline:%H:%M}"
        else:
            due = f"до {deadline:%d.%m %H:%M}"
        priority = {"2": "🔥 высокий приоритет", "1": "обычный приоритет", "0": "низкий приоритет"}.get(snapshot.priority, "обычный приоритет")
        text = f"#{snapshot.task_id}  {snapshot.title}\n📅 {due} · {priority}"
        keyboard = [[
            {"text": "▶️ В работу", "callback_data": f"work:start:{snapshot.task_id}"},
            {"text": "✅ Готово", "callback_data": f"rem:done:{snapshot.task_id}"},
        ]]
        if expanded:
            keyboard.extend([
                [{"text": "📝 Результат", "callback_data": f"rem:result:{snapshot.task_id}"}, {"text": "📅 Завтра", "callback_data": f"rem:tomorrow:{snapshot.task_id}"}],
                [{"text": "⏰ На час", "callback_data": f"rem:snooze:{snapshot.task_id}"}],
            ])
        else:
            keyboard.append([{"text": "⋯ Ещё", "callback_data": f"view:more:{snapshot.task_id}"}])
        return text, keyboard

    @staticmethod
    def _button_title(index: int, title: str) -> str:
        return f"{index}. {title[:38]}{'…' if len(title) > 38 else ''}"

    @staticmethod
    def _field(task: dict, name: str, default: str = "") -> str:
        # REST Bitrix24 returns task fields in two shapes: list endpoints use
        # UPPER_CASE while task.get commonly uses lower camelCase
        # (responsibleId, createdBy).  Keep rendering independent of endpoint.
        parts = name.lower().split("_")
        camel_name = parts[0] + "".join(part.capitalize() for part in parts[1:])
        value = task.get(name, task.get(name.lower(), task.get(camel_name, default)))
        return str(value) if value not in (None, "") else default

    def _send_task_card(self, chat_id: int, user: User, task_id: str, text: str, keyboard: list[list[dict[str, str]]], *, refresh: bool = False) -> None:
        """Keep one useful task card alive instead of filling the chat with stale controls."""
        if refresh:
            card = self.storage.task_card(user.tg_id, task_id)
            if card:
                try:
                    self.tg.edit_message(card.chat_id, card.message_id, text, keyboard)
                    return
                except TelegramError:
                    # A deleted/old Telegram message is harmless; create a fresh card below.
                    pass
        message = self.tg.send(chat_id, text, keyboard=keyboard, reply_keyboard=MAIN_MENU)
        message_id = message.get("message_id") if isinstance(message, dict) else None
        if isinstance(message_id, int):
            self.storage.remember_task_card(user.tg_id, task_id, chat_id, message_id)

    @staticmethod
    def _runtime_state_label(state: str | None) -> str:
        return {
            "planned": "ожидает старта",
            "in_progress": "в работе",
            "blocked": "заблокирована",
            "ready_to_finish": "готова к завершению",
            "completed": "завершена",
        }.get(state or "", "ожидает старта")

    def _task_is_completed(self, task_id: str) -> bool:
        """Read the authoritative completion state before accepting a stale control."""
        try:
            task = self.bitrix.get_task(int(task_id))
        except BitrixError:
            return False
        return self._field(task, "STATUS") == "5"

    def _task_detail(self, chat_id: int, user: User, snapshot: TaskSnapshot, *, expanded: bool = False, refresh: bool = False) -> None:
        self.storage.set_conversation_state(user.tg_id, last_task_id=snapshot.task_id)
        try:
            task = self.bitrix.get_task(int(snapshot.task_id))
        except BitrixError:
            text, keyboard = self._task_card(snapshot, expanded=expanded)
            self._send_task_card(chat_id, user, snapshot.task_id, text + "\n\nНе удалось загрузить подробности; доступны базовые действия.", keyboard, refresh=refresh)
            return
        title = self._field(task, "TITLE", snapshot.title)
        description = self._short(self._field(task, "DESCRIPTION", "Нет описания."), 900)
        if description.startswith("Создано через TaskBot."):
            description = "Описание пока не добавлено. Добавьте контекст через «Изменить»."
        deadline = self._parse_iso(self._field(task, "DEADLINE") or None)
        responsible_id = self._field(task, "RESPONSIBLE_ID")
        creator_id = self._field(task, "CREATED_BY")
        responsible = self.users.by_bitrix(int(responsible_id)) if responsible_id.isdigit() else None
        creator = self.users.by_bitrix(int(creator_id)) if creator_id.isdigit() else None
        project = self.storage.task_project(user.tg_id, snapshot.task_id)
        priority = {"2": "высокий", "1": "обычный", "0": "низкий"}.get(self._field(task, "PRIORITY"), "обычный")
        bitrix_status = self._field(task, "STATUS")
        status = {"2": "ожидает", "3": "в работе", "4": "ждёт контроля", "5": "завершена", "6": "отложена"}.get(bitrix_status, "в работе")
        text = (
            f"#{snapshot.task_id} · {title}\n"
            f"{status.capitalize()} · {priority} приоритет\n"
            f"👤 {responsible.display_name if responsible else 'исполнитель не указан'}\n"
            f"📅 {deadline:%d.%m %H:%M}" if deadline else f"#{snapshot.task_id} · {title}\n{status.capitalize()} · {priority} приоритет\n👤 {responsible.display_name if responsible else 'исполнитель не указан'}\n📅 без срока"
        )
        text += f"\nОт: {creator.display_name if creator else 'не указан'}"
        if project:
            text += f"\n🗂 {project.title}"
        runtime = self.storage.task_runtime(snapshot.task_id)
        runtime_state = "completed" if bitrix_status == "5" else (runtime.state if runtime else "planned")
        text += f"\n\n🧭 {self._runtime_state_label(runtime_state)}"
        if runtime and runtime.next_step:
            text += f"\n➡️ Следующий шаг: {self._short(runtime.next_step, 260)}"
        if runtime and runtime.last_progress:
            text += f"\n📝 Последнее: {self._short(runtime.last_progress, 260)}"
        if runtime and runtime.blocker:
            text += f"\n🚧 Блокер: {self._short(runtime.blocker, 260)}"
        if expanded:
            text += f"\n\n{description}"
        if bitrix_status == "5":
            # A finished task must not expose controls that can accidentally
            # restart it from an old Telegram card. History and deletion stay
            # available to the person who is allowed to remove it.
            keyboard = [[
                {"text": "🕘 История", "callback_data": f"run:history:{snapshot.task_id}"},
                {"text": "🗑 Удалить", "callback_data": f"live:delete:{snapshot.task_id}"},
            ]]
            if expanded:
                keyboard.append([{"text": "← К задаче", "callback_data": f"view:open:{snapshot.task_id}"}])
        else:
            focus_ids = self.storage.focus_task_ids(user.tg_id, datetime.now(MOSCOW).date().isoformat())
            focus_button = {"text": "⭐ В фокус" if snapshot.task_id not in focus_ids else "☆ Убрать из фокуса", "callback_data": f"focus:{'add' if snapshot.task_id not in focus_ids else 'remove'}:{snapshot.task_id}"}
            start_label = "▶️ Продолжить" if runtime_state in {"blocked", "in_progress"} else "▶️ Начать"
            keyboard = [[
                {"text": start_label, "callback_data": f"work:start:{snapshot.task_id}"},
                {"text": "📝 Обновить", "callback_data": f"run:progress:{snapshot.task_id}"},
            ], [
                {"text": "✅ Завершить", "callback_data": f"run:finish:{snapshot.task_id}"},
                {"text": "⋯ Ещё", "callback_data": f"view:more:{snapshot.task_id}"},
            ]]
        if expanded and bitrix_status != "5":
            keyboard.extend([
                [{"text": "➡️ Следующий шаг", "callback_data": f"run:next:{snapshot.task_id}"}, {"text": "🚧 Сообщить о блокере", "callback_data": f"run:block:{snapshot.task_id}"}],
                [{"text": "📅 Изменить срок", "callback_data": f"live:deadline:{snapshot.task_id}"}, focus_button],
                [{"text": "✏️ Изменить задачу", "callback_data": f"live:menu:{snapshot.task_id}"}, {"text": "🕘 История", "callback_data": f"run:history:{snapshot.task_id}"}],
            ])
            managed = self.storage.managed_task(snapshot.task_id)
            if managed and managed.responsible_tg_id == user.tg_id and managed.creator_tg_id != user.tg_id:
                keyboard.append([{"text": "❓ Вопрос постановщику", "callback_data": f"ctl:ask:{snapshot.task_id}"}])
            keyboard.append([{"text": "← К задаче", "callback_data": f"view:open:{snapshot.task_id}"}])
        self._send_task_card(chat_id, user, snapshot.task_id, text, keyboard, refresh=refresh)

    @staticmethod
    def _looks_like_task_update(text: str) -> bool:
        value = text.lower()
        markers = ("сделал", "сделала", "готово", "заверш", "жду", "ожида", "блок", "не могу", "не получается", "не успева", "проблем", "созвони", "отправил", "отправила", "получил", "получила", "результат", "отчёт", "отчет", "следующ", "дальше")
        return any(marker in value for marker in markers)

    def _runtime_task_data(self, user: User, snapshot: TaskSnapshot) -> dict[str, str]:
        runtime = self.storage.task_runtime(snapshot.task_id)
        project = self.storage.task_project(user.tg_id, snapshot.task_id)
        return {
            "id": snapshot.task_id,
            "title": snapshot.title,
            "deadline": snapshot.deadline or "без срока",
            "project": project.title if project else "не указан",
            "state": self._runtime_state_label(runtime.state if runtime else "planned"),
            "next_step": runtime.next_step if runtime and runtime.next_step else "не указан",
            "last_progress": runtime.last_progress if runtime and runtime.last_progress else "нет",
            "blocker": runtime.blocker if runtime and runtime.blocker else "нет",
        }

    def _request_runtime_input(self, chat_id: int, user: User, snapshot: TaskSnapshot, kind: str) -> None:
        prompts = {
            "progress": "Что изменилось по задаче? Можно голосом: что сделано, что дальше, есть ли риск по сроку.",
            "block": "Что блокирует задачу и что нужно, чтобы продолжить? Можно голосом или текстом.",
            "next": "Какой следующий конкретный шаг? Например: «созвониться с клиентом и согласовать сумму».",
            "finish": "Какой получен результат? Напишите или надиктуйте его — затем бот покажет подтверждение завершения.",
        }
        self.storage.set_mode(user.tg_id, f"runtime_{kind}", snapshot.task_id)
        card = self.storage.task_card(user.tg_id, snapshot.task_id)
        message = self.tg.send(
            chat_id,
            prompts[kind] + "\n\nЧтобы отменить, отправьте «Отмена».",
            force_reply=True,
            input_placeholder="Голосом или текстом…",
            reply_to_message_id=card.message_id if card else None,
        )
        message_id = message.get("message_id") if isinstance(message, dict) else None
        if isinstance(message_id, int):
            self.storage.bind_task_message(user.tg_id, snapshot.task_id, chat_id, message_id)

    def _offer_finish(self, chat_id: int, user: User, snapshot: TaskSnapshot, result: str) -> None:
        payload = json.dumps({"result": self._short(result, 1800)}, ensure_ascii=False)
        action = self.storage.create_pending_action(user.tg_id, "complete_with_result", snapshot.task_id, payload)
        self.tg.send(
            chat_id,
            f"Завершить «{snapshot.title}»?\n\n📝 Результат: {self._short(result, 700)}",
            keyboard=[[{"text": "✅ Сохранить и завершить", "callback_data": f"act:confirm:{action.id}"}, {"text": "Отмена", "callback_data": f"act:cancel:{action.id}"}]],
            reply_keyboard=MAIN_MENU,
        )

    def _apply_runtime_update(self, chat_id: int, user: User, snapshot: TaskSnapshot, text: str, *, requested_kind: str | None = None) -> bool:
        try:
            intent = self.ai.understand_task_update(
                text,
                task=self._runtime_task_data(user, snapshot),
                now=datetime.now(MOSCOW),
                context=self._conversation_context(user),
            )
        except OpenRouterError:
            intent = None
        kind = requested_kind or (intent.kind if intent else "unknown")
        if requested_kind is None and intent and intent.kind == "reschedule" and intent.deadline:
            self._offer_update(chat_id, user, snapshot.task_id, {"DEADLINE": intent.deadline}, f"Новый срок: {self._parse_iso(intent.deadline):%d.%m %H:%M}")
            return True
        if requested_kind is None and intent and intent.kind == "question":
            managed = self.storage.managed_task(snapshot.task_id)
            if managed and managed.responsible_tg_id == user.tg_id and managed.creator_tg_id != user.tg_id:
                self.storage.record_event(snapshot.task_id, user.tg_id, "question", self._short(text))
                self._creator_notice(managed, f"❓ Вопрос от {user.display_name} по задаче «{managed.title}»:\n{self._short(text, 700)}")
                self.tg.send(chat_id, "Вопрос отправлен постановщику.", reply_keyboard=MAIN_MENU)
                return True
        if kind == "finish" or (intent and intent.kind == "finish"):
            self._offer_finish(chat_id, user, snapshot, intent.progress or text if intent else text)
            return True
        if kind not in {"progress", "block", "next"} and (not intent or intent.kind == "unknown"):
            return False
        managed = self.storage.managed_task(snapshot.task_id)
        if kind == "block" or (intent and intent.kind == "blocker"):
            blocker = (intent.blocker if intent else None) or text
            next_step = intent.next_step if intent else None
            self.storage.update_task_runtime(snapshot.task_id, responsible_tg_id=user.tg_id, state="blocked", blocker=blocker, next_step=next_step)
            self.storage.record_event(snapshot.task_id, user.tg_id, "blocked", self._short(blocker, 1000))
            self.tg.send(chat_id, "🚧 Блокер сохранён. Карточка задачи обновлена.", reply_keyboard=MAIN_MENU)
            if managed and managed.creator_tg_id != user.tg_id:
                self._creator_notice(managed, f"🚧 {user.display_name} заблокировал задачу «{managed.title}»:\n{self._short(blocker, 700)}")
        elif kind == "next" or (intent and intent.kind == "next_step"):
            next_step = (intent.next_step if intent else None) or text
            self.storage.update_task_runtime(snapshot.task_id, responsible_tg_id=user.tg_id, state="in_progress", next_step=next_step, clear_blocker=True)
            self.storage.record_event(snapshot.task_id, user.tg_id, "next_step", self._short(next_step, 1000))
            self.tg.send(chat_id, "➡️ Следующий шаг сохранён.", reply_keyboard=MAIN_MENU)
        else:
            progress = (intent.progress if intent else None) or text
            self.storage.update_task_runtime(
                snapshot.task_id,
                responsible_tg_id=user.tg_id,
                state="in_progress",
                last_progress=progress,
                next_step=intent.next_step if intent else None,
                clear_blocker=True,
            )
            self.storage.record_event(snapshot.task_id, user.tg_id, "progress", self._short(progress, 1000))
            self.tg.send(chat_id, "📝 Обновление сохранено. Карточка задачи обновлена.", reply_keyboard=MAIN_MENU)
            if managed and managed.creator_tg_id != user.tg_id:
                self._creator_notice(managed, f"📝 Обновление от {user.display_name} по задаче «{managed.title}»:\n{self._short(progress, 700)}")
        if intent and intent.deadline:
            self._offer_update(chat_id, user, snapshot.task_id, {"DEADLINE": intent.deadline}, f"ИИ услышал риск по сроку. Перенести на: {self._parse_iso(intent.deadline):%d.%m %H:%M}")
        self._task_detail(chat_id, user, snapshot, refresh=True)
        return True

    def _today(self, chat_id: int, user: User) -> None:
        try:
            tasks = self.bitrix.list_my_open_tasks(user.bitrix_id)
        except BitrixError:
            self.tg.send(chat_id, "Не удалось обновить ваш список задач. Повторите немного позже.", reply_keyboard=MAIN_MENU)
            return
        snapshots = self.storage.sync_task_snapshots(user.tg_id, tasks)
        if not snapshots:
            self.tg.send(chat_id, "🎯 Сейчас задач нет.\n\nНапишите или надиктуйте первую мысль — я пойму, сделать из неё задачу или сохранить во входящие.", reply_keyboard=MAIN_MENU)
            return
        overdue = sum(1 for snapshot in snapshots if (deadline := self._parse_iso(snapshot.deadline)) and deadline < datetime.now(MOSCOW))
        focus_ids = self.storage.focus_task_ids(user.tg_id, datetime.now(MOSCOW).date().isoformat())
        focus = [snapshot for snapshot in snapshots if snapshot.task_id in focus_ids]
        overdue_tasks = [snapshot for snapshot in snapshots if (deadline := self._parse_iso(snapshot.deadline)) and deadline < datetime.now(MOSCOW)]
        current = (focus or overdue_tasks or [snapshot for snapshot in snapshots if snapshot.priority == "2"] or snapshots)[0]
        deadline = self._parse_iso(current.deadline)
        due = "без срока" if not deadline else (f"просрочена с {deadline:%d.%m %H:%M}" if deadline < datetime.now(MOSCOW) else f"сегодня до {deadline:%H:%M}" if deadline.date() == datetime.now(MOSCOW).date() else f"до {deadline:%d.%m %H:%M}")
        runtime = self.storage.task_runtime(current.task_id)
        lines = ["🎯 Сейчас", f"\n{current.title}", f"📅 {due}"]
        if runtime and runtime.next_step:
            lines.append(f"➡️ {self._short(runtime.next_step, 180)}")
        if focus:
            lines.append(f"\nФокус дня: {len(focus)}/3")
        else:
            lines.append("\nФокус пока не выбран — откройте задачу и добавьте главные до трёх.")
        if overdue:
            lines.append(f"⚠️ Просрочено: {overdue}")
        keyboard = [
            [{"text": "▶️ Продолжить", "callback_data": f"work:start:{current.task_id}"}, {"text": "📝 Обновить", "callback_data": f"run:progress:{current.task_id}"}],
            [{"text": "🎯 Открыть задачу", "callback_data": f"view:open:{current.task_id}"}, {"text": "📋 Все задачи", "callback_data": "list:all:0"}],
            [{"text": "✨ Спланировать день", "callback_data": "hub:focus:0"}],
        ]
        self.tg.send(chat_id, "\n".join(lines), keyboard=keyboard, reply_keyboard=MAIN_MENU)

    def _task_list(self, chat_id: int, user: User, kind: str = "all", page: int = 0) -> None:
        try:
            snapshots = self.storage.sync_task_snapshots(user.tg_id, self.bitrix.list_my_open_tasks(user.bitrix_id))
        except BitrixError:
            self.tg.send(chat_id, "Не удалось обновить задачи. Повторите чуть позже.", reply_keyboard=MAIN_MENU)
            return
        now = datetime.now(MOSCOW)
        filters = {
            "all": ("Все открытые", lambda task: True),
            "today": ("На сегодня", lambda task: (deadline := self._parse_iso(task.deadline)) is not None and deadline.date() == now.date()),
            "overdue": ("Просроченные", lambda task: (deadline := self._parse_iso(task.deadline)) is not None and deadline < now),
            "nodate": ("Без срока", lambda task: not task.deadline),
        }
        title, predicate = filters.get(kind, filters["all"])
        rows = [task for task in snapshots if predicate(task)]
        size = 8
        page = max(0, page)
        shown = rows[page * size:(page + 1) * size]
        lines = [f"📋 {title}: {len(rows)}"]
        if not shown:
            lines.append("Здесь пока пусто.")
        keyboard = [[{"text": self._button_title(page * size + index, task.title), "callback_data": f"view:open:{task.task_id}"}] for index, task in enumerate(shown, 1)]
        keyboard.append([{"text": "Сегодня", "callback_data": "list:today:0"}, {"text": "Просрочены", "callback_data": "list:overdue:0"}])
        keyboard.append([{"text": "Без срока", "callback_data": "list:nodate:0"}, {"text": "Все", "callback_data": "list:all:0"}])
        navigation = []
        if page:
            navigation.append({"text": "←", "callback_data": f"list:{kind}:{page - 1}"})
        if (page + 1) * size < len(rows):
            navigation.append({"text": "Дальше →", "callback_data": f"list:{kind}:{page + 1}"})
        if navigation:
            keyboard.append(navigation)
        keyboard.append([{"text": "🔎 Найти по названию", "callback_data": "list:search:0"}])
        self.tg.send(chat_id, "\n".join(lines), keyboard=keyboard, reply_keyboard=MAIN_MENU)

    def _plan_day(self, chat_id: int, user: User) -> None:
        try:
            tasks = self.bitrix.list_my_open_tasks(user.bitrix_id)
            plan = self.ai.plan_day(tasks)
        except (BitrixError, OpenRouterError):
            self.tg.send(chat_id, "Не удалось собрать умный план. Откройте «📅 Сегодня» и выберите три главные задачи вручную.")
            return
        self.tg.send(chat_id, "✨ План дня\n\n" + plan, reply_keyboard=MAIN_MENU)

    @staticmethod
    def _short(text: str, limit: int = 500) -> str:
        return text if len(text) <= limit else text[: limit - 1] + "…"

    def _creator_notice(self, managed: ManagedTask, text: str) -> None:
        if managed.creator_tg_id == managed.responsible_tg_id:
            return
        try:
            self.tg.send(managed.creator_tg_id, text, reply_keyboard=MAIN_MENU)
        except TelegramError:
            LOG.warning("Creator notification delivery failed for Telegram user %s", managed.creator_tg_id)

    def _weekly_report(self, chat_id: int, user: User) -> None:
        since = (datetime.now(MOSCOW) - timedelta(days=7)).astimezone(timezone.utc).isoformat()
        summary = self.storage.weekly_summary(user.tg_id, since)
        self.tg.send(
            chat_id,
            "📊 За последние 7 дней (задачи, созданные через TaskBot)\n"
            f"Создано: {summary.get('created', 0)}\n"
            f"Принято в работу: {summary.get('accepted', 0)}\n"
            f"Отчётов добавлено: {summary.get('result', 0)}\n"
            f"Завершено: {summary.get('completed', 0)}\n"
            f"Сейчас в работе: {summary.get('open', 0)}",
            reply_keyboard=MAIN_MENU,
        )

    def _assignment_picker(self, chat_id: int, actor: User) -> None:
        if actor.role not in {"owner", "partner"}:
            self.tg.send(chat_id, "Сейчас вы можете ставить задачи только себе.", reply_keyboard=MAIN_MENU)
            return
        targets = [user for user in self.users.users() if user.tg_id != actor.tg_id]
        if not targets:
            self.tg.send(chat_id, "Партнёр или сотрудник ещё не привязаны к Bitrix24. Как только добавим профиль, здесь появится выбор исполнителя.", reply_keyboard=MAIN_MENU)
            return
        keyboard = [[{"text": target.display_name, "callback_data": f"assign:{target.alias}"}] for target in targets]
        self.tg.send(chat_id, "Кому поставить задачу?", keyboard=keyboard, reply_keyboard=MAIN_MENU)

    def _inbox(self, chat_id: int, user: User) -> None:
        ideas = self.storage.inbox_items(user.tg_id)
        tasks = self.storage.incoming_tasks(user.tg_id)
        keyboard = []
        if ideas:
            keyboard.append([{"text": f"💭 Мои захваты ({len(ideas)})", "callback_data": "inbox:mine:0"}])
        if tasks:
            keyboard.append([{"text": f"👥 Поручения от других ({len(tasks)})", "callback_data": "inbox:team:0"}])
        if not keyboard:
            self.tg.send(chat_id, "📥 Входящие пусты. Мысли и неоформленные дела можно писать прямо в чат — бот сохранит их сюда, а не будет создавать лишние задачи.", reply_keyboard=MAIN_MENU)
            return
        self.tg.send(chat_id, f"📥 Входящие\n💭 Мои захваты: {len(ideas)} · 👥 Поручения: {len(tasks)}", keyboard=keyboard, reply_keyboard=MAIN_MENU)

    def _capture(self, chat_id: int, user: User, text: str) -> None:
        if not text.strip():
            self.tg.send(chat_id, "Напишите саму мысль после «идея:» или «входящие:».", reply_keyboard=MAIN_MENU)
            return
        item = self.storage.capture_inbox(user.tg_id, text)
        self.tg.send(
            chat_id,
            "💭 Сохранил во входящие. Это пока не задача и не создаёт обязательство. Разберёте, когда будет время.",
            keyboard=[[{"text": "Разобрать сейчас", "callback_data": f"capture:convert:{item.id}"}, {"text": "Оставить", "callback_data": f"capture:keep:{item.id}"}]],
            reply_keyboard=MAIN_MENU,
        )

    def _show_captures(self, chat_id: int, user: User) -> None:
        items = self.storage.inbox_items(user.tg_id)
        if not items:
            self.tg.send(chat_id, "💭 Во входящих мыслей нет.", reply_keyboard=MAIN_MENU)
            return
        keyboard = [[{"text": self._button_title(index, item.text), "callback_data": f"capture:open:{item.id}"}] for index, item in enumerate(items[:10], 1)]
        self.tg.send(chat_id, f"💭 Мои захваты: {len(items)}\nВыберите мысль, чтобы превратить её в задачу, оставить на потом или удалить.", keyboard=keyboard)

    def _team(self, chat_id: int, user: User) -> None:
        tasks = self.storage.delegated_tasks(user.tg_id)
        if not tasks:
            self.tg.send(chat_id, "👥 Нет активных задач, которые вы поставили другим через TaskBot.", reply_keyboard=MAIN_MENU)
            return
        keyboard = [[{"text": self._button_title(index, task.title), "callback_data": f"team:open:{task.task_id}"}] for index, task in enumerate(tasks[:10], 1)]
        self.tg.send(chat_id, f"👥 В работе у команды: {len(tasks)}\nВыберите задачу, чтобы посмотреть статус или напомнить исполнителю.", keyboard=keyboard, reply_keyboard=MAIN_MENU)

    def _projects(self, chat_id: int, user: User) -> None:
        projects = self.storage.projects(user.tg_id)
        if not projects:
            self.tg.send(chat_id, "🗂 Проектов пока нет. Создайте только устойчивые направления: например, «Тендеры», «Продажи», «Личное» — не отдельные разовые дела.", keyboard=[[{"text": "➕ Новый проект", "callback_data": "project:new:0"}]], reply_keyboard=MAIN_MENU)
            return
        lines = ["🗂 Активные проекты:"] + [f"• {project.title}" for project in projects[:12]]
        keyboard = [[{"text": project.title[:45], "callback_data": f"project:open:{project.id}"}] for project in projects[:12]]
        keyboard.append([{"text": "➕ Новый проект", "callback_data": "project:new:0"}])
        self.tg.send(chat_id, "\n".join(lines), keyboard=keyboard, reply_keyboard=MAIN_MENU)

    def _project_detail(self, chat_id: int, user: User, project_id: str) -> None:
        project = self.storage.project(user.tg_id, project_id)
        if not project:
            self.tg.send(chat_id, "Проект уже недоступен.", reply_keyboard=MAIN_MENU)
            return
        goals = self.storage.goals(user.tg_id, project.id)
        lines = [f"🗂 {project.title}", "Цели:"]
        lines.extend(f"• {goal.title}" for goal in goals) if goals else lines.append("• пока нет")
        self.tg.send(chat_id, "\n".join(lines), keyboard=[[{"text": "🎯 Новая цель", "callback_data": f"goal:new:{project.id}"}]], reply_keyboard=MAIN_MENU)

    def _more(self, chat_id: int) -> None:
        self.tg.send(
            chat_id,
            "Что открыть?",
            keyboard=[
                [{"text": "📋 Все задачи", "callback_data": "hub:tasks:0"}, {"text": "👥 Команда", "callback_data": "hub:team:0"}],
                [{"text": "🗂 Проекты", "callback_data": "hub:projects:0"}, {"text": "📊 Итоги недели", "callback_data": "hub:week:0"}],
                [{"text": "⚙️ Настройки", "callback_data": "hub:settings:0"}],
            ],
        )

    def _coach(self, chat_id: int, user: User, question: str) -> None:
        try:
            answer = self.ai.coach(question, self.bitrix.list_my_open_tasks(user.bitrix_id))
        except (BitrixError, OpenRouterError):
            self.tg.send(chat_id, "AI-помощник временно недоступен. Попробуйте чуть позже.", reply_keyboard=MAIN_MENU)
            return
        self.tg.send(chat_id, "🤖 " + answer, reply_keyboard=MAIN_MENU)

    def _run_daily_routines(self) -> None:
        now = datetime.now(MOSCOW)
        date = now.date().isoformat()
        if now.hour == self.config.morning_hour:
            for user in self.users.users():
                if self.storage.claim_routine("morning", date, user.tg_id):
                    self.tg.send(user.tg_id, "Доброе утро. Выберите до трёх главных результатов дня — напишите или надиктуйте первую задачу.")
                    self._today(user.tg_id, user)
        if now.weekday() == 0 and now.hour == self.config.morning_hour:
            for user in self.users.users():
                if self.storage.claim_routine("weekly", date, user.tg_id):
                    self._weekly_report(user.tg_id, user)
        if now.hour == self.config.evening_hour:
            for user in self.users.users():
                if self.storage.claim_routine("evening", date, user.tg_id):
                    focus_ids = self.storage.focus_task_ids(user.tg_id, date)
                    titles = [self.storage.get_snapshot(user.tg_id, task_id).title for task_id in focus_ids if self.storage.get_snapshot(user.tg_id, task_id)]
                    text = "Вечерний обзор."
                    if titles:
                        text += "\nФокус дня:\n" + "\n".join(f"• {title}" for title in titles)
                    text += "\n\nЗавершите сделанное, а важное перенесите прямо в карточке. Не переносите задачи автоматически — сначала решите, нужны ли они завтра."
                    self.tg.send(user.tg_id, text, keyboard=[[{"text": "🎯 Открыть сегодня", "callback_data": "menu:today"}]], reply_keyboard=MAIN_MENU)

    def _notifications_allowed(self, now: datetime) -> bool:
        return self.config.notify_from_hour <= now.hour < self.config.notify_until_hour

    @staticmethod
    def _parse_iso(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=MOSCOW)

    def _reminder_payload(self, snapshot: TaskSnapshot, now: datetime) -> tuple[str, str, str] | None:
        deadline = self._parse_iso(snapshot.deadline)
        if not deadline:
            return None
        snooze = self._parse_iso(self.storage.get_snooze(snapshot.tg_id, snapshot.task_id))
        if snooze and snooze > now:
            return None
        if snooze and snooze <= now:
            self.storage.clear_snooze(snapshot.tg_id, snapshot.task_id)
        delta = deadline - now
        if delta.total_seconds() <= 0:
            return "overdue", now.date().isoformat(), f"⚠️ Просрочена задача\n{snapshot.title}\nСрок был: {deadline:%d.%m %H:%M}"
        if delta <= timedelta(hours=2):
            return "two_hours", deadline.isoformat(), f"⏰ Срок менее чем через 2 часа\n{snapshot.title}\nДо: {deadline:%H:%M}"
        if delta <= timedelta(days=1):
            return "day", deadline.isoformat(), f"📌 Срок задачи в течение суток\n{snapshot.title}\nДо: {deadline:%d.%m %H:%M}"
        return None

    def _reminder_keyboard(self, task_id: str) -> list[list[dict[str, str]]]:
        return [
            [{"text": "✅ Готово", "callback_data": f"rem:done:{task_id}"}, {"text": "⏰ На 1 час", "callback_data": f"rem:snooze:{task_id}"}],
            [{"text": "📅 На завтра", "callback_data": f"rem:tomorrow:{task_id}"}, {"text": "📝 Результат", "callback_data": f"rem:result:{task_id}"}],
        ]

    @staticmethod
    def _assignment_keyboard(task_id: int) -> list[list[dict[str, str]]]:
        return [[
            {"text": "▶️ Начать", "callback_data": f"ctl:accept:{task_id}"},
            {"text": "❓ Уточнить", "callback_data": f"ctl:ask:{task_id}"},
        ]]

    def _run_reminders(self) -> None:
        now = datetime.now(MOSCOW)
        self.storage.heartbeat(now.isoformat())
        if time.monotonic() < self._next_reminder_sync or not self._notifications_allowed(now):
            return
        self._next_reminder_sync = time.monotonic() + self.config.reminder_sync_seconds
        for user in self.users.users():
            try:
                snapshots = self.storage.sync_task_snapshots(user.tg_id, self.bitrix.list_my_open_tasks(user.bitrix_id))
            except BitrixError:
                LOG.warning("Bitrix synchronization failed for Telegram user %s", user.tg_id)
                continue
            due_reminders: list[tuple[TaskSnapshot, str, str, str, ManagedTask | None]] = []
            for snapshot in snapshots:
                managed = self.storage.managed_task(snapshot.task_id)
                runtime = self.storage.task_runtime(snapshot.task_id)
                # A delegation is not considered healthy merely because a deadline exists.
                # Ask for an explicit acceptance, then for a first status update, with one nudge per day.
                if managed and managed.creator_tg_id != snapshot.tg_id:
                    created = self._parse_iso(managed.created_at)
                    daily_bucket = now.date().isoformat()
                    if not managed.accepted_at and created and now - created >= timedelta(hours=2):
                        if not self.storage.reminder_was_sent(snapshot.tg_id, snapshot.task_id, "acceptance", daily_bucket):
                            try:
                                self.tg.send(snapshot.tg_id, f"📥 Поручение ждёт принятия\n{snapshot.title}\n\nЕсли берёте — нажмите «Принять». Если не хватает данных — задайте вопрос.", keyboard=self._assignment_keyboard(int(snapshot.task_id)), reply_keyboard=MAIN_MENU)
                            except TelegramError:
                                LOG.warning("Acceptance reminder delivery failed for Telegram user %s", snapshot.tg_id)
                            else:
                                self.storage.mark_reminder_sent(snapshot.tg_id, snapshot.task_id, "acceptance", daily_bucket)
                    elif managed.accepted_at and runtime and runtime.state == "in_progress" and not runtime.last_progress:
                        started = self._parse_iso(runtime.started_at)
                        if started and now - started >= timedelta(hours=6) and not self.storage.reminder_was_sent(snapshot.tg_id, snapshot.task_id, "progress_check", daily_bucket):
                            try:
                                self.tg.send(snapshot.tg_id, f"📝 Как продвигается задача?\n{snapshot.title}\n\nОдним голосовым или сообщением скажите, что сделано и что дальше.", keyboard=[[{"text": "📝 Дать обновление", "callback_data": f"run:progress:{snapshot.task_id}"}, {"text": "🚧 Есть блокер", "callback_data": f"run:block:{snapshot.task_id}"}]], reply_keyboard=MAIN_MENU)
                            except TelegramError:
                                LOG.warning("Progress reminder delivery failed for Telegram user %s", snapshot.tg_id)
                            else:
                                self.storage.mark_reminder_sent(snapshot.tg_id, snapshot.task_id, "progress_check", daily_bucket)
                payload = self._reminder_payload(snapshot, now)
                if not payload:
                    continue
                kind, bucket, text = payload
                if self.storage.reminder_was_sent(snapshot.tg_id, snapshot.task_id, kind, bucket):
                    continue
                due_reminders.append((snapshot, kind, bucket, text, managed))

            if not due_reminders:
                continue
            if len(due_reminders) == 1:
                snapshot, kind, bucket, text, managed = due_reminders[0]
                try:
                    self.tg.send(snapshot.tg_id, text, keyboard=self._reminder_keyboard(snapshot.task_id))
                except TelegramError:
                    LOG.warning("Reminder delivery failed for Telegram user %s", snapshot.tg_id)
                    continue
                self.storage.mark_reminder_sent(snapshot.tg_id, snapshot.task_id, kind, bucket)
            else:
                labels = {"overdue": "просрочена", "two_hours": "срок менее 2 часов", "day": "срок в течение суток"}
                shown = due_reminders[:3]
                lines = ["📌 Задачи требуют внимания", ""]
                lines.extend(f"• {item[0].title} — {labels.get(item[1], 'проверьте срок')}" for item in shown)
                if len(due_reminders) > len(shown):
                    lines.append(f"• и ещё {len(due_reminders) - len(shown)}")
                lines.extend(["", "Откройте «🎯 Сейчас», выберите главное и обновите статус одной кнопкой."])
                try:
                    self.tg.send(user.tg_id, "\n".join(lines), keyboard=[[{"text": "🎯 Открыть сейчас", "callback_data": "menu:today"}]], reply_keyboard=MAIN_MENU)
                except TelegramError:
                    LOG.warning("Reminder digest delivery failed for Telegram user %s", user.tg_id)
                    continue
                for snapshot, kind, bucket, _text, _managed in due_reminders:
                    self.storage.mark_reminder_sent(snapshot.tg_id, snapshot.task_id, kind, bucket)
            for snapshot, kind, _bucket, _text, managed in due_reminders:
                if kind == "overdue" and snapshot.priority == "2" and managed and managed.creator_tg_id != snapshot.tg_id:
                    escalation_bucket = now.date().isoformat()
                    if not self.storage.reminder_was_sent(managed.creator_tg_id, snapshot.task_id, "escalation", escalation_bucket):
                        self._creator_notice(managed, f"⚠️ Высокоприоритетная задача просрочена\nИсполнитель: {user.display_name}\n{snapshot.title}")
                        self.storage.mark_reminder_sent(managed.creator_tg_id, snapshot.task_id, "escalation", escalation_bucket)

    def _run_backup(self) -> None:
        today = datetime.now(MOSCOW).date().isoformat()
        if self.storage.get_state("backup_date") == today:
            return
        path = Path(__file__).parent / "backups" / f"taskbot-{today}.sqlite3"
        try:
            self.storage.backup(path)
        except sqlite3.Error:
            LOG.exception("TaskBot database backup failed")
            return
        self.storage.set_state("backup_date", today)

    def _status(self, chat_id: int, user: User) -> None:
        heartbeat = self.storage.get_state("heartbeat") or "нет данных"
        backup = self.storage.get_state("backup_date") or "ещё не выполнен"
        self.tg.send(chat_id, f"🛡 TaskBot работает\nОткрытых задач в локальной синхронизации: {self.storage.snapshot_count(user.tg_id)}\nПоследний heartbeat: {heartbeat[:16]}\nПоследний бэкап: {backup}\nНапоминания: каждые {self.config.reminder_sync_seconds // 60} мин., в {self.config.notify_from_hour}:00–{self.config.notify_until_hour}:00.", reply_keyboard=MAIN_MENU)

    def _handle_message(self, message: dict) -> None:
        chat_id = int(message["chat"]["id"])
        sender = int(message["from"]["id"])
        text = (message.get("text") or "").strip()
        if text in {"/start", "/help"}:
            user = self._user(sender)
            if user:
                self._show_menu(chat_id, "TaskBot — ваше рабочее место для задач. Напишите или надиктуйте поручение, либо откройте «🎯 Сегодня».")
                self._today(chat_id, user)
            else:
                self._require_user(chat_id, sender)
            return
        user = self._require_user(chat_id, sender)
        if not user:
            return
        reply = message.get("reply_to_message") or {}
        reply_message_id = reply.get("message_id")
        reply_task_id = self.storage.task_for_message(sender, chat_id, int(reply_message_id)) if isinstance(reply_message_id, int) else None
        if reply_task_id:
            snapshot = self.storage.get_snapshot(sender, reply_task_id)
            if not snapshot:
                self.tg.send(chat_id, "Эта карточка уже устарела. Откройте задачу заново через «🎯 Сейчас».", reply_keyboard=MAIN_MENU)
                return
            if text.casefold() in {"отмена", "/cancel"}:
                self.storage.pop_mode(sender)
                self.tg.send(chat_id, "Отменено. Задача не изменилась.", reply_keyboard=MAIN_MENU)
                return
            mode = self.storage.pop_mode(sender)
            requested_kind = mode[0].removeprefix("runtime_") if mode and mode[0] in {"runtime_progress", "runtime_block", "runtime_next", "runtime_finish"} and mode[1] == snapshot.task_id else None
            if message.get("voice"):
                self._voice_to_runtime(chat_id, user, message["voice"], snapshot, requested_kind)
                return
            if text:
                if not self._apply_runtime_update(chat_id, user, snapshot, text, requested_kind=requested_kind):
                    self.tg.send(chat_id, "Это ответ по задаче «%s». Напишите, что сделано, что мешает, следующий шаг или новый срок." % snapshot.title, reply_keyboard=MAIN_MENU)
                return
        if message.get("voice"):
            mode = self.storage.pop_mode(sender)
            if mode and mode[0] in {"runtime_progress", "runtime_block", "runtime_next", "runtime_finish"} and mode[1]:
                snapshot = self.storage.get_snapshot(sender, mode[1])
                if snapshot:
                    self._voice_to_runtime(chat_id, user, message["voice"], snapshot, mode[0].removeprefix("runtime_"))
                else:
                    self.tg.send(chat_id, "Эта задача уже неактуальна. Откройте её снова через «🎯 Сегодня».", reply_keyboard=MAIN_MENU)
                return
            target = self.users.by_alias(mode[1]) if mode and mode[0] == "assign" and mode[1] else None
            self._voice_to_draft(chat_id, user, message["voice"], forced_responsible=target)
        elif text in {"/today", "📅 Сегодня", "🎯 Мой день", "🎯 Сегодня", "🎯 Сейчас"}:
            self._today(chat_id, user)
        elif text in {"/plan", "✨ План дня", "✨ Фокус"}:
            self._plan_day(chat_id, user)
        elif text in {"/week", "📊 Неделя", "📊 Итоги"}:
            self._weekly_report(chat_id, user)
        elif text in {"➕ Задача", "🎙 Голосовая", "➕ Добавить"}:
            self.tg.send(chat_id, "Что нужно сделать? Напишите или надиктуйте одной фразой — срок, исполнитель и важность можно сказать сразу или уточнить потом.", force_reply=True, input_placeholder="Например: согласовать смету завтра до 12")
        elif text in {"👥 Поставить задачу", "👥 Команда"}:
            self._team(chat_id, user)
        elif text == "📥 Входящие":
            self._inbox(chat_id, user)
        elif text == "☰ Ещё":
            self._more(chat_id)
        elif text == "🤖 AI-помощник":
            self.storage.set_mode(sender, "coach")
            self.tg.send(chat_id, "Спросите, например: «Что у меня сейчас главное?» или «Что лучше перенести?». Этот режим ничего не меняет в Bitrix24.", reply_keyboard=MAIN_MENU)
        elif text in {"🛡 Статус", "⚙️ Настройки"}:
            self._status(chat_id, user)
        elif text == "❓ Помощь":
            self._show_menu(chat_id, "Напишите или надиктуйте задачу — это основной способ работы. «🎯 Сегодня» показывает главное, «📥 Входящие» — поручения от других, а «☰ Ещё» открывает фокус, команду и итоги.")
        elif text.lower().startswith("запомни"):
            memory = text[len("запомни"):].lstrip(" :—-").strip()
            if not memory:
                self.tg.send(chat_id, "Напишите, что запомнить. Например: «запомни: Дима — мой партнёр» или «запомни: задачи без срока ставь на завтра в 10:00».", reply_keyboard=MAIN_MENU)
            else:
                self.storage.remember_fact(sender, memory)
                self.tg.send(chat_id, f"Запомнил: {memory}", reply_keyboard=MAIN_MENU)
        elif text.lower().startswith("забудь"):
            query = text[len("забудь"):].lstrip(" :—-").strip()
            removed = self.storage.forget_memories(sender, query)
            self.tg.send(chat_id, "Удалил это из личной памяти." if removed else "Не нашёл такого сохранённого предпочтения.", reply_keyboard=MAIN_MENU)
        elif text.startswith("/task"):
            self._draft_from_text(chat_id, user, text.removeprefix("/task").strip())
        elif text.startswith("/to "):
            parts = text.split(maxsplit=2)
            target = self.users.by_alias(parts[1] if len(parts) > 1 else "")
            if user.role not in {"owner", "partner"}:
                self.tg.send(chat_id, "Вы можете создавать задачи только себе.")
            elif not target or len(parts) < 3:
                self.tg.send(chat_id, "Формат: /to @алиас Текст задачи")
            else:
                self._draft_from_text(chat_id, user, parts[2], forced_responsible=target)
        elif text:
            if text.casefold() in {"отмена", "/cancel"}:
                cancelled = self.storage.pop_mode(sender)
                if cancelled:
                    self.tg.send(chat_id, "Отменено. Задача не изменилась.", reply_keyboard=MAIN_MENU)
                    return
                # Inline buttons are convenient, but a spoken or typed
                # "Отмена" must work as well when a draft card is open.
                # This is especially important on phones where an older
                # keyboard can remain visible below a newer card.
                state = self.storage.conversation_state(sender)
                draft = self.storage.get_pending(state.last_draft_id) if state.last_draft_id else None
                if draft:
                    self.storage.set_status(draft.id, "cancelled")
                    self.storage.set_conversation_state(sender, last_draft_id="")
                    self.tg.send(chat_id, f"Черновик «{draft.title}» отменён.", reply_keyboard=MAIN_MENU)
                    return
                self.tg.send(chat_id, "Нет активного действия для отмены. Для старой карточки используйте её кнопку «Отмена».", reply_keyboard=MAIN_MENU)
                return
            mode = self.storage.pop_mode(sender)
            if mode and mode[0] in {"runtime_progress", "runtime_block", "runtime_next", "runtime_finish"} and mode[1]:
                snapshot = self.storage.get_snapshot(sender, mode[1])
                if not snapshot:
                    self.tg.send(chat_id, "Эта задача уже неактуальна. Откройте её снова через «🎯 Сегодня».", reply_keyboard=MAIN_MENU)
                else:
                    kind = mode[0].removeprefix("runtime_")
                    self._apply_runtime_update(chat_id, user, snapshot, text, requested_kind=kind)
            elif mode and mode[0] == "task_search":
                self._choose_task(chat_id, self._find_task(user, text), "Нашёл такие задачи:")
            elif mode and mode[0] == "result" and mode[1]:
                snapshot = self.storage.get_snapshot(sender, mode[1])
                if not snapshot:
                    self.tg.send(chat_id, "Эта задача уже неактуальна. Откройте «📅 Сегодня».", reply_keyboard=MAIN_MENU)
                else:
                    try:
                        self.bitrix.add_result(int(snapshot.task_id), text)
                    except BitrixError:
                        self.tg.send(chat_id, "Не удалось сохранить результат в Bitrix24. Попробуйте ещё раз.", reply_keyboard=MAIN_MENU)
                    else:
                        managed = self.storage.managed_task(snapshot.task_id)
                        self.storage.record_event(snapshot.task_id, sender, "result", self._short(text))
                        if managed:
                            self._creator_notice(managed, f"📝 {user.display_name} добавил результат по задаче «{managed.title}»:\n{self._short(text)}")
                        self.tg.send(chat_id, "Результат сохранён. Если задача выполнена, нажмите «Готово».", keyboard=[[{"text": "✅ Готово", "callback_data": f"rem:done:{snapshot.task_id}"}]], reply_keyboard=MAIN_MENU)
            elif mode and mode[0] in {"live_title", "live_description", "live_deadline"} and mode[1]:
                snapshot = self.storage.get_snapshot(sender, mode[1])
                if not snapshot:
                    self.tg.send(chat_id, "Эта задача уже изменилась. Откройте её снова через «🎯 Сегодня».", reply_keyboard=MAIN_MENU)
                elif mode[0] == "live_title":
                    self._offer_update(chat_id, user, snapshot.task_id, {"TITLE": text}, f"Новое название: {self._short(text, 180)}")
                elif mode[0] == "live_description":
                    self._offer_update(chat_id, user, snapshot.task_id, {"DESCRIPTION": text}, f"Новое описание: {self._short(text, 180)}")
                else:
                    try:
                        deadline = self.ai.parse_task(text, aliases=self.users.aliases(), now=datetime.now(MOSCOW)).deadline
                    except OpenRouterError:
                        deadline = None
                    if not deadline:
                        self.tg.send(chat_id, "Не понял срок. Напишите, например: «в пятницу в 15:00».", reply_keyboard=MAIN_MENU)
                    else:
                        parsed = self._parse_iso(deadline)
                        self._offer_update(chat_id, user, snapshot.task_id, {"DEADLINE": deadline}, f"Новый срок: {parsed:%d.%m %H:%M}")
            elif mode and mode[0] == "draft_title" and mode[1]:
                draft = self.storage.update_draft(mode[1], title=text)
                if not draft or draft.creator_tg_id != sender:
                    self.tg.send(chat_id, "Этот черновик уже неактуален.", reply_keyboard=MAIN_MENU)
                else:
                    self._send_draft_card(chat_id, draft)
            elif mode and mode[0] == "clarify" and mode[1]:
                managed = self.storage.managed_task(mode[1])
                if not managed or managed.responsible_tg_id != sender:
                    self.tg.send(chat_id, "Эта задача больше недоступна для вопроса.", reply_keyboard=MAIN_MENU)
                else:
                    self.storage.record_event(managed.task_id, sender, "question", self._short(text))
                    try:
                        self.tg.send(
                            managed.creator_tg_id,
                            f"❓ Вопрос от {user.display_name} по задаче «{managed.title}»:\n{self._short(text)}",
                            keyboard=[[{"text": "💬 Ответить", "callback_data": f"ctl:reply:{managed.task_id}"}]],
                        )
                    except TelegramError:
                        LOG.warning("Question delivery failed for Telegram user %s", managed.creator_tg_id)
                    self.tg.send(chat_id, "Вопрос отправлен постановщику. После ответа уточните задачу в Bitrix24 или поставьте новую карточку в TaskBot.", reply_keyboard=MAIN_MENU)
            elif mode and mode[0] == "reply" and mode[1]:
                managed = self.storage.managed_task(mode[1])
                if not managed or managed.creator_tg_id != sender:
                    self.tg.send(chat_id, "Эта задача больше недоступна для ответа.", reply_keyboard=MAIN_MENU)
                else:
                    self.storage.record_event(managed.task_id, sender, "answer", self._short(text))
                    try:
                        self.tg.send(
                            managed.responsible_tg_id,
                            f"💬 Ответ от постановщика по задаче «{managed.title}»:\n{self._short(text)}",
                            reply_keyboard=MAIN_MENU,
                        )
                    except TelegramError:
                        LOG.warning("Answer delivery failed for Telegram user %s", managed.responsible_tg_id)
                    self.tg.send(chat_id, "Ответ отправлен исполнителю.", reply_keyboard=MAIN_MENU)
            elif mode and mode[0] == "clarify_request" and mode[1]:
                self._route_free_text(chat_id, user, f"{mode[1]}\nУточнение пользователя: {text}")
            elif mode and mode[0] == "new_project":
                project = self.storage.create_project(sender, text)
                self.tg.send(chat_id, f"🗂 Создал проект «{project.title}». Теперь его можно привязывать к задачам через «Изменить» в карточке задачи.", reply_keyboard=MAIN_MENU)
            elif mode and mode[0] == "new_goal" and mode[1]:
                project = self.storage.project(sender, mode[1])
                if not project:
                    self.tg.send(chat_id, "Проект уже недоступен.", reply_keyboard=MAIN_MENU)
                else:
                    goal = self.storage.create_goal(sender, project.id, text)
                    self.tg.send(chat_id, f"🎯 Добавил цель «{goal.title}» в проект «{project.title}».", reply_keyboard=MAIN_MENU)
            elif mode and mode[0] == "coach":
                self._coach(chat_id, user, text)
            elif mode and mode[0] == "assign" and mode[1]:
                target = self.users.by_alias(mode[1])
                self._draft_from_text(chat_id, user, text, forced_responsible=target) if target else self._draft_from_text(chat_id, user, text)
            else:
                self._route_free_text(chat_id, user, text)

    def _handle_callback(self, query: dict) -> None:
        sender = int(query["from"]["id"])
        chat_id = int(query["message"]["chat"]["id"])
        callback_id = query["id"]
        parts = (query.get("data") or "").split(":")
        if len(parts) == 3 and parts[0] == "list":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            if parts[1] == "search":
                self.storage.set_mode(sender, "task_search")
                self.tg.answer_callback(callback_id, "Напишите название")
                self.tg.send(chat_id, "Напишите несколько слов из названия задачи.", force_reply=True, input_placeholder="Например: смета клиенту")
                return
            try:
                page = int(parts[2])
            except ValueError:
                page = 0
            self.tg.answer_callback(callback_id)
            self._task_list(chat_id, user, parts[1], page)
            return
        if len(parts) == 3 and parts[0] == "run":
            user = self._user(sender)
            snapshot = self.storage.get_snapshot(sender, parts[2])
            if not user or not snapshot:
                self.tg.answer_callback(callback_id, "Задача уже изменилась")
                return
            if parts[1] in {"progress", "block", "next", "finish"}:
                if self._task_is_completed(snapshot.task_id):
                    self.storage.update_task_runtime(snapshot.task_id, state="completed")
                    self.tg.answer_callback(callback_id, "Задача уже завершена")
                    self.tg.send(chat_id, "Эта задача уже завершена в Bitrix24. Откройте её заново — доступны только история и удаление.", reply_keyboard=MAIN_MENU)
                    return
                self.tg.answer_callback(callback_id)
                self._request_runtime_input(chat_id, user, snapshot, parts[1])
                return
            if parts[1] == "history":
                events = self.storage.task_events(snapshot.task_id)
                labels = {"created": "создана", "accepted": "взята в работу", "progress": "обновление", "next_step": "следующий шаг", "blocked": "блокер", "result": "результат", "completed": "завершена", "rescheduled": "срок изменён", "updated": "изменена"}
                lines = [f"🕘 История: {snapshot.title}"]
                if not events:
                    lines.append("Пока только исходная задача.")
                for kind, payload, created_at in events:
                    stamp = self._parse_iso(created_at)
                    lines.append(f"• {stamp.astimezone(MOSCOW):%d.%m %H:%M} — {labels.get(kind, kind)}" + (f": {self._short(payload, 260)}" if payload else ""))
                self.tg.answer_callback(callback_id)
                self.tg.send(chat_id, "\n".join(lines), reply_keyboard=MAIN_MENU)
                return
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        if len(parts) == 4 and parts[0] == "proj" and parts[1] == "set":
            user = self._user(sender)
            snapshot = self.storage.get_snapshot(sender, parts[2])
            project = self.storage.project(sender, parts[3]) if user else None
            if not user or not snapshot or not project:
                self.tg.answer_callback(callback_id, "Проект или задача уже недоступны")
                return
            self.storage.set_task_project(sender, snapshot.task_id, project.id)
            self.tg.answer_callback(callback_id, "Проект привязан")
            self.tg.send(chat_id, f"🗂 Задача «{snapshot.title}» привязана к проекту «{project.title}».", reply_keyboard=MAIN_MENU)
            return
        if len(parts) == 3 and parts[0] == "focus":
            user = self._user(sender)
            snapshot = self.storage.get_snapshot(sender, parts[2])
            if not user or not snapshot:
                self.tg.answer_callback(callback_id, "Задача уже изменилась")
                return
            date = datetime.now(MOSCOW).date().isoformat()
            if parts[1] == "add":
                if not self.storage.add_focus(sender, date, snapshot.task_id):
                    self.tg.answer_callback(callback_id, "В фокусе уже три задачи")
                    self.tg.send(chat_id, "В фокусе уже три задачи. Сначала снимите одну — иначе план дня перестанет быть реальным.", reply_keyboard=MAIN_MENU)
                    return
                self.tg.answer_callback(callback_id, "Добавлено в фокус")
                self.tg.send(chat_id, f"⭐ «{snapshot.title}» — в фокусе дня.", reply_keyboard=MAIN_MENU)
                return
            if parts[1] == "remove":
                self.storage.remove_focus(sender, date, snapshot.task_id)
                self.tg.answer_callback(callback_id, "Убрано из фокуса")
                self.tg.send(chat_id, f"Убрал «{snapshot.title}» из фокуса дня.", reply_keyboard=MAIN_MENU)
                return
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        if len(parts) == 3 and parts[0] == "live":
            user = self._user(sender)
            snapshot = self.storage.get_snapshot(sender, parts[2])
            if not user or not snapshot:
                self.tg.answer_callback(callback_id, "Задача уже изменилась")
                return
            if parts[1] == "menu":
                self.tg.answer_callback(callback_id)
                self.tg.send(
                    chat_id,
                    f"Что изменить в задаче «{snapshot.title}" + "»?",
                    keyboard=[
                        [{"text": "✏️ Название", "callback_data": f"live:title:{snapshot.task_id}"}, {"text": "📝 Описание", "callback_data": f"live:description:{snapshot.task_id}"}],
                        [{"text": "📅 Срок", "callback_data": f"live:deadline:{snapshot.task_id}"}, {"text": "🔥 Приоритет", "callback_data": f"live:priority:{snapshot.task_id}"}],
                        [{"text": "👤 Исполнитель", "callback_data": f"live:assignee:{snapshot.task_id}"}],
                        [{"text": "🗂 Проект", "callback_data": f"live:project:{snapshot.task_id}"}],
                        [{"text": "🗑 Удалить задачу", "callback_data": f"live:delete:{snapshot.task_id}"}],
                    ],
                )
                return
            if parts[1] in {"title", "description", "deadline"}:
                self.storage.set_mode(sender, f"live_{parts[1]}", snapshot.task_id)
                prompt = {"title": "Напишите новое название задачи.", "description": "Напишите новое описание задачи.", "deadline": "Напишите новый срок, например: «в пятницу в 15:00»."}[parts[1]]
                self.tg.answer_callback(callback_id, "Напишите новое значение")
                self.tg.send(chat_id, prompt, force_reply=True, input_placeholder="Напишите значение")
                return
            if parts[1] == "priority":
                self.tg.answer_callback(callback_id, "Выберите приоритет")
                self.tg.send(chat_id, "Приоритет задачи:", keyboard=[[
                    {"text": "🔥 Высокий", "callback_data": f"liveprio:{snapshot.task_id}:high"},
                    {"text": "• Обычный", "callback_data": f"liveprio:{snapshot.task_id}:medium"},
                    {"text": "↓ Низкий", "callback_data": f"liveprio:{snapshot.task_id}:low"},
                ]])
                return
            if parts[1] == "assignee":
                targets = self.users.users() if user.role in {"owner", "partner"} else [user]
                self.tg.answer_callback(callback_id, "Выберите исполнителя")
                self.tg.send(chat_id, "Кому назначить задачу?", keyboard=[[{"text": target.display_name, "callback_data": f"livewho:{snapshot.task_id}:{target.alias}"}] for target in targets])
                return
            if parts[1] == "project":
                projects = self.storage.projects(user.tg_id)
                self.tg.answer_callback(callback_id)
                if not projects:
                    self.tg.send(chat_id, "Сначала создайте проект через «☰ Ещё» → «🗂 Проекты».", reply_keyboard=MAIN_MENU)
                else:
                    self.tg.send(chat_id, "К какому проекту привязать задачу?", keyboard=[[{"text": project.title, "callback_data": f"proj:set:{snapshot.task_id}:{project.id}"}] for project in projects[:12]])
                return
            if parts[1] == "delete":
                managed = self.storage.managed_task(snapshot.task_id)
                if user.role != "owner" and (not managed or managed.creator_tg_id != sender):
                    self.tg.answer_callback(callback_id, "Удаление недоступно")
                    self.tg.send(chat_id, "Удалять задачу может только её постановщик или владелец TaskBot.", reply_keyboard=MAIN_MENU)
                    return
                action = self.storage.create_pending_action(sender, "delete", snapshot.task_id)
                self.tg.answer_callback(callback_id, "Нужно подтверждение")
                self.tg.send(chat_id, f"🗑 Удалить задачу «{snapshot.title}»? Это действие нельзя отменить.", keyboard=[[{"text": "✅ Удалить", "callback_data": f"act:confirm:{action.id}"}, {"text": "Отмена", "callback_data": f"act:cancel:{action.id}"}]])
                return
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        if len(parts) == 3 and parts[0] in {"liveprio", "livewho"}:
            user = self._user(sender)
            snapshot = self.storage.get_snapshot(sender, parts[1])
            if not user or not snapshot:
                self.tg.answer_callback(callback_id, "Задача уже изменилась")
                return
            if parts[0] == "liveprio":
                if parts[2] not in {"high", "medium", "low"}:
                    self.tg.answer_callback(callback_id, "Неизвестный приоритет")
                    return
                label = {"high": "высокий", "medium": "обычный", "low": "низкий"}[parts[2]]
                self.tg.answer_callback(callback_id)
                priority_value = {"high": "2", "medium": "1", "low": "0"}[parts[2]]
                self._offer_update(chat_id, user, snapshot.task_id, {"PRIORITY": priority_value}, f"Приоритет: {label}")
                return
            target = self.users.by_alias(parts[2])
            if not target or (user.role not in {"owner", "partner"} and target.tg_id != sender):
                self.tg.answer_callback(callback_id, "Исполнитель недоступен")
                return
            self.tg.answer_callback(callback_id)
            self._offer_update(chat_id, user, snapshot.task_id, {"RESPONSIBLE_ID": target.bitrix_id}, f"Исполнитель: {target.display_name}")
            return
        if len(parts) == 3 and parts[0] == "act":
            action = self.storage.get_pending_action(parts[2])
            user = self._user(sender)
            if not action or not user or action.tg_id != sender:
                self.tg.answer_callback(callback_id, "Действие уже обработано")
                return
            if parts[1] == "cancel":
                self.storage.set_action_status(action.id, "cancelled")
                self.tg.answer_callback(callback_id, "Отменено")
                self.tg.send(chat_id, "Ничего не изменено.", reply_keyboard=MAIN_MENU)
                return
            if parts[1] != "confirm":
                self.tg.answer_callback(callback_id, "Неизвестное действие")
                return
            if action.kind == "plan_prepare":
                try:
                    operations = json.loads(action.payload or "[]")
                except json.JSONDecodeError:
                    operations = []
                if not isinstance(operations, list):
                    self.tg.answer_callback(callback_id, "Не удалось прочитать план")
                    return
                self.storage.set_action_status(action.id, "prepared")
                self.tg.answer_callback(callback_id, "Карточки готовы")
                self.tg.send(chat_id, "Подготовил карточки. Создание и изменения по-прежнему требуют отдельного подтверждения.", reply_keyboard=MAIN_MENU)
                for operation in operations:
                    if not isinstance(operation, dict):
                        continue
                    kind = str(operation.get("kind") or "")
                    if kind == "create" and operation.get("title"):
                        target = self.users.by_alias(str(operation.get("assignee_alias") or "")) if operation.get("assignee_alias") else user
                        if not target or (user.role not in {"owner", "partner"} and target.tg_id != sender):
                            target = user
                        self._draft(
                            chat_id,
                            user,
                            str(operation["title"]),
                            target,
                            deadline=str(operation.get("deadline") or self._deadline()),
                            priority=str(operation.get("priority") or "medium"),
                        )
                    elif kind in {"reschedule", "complete", "delete"}:
                        self._prepare_action_card(chat_id, user, {key: (str(value) if value is not None else None) for key, value in operation.items()})
                return
            snapshot = self.storage.get_snapshot(sender, action.task_id)
            title = snapshot.title if snapshot else f"Задача #{action.task_id}"
            if action.kind == "delete":
                managed = self.storage.managed_task(action.task_id)
                if user.role != "owner" and (not managed or managed.creator_tg_id != sender):
                    self.tg.answer_callback(callback_id, "Недостаточно прав")
                    return
            try:
                if action.kind == "reschedule" and action.payload:
                    self.bitrix.move_deadline(int(action.task_id), action.payload)
                    message = f"Срок задачи «{title}» изменён на {self._parse_iso(action.payload):%d.%m %H:%M}."
                    event = "rescheduled"
                elif action.kind == "complete":
                    self.bitrix.complete_task(int(action.task_id))
                    self.storage.mark_completed(action.task_id)
                    message = f"Задача «{title}» завершена."
                    event = "completed"
                elif action.kind == "complete_with_result" and action.payload:
                    try:
                        result_payload = json.loads(action.payload)
                    except json.JSONDecodeError:
                        result_payload = {}
                    result = str(result_payload.get("result") or "").strip() if isinstance(result_payload, dict) else ""
                    if not result:
                        self.tg.answer_callback(callback_id, "Нужен результат")
                        return
                    self.bitrix.add_result(int(action.task_id), result)
                    self.bitrix.complete_task(int(action.task_id))
                    self.storage.mark_completed(action.task_id)
                    self.storage.update_task_runtime(action.task_id, state="completed", last_progress=result, clear_blocker=True)
                    message = f"Задача «{title}» завершена. Результат сохранён в Bitrix24."
                    event = "completed"
                elif action.kind == "delete":
                    self.bitrix.delete_task(int(action.task_id))
                    message = f"Задача «{title}» удалена."
                    event = "deleted"
                elif action.kind == "update" and action.payload:
                    try:
                        fields = json.loads(action.payload)
                    except json.JSONDecodeError:
                        fields = None
                    if not isinstance(fields, dict) or not fields:
                        self.tg.answer_callback(callback_id, "Не удалось прочитать изменение")
                        return
                    self.bitrix.update_task(int(action.task_id), fields)
                    if "TITLE" in fields:
                        self.storage.update_managed_title(action.task_id, str(fields["TITLE"]))
                    if "RESPONSIBLE_ID" in fields:
                        target = self.users.by_bitrix(int(fields["RESPONSIBLE_ID"])) if str(fields["RESPONSIBLE_ID"]).isdigit() else None
                        if target:
                            self.storage.update_task_runtime(action.task_id, responsible_tg_id=target.tg_id)
                    message = f"Задача «{title}» обновлена."
                    event = "updated"
                else:
                    self.tg.answer_callback(callback_id, "Не удалось выполнить действие")
                    return
            except BitrixError:
                self.tg.answer_callback(callback_id, "Bitrix24 не принял действие")
                self.tg.send(chat_id, "Не удалось применить изменение. Задача не была подтверждена как изменённая.", reply_keyboard=MAIN_MENU)
                return
            self.storage.set_action_status(action.id, "confirmed")
            self.storage.record_event(action.task_id, sender, event, action.payload)
            self.tg.answer_callback(callback_id, "Готово")
            self.tg.send(chat_id, message, reply_keyboard=MAIN_MENU)
            if snapshot and event in {"rescheduled", "updated", "completed"}:
                self._task_detail(chat_id, user, snapshot, refresh=True)
            managed = self.storage.managed_task(action.task_id)
            if managed and event == "completed":
                self._creator_notice(managed, f"✅ {user.display_name} завершил задачу «{managed.title}».")
            return
        if len(parts) == 3 and parts[0] == "hub":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            self.tg.answer_callback(callback_id)
            if parts[1] == "focus":
                self._plan_day(chat_id, user)
            elif parts[1] == "tasks":
                self._task_list(chat_id, user)
            elif parts[1] == "team":
                self._team(chat_id, user)
            elif parts[1] == "projects":
                self._projects(chat_id, user)
            elif parts[1] == "week":
                self._weekly_report(chat_id, user)
            elif parts[1] == "settings":
                self._status(chat_id, user)
            return
        if len(parts) == 3 and parts[0] == "project" and parts[1] == "open":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            self.tg.answer_callback(callback_id)
            self._project_detail(chat_id, user, parts[2])
            return
        if len(parts) == 3 and parts[0] == "project" and parts[1] == "new":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            self.storage.set_mode(sender, "new_project")
            self.tg.answer_callback(callback_id, "Напишите название")
            self.tg.send(chat_id, "Напишите название проекта. Лучше направление с несколькими задачами, например: «Тендеры» или «Развитие продаж».", reply_keyboard=MAIN_MENU)
            return
        if len(parts) == 3 and parts[0] == "goal" and parts[1] == "new":
            user = self._user(sender)
            project = self.storage.project(sender, parts[2]) if user else None
            if not user or not project:
                self.tg.answer_callback(callback_id, "Проект уже недоступен")
                return
            self.storage.set_mode(sender, "new_goal", project.id)
            self.tg.answer_callback(callback_id, "Напишите цель")
            self.tg.send(chat_id, "Напишите результат, которого хотите достичь в этом проекте. Например: «Подать пять целевых тендеров до конца месяца».", reply_keyboard=MAIN_MENU)
            return
        if len(parts) == 3 and parts[0] == "view":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            if parts[1] == "all":
                try:
                    snapshots = self.storage.sync_task_snapshots(user.tg_id, self.bitrix.list_my_open_tasks(user.bitrix_id))
                except BitrixError:
                    self.tg.answer_callback(callback_id, "Не удалось обновить список")
                    return
                keyboard = [[{"text": self._button_title(index, snapshot.title), "callback_data": f"view:open:{snapshot.task_id}"}] for index, snapshot in enumerate(snapshots[:10], 1)]
                self.tg.answer_callback(callback_id)
                self.tg.send(chat_id, f"📋 Все задачи: {len(snapshots)}", keyboard=keyboard)
                return
            snapshot = self.storage.get_snapshot(sender, parts[2])
            if not snapshot:
                self.tg.answer_callback(callback_id, "Задача уже изменилась")
                return
            self.tg.answer_callback(callback_id)
            self._task_detail(chat_id, user, snapshot, expanded=parts[1] == "more")
            return
        if len(parts) == 3 and parts[0] == "inbox" and parts[1] == "mine":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            self.tg.answer_callback(callback_id)
            self._show_captures(chat_id, user)
            return
        if len(parts) == 3 and parts[0] == "inbox" and parts[1] == "team":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            tasks = self.storage.incoming_tasks(user.tg_id)
            self.tg.answer_callback(callback_id)
            if not tasks:
                self.tg.send(chat_id, "Новых поручений нет.", reply_keyboard=MAIN_MENU)
            else:
                self.tg.send(chat_id, "Выберите поручение:", keyboard=[[{"text": self._button_title(index, task.title), "callback_data": f"inbox:open:{task.task_id}"}] for index, task in enumerate(tasks[:10], 1)])
            return
        if len(parts) == 3 and parts[0] == "capture":
            user = self._user(sender)
            item = self.storage.inbox_item(sender, parts[2]) if user else None
            if not user or not item or item.status != "new":
                self.tg.answer_callback(callback_id, "Этот захват уже обработан")
                return
            if parts[1] == "open":
                self.tg.answer_callback(callback_id)
                self.tg.send(chat_id, f"💭 {item.text}", keyboard=[[
                    {"text": "Сделать задачей", "callback_data": f"capture:convert:{item.id}"},
                    {"text": "Оставить", "callback_data": f"capture:keep:{item.id}"},
                ], [{"text": "Удалить", "callback_data": f"capture:discard:{item.id}"}]])
                return
            if parts[1] == "convert":
                self.storage.set_inbox_status(item.id, "drafted")
                self.tg.answer_callback(callback_id, "Готовлю карточку")
                self._draft_from_text(chat_id, user, item.text)
                return
            if parts[1] == "keep":
                self.tg.answer_callback(callback_id, "Оставил во входящих")
                self.tg.send(chat_id, "Оставил во входящих. Вернуться можно через «📥 Входящие».", reply_keyboard=MAIN_MENU)
                return
            if parts[1] == "discard":
                self.storage.set_inbox_status(item.id, "discarded")
                self.tg.answer_callback(callback_id, "Удалено")
                self.tg.send(chat_id, "Убрал из входящих.", reply_keyboard=MAIN_MENU)
                return
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        if len(parts) == 3 and parts[0] == "inbox" and parts[1] == "open":
            managed = self.storage.managed_task(parts[2])
            if not managed or managed.responsible_tg_id != sender or managed.accepted_at:
                self.tg.answer_callback(callback_id, "Задача уже обработана")
                return
            creator = self._user(managed.creator_tg_id)
            self.tg.answer_callback(callback_id)
            self.tg.send(chat_id, f"📥 {managed.title}\nОт: {creator.display_name if creator else 'постановщик'}", keyboard=self._assignment_keyboard(int(managed.task_id)))
            return
        if len(parts) == 3 and parts[0] == "team" and parts[1] == "open":
            managed = self.storage.managed_task(parts[2])
            if not managed or managed.creator_tg_id != sender:
                self.tg.answer_callback(callback_id, "Задача недоступна")
                return
            responsible = self._user(managed.responsible_tg_id)
            runtime = self.storage.task_runtime(managed.task_id)
            state = "ожидает принятия" if not managed.accepted_at else self._runtime_state_label(runtime.state if runtime else "in_progress")
            lines = [f"👥 {managed.title}", f"Исполнитель: {responsible.display_name if responsible else 'неизвестен'}", f"Статус: {state}"]
            if runtime and runtime.next_step:
                lines.append(f"➡️ Следующий шаг: {self._short(runtime.next_step, 260)}")
            if runtime and runtime.last_progress:
                lines.append(f"📝 Последнее: {self._short(runtime.last_progress, 260)}")
            if runtime and runtime.blocker:
                lines.append(f"🚧 Блокер: {self._short(runtime.blocker, 260)}")
            self.tg.answer_callback(callback_id)
            self.tg.send(chat_id, "\n".join(lines), keyboard=[[{"text": "🔔 Напомнить", "callback_data": f"team:ping:{managed.task_id}"}]])
            return
        if len(parts) == 3 and parts[0] == "draft" and parts[1] == "edit":
            draft = self.storage.get_pending(parts[2])
            actor = self._user(sender)
            if not draft or not actor or draft.creator_tg_id != sender:
                self.tg.answer_callback(callback_id, "Черновик уже обработан")
                return
            self.tg.answer_callback(callback_id)
            self.tg.send(
                chat_id,
                "Что исправить?",
                keyboard=[
                    [{"text": "Название", "callback_data": f"edit:title:{draft.id}"}, {"text": "Срок", "callback_data": f"edit:deadline:{draft.id}"}],
                    [{"text": "Исполнитель", "callback_data": f"edit:assignee:{draft.id}"}, {"text": "Приоритет", "callback_data": f"edit:priority:{draft.id}"}],
                    [{"text": "← К черновику", "callback_data": f"task:open:{draft.id}"}],
                ],
            )
            return
        if len(parts) == 3 and parts[0] == "edit":
            draft = self.storage.get_pending(parts[2])
            actor = self._user(sender)
            if not draft or not actor or draft.creator_tg_id != sender:
                self.tg.answer_callback(callback_id, "Черновик уже обработан")
                return
            if parts[1] == "title":
                self.storage.set_mode(sender, "draft_title", draft.id)
                self.tg.answer_callback(callback_id, "Напишите новое название")
                self.tg.send(chat_id, "Напишите новое название задачи одним сообщением.", force_reply=True, input_placeholder="Новое название")
                return
            if parts[1] == "deadline":
                self.tg.answer_callback(callback_id, "Выберите срок")
                self.tg.send(
                    chat_id,
                    "Выберите срок. Точное время можно затем уточнить голосом или текстом в новой задаче.",
                    keyboard=[[
                        {"text": "Сегодня 19:00", "callback_data": f"editdate:{draft.id}:today"},
                        {"text": "Завтра 10:00", "callback_data": f"editdate:{draft.id}:tomorrow"},
                    ], [{"text": "Послезавтра 10:00", "callback_data": f"editdate:{draft.id}:after"}, {"text": "Без срока", "callback_data": f"editdate:{draft.id}:none"}]],
                )
                return
            if parts[1] == "priority":
                self.tg.answer_callback(callback_id, "Выберите приоритет")
                self.tg.send(
                    chat_id,
                    "Приоритет задачи:",
                    keyboard=[[ 
                        {"text": "🔥 Высокий", "callback_data": f"editprio:{draft.id}:high"},
                        {"text": "• Обычный", "callback_data": f"editprio:{draft.id}:medium"},
                        {"text": "↓ Низкий", "callback_data": f"editprio:{draft.id}:low"},
                    ]],
                )
                return
            if parts[1] == "assignee":
                targets = self.users.users() if actor.role in {"owner", "partner"} else [actor]
                keyboard = [[{"text": target.display_name, "callback_data": f"editwho:{draft.id}:{target.alias}"}] for target in targets]
                self.tg.answer_callback(callback_id, "Выберите исполнителя")
                self.tg.send(chat_id, "Кому поставить задачу?", keyboard=keyboard)
                return
            self.tg.answer_callback(callback_id, "Неизвестное поле")
            return
        if len(parts) == 3 and parts[0] in {"editdate", "editprio", "editwho"}:
            draft = self.storage.get_pending(parts[1])
            actor = self._user(sender)
            if not draft or not actor or draft.creator_tg_id != sender:
                self.tg.answer_callback(callback_id, "Черновик уже обработан")
                return
            if parts[0] == "editdate":
                now = datetime.now(MOSCOW)
                offsets = {"today": 0, "tomorrow": 1, "after": 2}
                if parts[2] == "none":
                    updated = self.storage.update_draft(draft.id, deadline="")
                    self.tg.answer_callback(callback_id, "Срок снят")
                    if updated:
                        self._send_draft_card(chat_id, updated)
                    return
                if parts[2] not in offsets:
                    self.tg.answer_callback(callback_id, "Неизвестный срок")
                    return
                deadline = (now + timedelta(days=offsets[parts[2]])).replace(hour=19 if parts[2] == "today" else 10, minute=0, second=0, microsecond=0)
                if parts[2] == "today" and deadline <= now:
                    deadline += timedelta(days=1)
                updated = self.storage.update_draft(draft.id, deadline=deadline.isoformat())
            elif parts[0] == "editprio":
                if parts[2] not in {"high", "medium", "low"}:
                    self.tg.answer_callback(callback_id, "Неизвестный приоритет")
                    return
                updated = self.storage.update_draft(draft.id, priority=parts[2])
            else:
                target = self.users.by_alias(parts[2])
                if not target or (actor.role not in {"owner", "partner"} and target.tg_id != sender):
                    self.tg.answer_callback(callback_id, "Исполнитель недоступен")
                    return
                updated = self.storage.update_draft(draft.id, responsible_id=target.bitrix_id)
            self.tg.answer_callback(callback_id, "Карточка обновлена")
            if updated:
                self._send_draft_card(chat_id, updated)
            return
        if len(parts) == 3 and parts[0] == "work" and parts[1] == "start":
            snapshot = self.storage.get_snapshot(sender, parts[2])
            if not snapshot:
                self.tg.answer_callback(callback_id, "Карточка устарела")
                return
            if self._task_is_completed(snapshot.task_id):
                self.storage.update_task_runtime(snapshot.task_id, state="completed")
                self.tg.answer_callback(callback_id, "Задача уже завершена")
                self.tg.send(chat_id, "Эта задача уже завершена в Bitrix24 и не будет повторно запущена.", reply_keyboard=MAIN_MENU)
                return
            try:
                self.bitrix.start_task(int(snapshot.task_id))
            except BitrixError:
                self.tg.answer_callback(callback_id, "Не удалось начать")
                self.tg.send(chat_id, "Bitrix24 не принял перевод задачи в работу. Возможно, её статус уже изменён.", reply_keyboard=MAIN_MENU)
                return
            managed = self.storage.managed_task(snapshot.task_id)
            self.storage.mark_accepted(snapshot.task_id)
            self.storage.update_task_runtime(snapshot.task_id, responsible_tg_id=sender, state="in_progress", clear_blocker=True, started=True)
            self.storage.record_event(snapshot.task_id, sender, "accepted")
            self.tg.answer_callback(callback_id, "Задача в работе")
            self.tg.send(chat_id, f"▶️ Задача «{snapshot.title}» переведена в работу. Зафиксируйте следующий шаг, когда он ясен.", keyboard=[[{"text": "➡️ Указать следующий шаг", "callback_data": f"run:next:{snapshot.task_id}"}]], reply_keyboard=MAIN_MENU)
            actor = self._user(sender)
            if actor:
                self._task_detail(chat_id, actor, snapshot, refresh=True)
            if managed:
                worker = self._user(sender)
                self._creator_notice(managed, f"▶️ {worker.display_name if worker else 'Исполнитель'} принял в работу задачу «{managed.title}».")
            return
        if len(parts) == 3 and parts[0] == "team" and parts[1] == "ping":
            managed = self.storage.managed_task(parts[2])
            if not managed or managed.creator_tg_id != sender:
                self.tg.answer_callback(callback_id, "Это действие недоступно")
                return
            try:
                self.tg.send(managed.responsible_tg_id, f"🔔 Напоминание от постановщика по задаче «{managed.title}».\nОткройте «🎯 Мой день» и обновите статус или добавьте результат.", reply_keyboard=MAIN_MENU)
            except TelegramError:
                self.tg.answer_callback(callback_id, "Не удалось доставить")
                return
            self.storage.record_event(managed.task_id, sender, "manual_reminder")
            self.tg.answer_callback(callback_id, "Напоминание отправлено")
            self.tg.send(chat_id, "Напоминание отправлено исполнителю.", reply_keyboard=MAIN_MENU)
            return
        if len(parts) == 3 and parts[0] == "ctl":
            managed = self.storage.managed_task(parts[2])
            user = self._user(sender)
            if not managed or not user:
                self.tg.answer_callback(callback_id, "Это действие недоступно")
                return
            if parts[1] == "reply":
                if managed.creator_tg_id != sender:
                    self.tg.answer_callback(callback_id, "Это действие недоступно")
                    return
                self.storage.set_mode(sender, "reply", managed.task_id)
                self.tg.answer_callback(callback_id, "Напишите ответ")
                self.tg.send(chat_id, f"Напишите ответ по задаче «{managed.title}». Я передам его исполнителю.", reply_keyboard=MAIN_MENU)
                return
            if managed.responsible_tg_id != sender:
                self.tg.answer_callback(callback_id, "Это действие недоступно")
                return
            if parts[1] == "accept":
                try:
                    self.bitrix.start_task(int(managed.task_id))
                except BitrixError:
                    self.tg.answer_callback(callback_id, "Bitrix24 не принял действие")
                    self.tg.send(chat_id, "Не удалось перевести задачу в работу. Возможно, её статус уже изменён в Bitrix24.", reply_keyboard=MAIN_MENU)
                    return
                self.storage.mark_accepted(managed.task_id)
                self.storage.update_task_runtime(managed.task_id, responsible_tg_id=sender, state="in_progress", clear_blocker=True, started=True)
                self.storage.record_event(managed.task_id, sender, "accepted")
                self.tg.answer_callback(callback_id, "Принято в работу")
                self.tg.send(chat_id, f"Задача «{managed.title}» принята в работу в Bitrix24.", reply_keyboard=MAIN_MENU)
                snapshot = self.storage.get_snapshot(sender, managed.task_id)
                if snapshot:
                    self._task_detail(chat_id, user, snapshot)
                self._creator_notice(managed, f"▶️ {user.display_name} принял в работу задачу «{managed.title}».")
                return
            if parts[1] == "ask":
                self.storage.set_mode(sender, "clarify", managed.task_id)
                self.tg.answer_callback(callback_id, "Напишите вопрос")
                self.tg.send(chat_id, f"Напишите вопрос постановщику по задаче «{managed.title}». Я передам его в Telegram.", reply_keyboard=MAIN_MENU)
                return
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        if len(parts) == 3 and parts[0] == "rem":
            snapshot = self.storage.get_snapshot(sender, parts[2])
            if not snapshot:
                self.tg.answer_callback(callback_id, "Напоминание устарело")
                return
            if parts[1] == "done":
                user = self._user(sender)
                if not user:
                    self.tg.answer_callback(callback_id, "Пользователь не найден")
                    return
                self.tg.answer_callback(callback_id)
                self._request_runtime_input(chat_id, user, snapshot, "finish")
                return
            if parts[1] == "snooze":
                until = datetime.now(MOSCOW) + timedelta(hours=1)
                self.storage.set_snooze(sender, snapshot.task_id, until.isoformat())
                self.tg.answer_callback(callback_id, "Напомню через час")
                self.tg.send(chat_id, f"Отложил напоминание по задаче «{snapshot.title}» на час.", reply_keyboard=MAIN_MENU)
                return
            if parts[1] == "tomorrow":
                tomorrow = (datetime.now(MOSCOW) + timedelta(days=1)).replace(hour=10, minute=0, second=0, microsecond=0)
                user = self._user(sender)
                if not user:
                    self.tg.answer_callback(callback_id, "Пользователь не найден")
                    return
                self.tg.answer_callback(callback_id)
                self._offer_update(chat_id, user, snapshot.task_id, {"DEADLINE": tomorrow.isoformat()}, f"Новый срок: завтра, {tomorrow:%d.%m %H:%M}")
                return
            if parts[1] == "result":
                self.storage.set_mode(sender, "result", snapshot.task_id)
                self.tg.answer_callback(callback_id, "Напишите результат")
                self.tg.send(chat_id, f"Напишите краткий результат по задаче «{snapshot.title}». Он будет сохранён в Bitrix24; задачу бот сам не завершит.", reply_keyboard=MAIN_MENU)
                return
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        if len(parts) == 2 and parts[0] == "menu":
            user = self._user(sender)
            if not user:
                self.tg.answer_callback(callback_id, "Сначала откройте бота через /start")
                return
            self.tg.answer_callback(callback_id)
            if parts[1] == "new":
                self.tg.send(chat_id, "Напишите или надиктуйте задачу. Я сначала покажу карточку.", reply_keyboard=MAIN_MENU)
            elif parts[1] == "today":
                self._today(chat_id, user)
            elif parts[1] == "plan":
                self._plan_day(chat_id, user)
            elif parts[1] == "assign":
                self._assignment_picker(chat_id, user)
            return
        if len(parts) == 2 and parts[0] == "assign":
            user = self._user(sender)
            target = self.users.by_alias(parts[1]) if user else None
            if not user or not target or user.role not in {"owner", "partner"}:
                self.tg.answer_callback(callback_id, "Исполнитель недоступен")
                return
            self.storage.set_mode(sender, "assign", target.alias)
            self.tg.answer_callback(callback_id, "Исполнитель выбран")
            self.tg.send(chat_id, f"Задача будет поставлена: {target.display_name}. Напишите или надиктуйте её текст.", reply_keyboard=MAIN_MENU)
            return
        if len(parts) != 3 or parts[0] != "task":
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        draft = self.storage.get_pending(parts[2])
        if not draft or draft.creator_tg_id != sender:
            self.tg.answer_callback(callback_id, "Черновик уже обработан")
            return
        if parts[1] == "open":
            self.tg.answer_callback(callback_id)
            self._send_draft_card(chat_id, draft)
            return
        if parts[1] == "cancel":
            self.storage.set_status(draft.id, "cancelled")
            self.tg.answer_callback(callback_id, "Отменено")
            self.tg.send(chat_id, "Черновик отменён.")
            return
        if parts[1] != "confirm":
            self.tg.answer_callback(callback_id, "Неизвестное действие")
            return
        try:
            task_id = self.bitrix.create_task(title=draft.title, responsible_id=draft.responsible_id, deadline=draft.deadline or None, priority=draft.priority, creator_tg_id=sender)
        except BitrixError:
            self.tg.answer_callback(callback_id, "Ошибка Bitrix24")
            self.tg.send(chat_id, "Задача не создана — попробуйте подтвердить ещё раз.")
            return
        self.storage.set_status(draft.id, "created")
        responsible = self.users.by_bitrix(draft.responsible_id)
        priority_value = {"high": "2", "medium": "1", "low": "0"}.get(draft.priority, "1")
        creator_snapshot = TaskSnapshot(sender, str(task_id), draft.title, draft.deadline or None, priority_value)
        if responsible and responsible.tg_id == sender:
            self.storage.set_conversation_state(sender, last_task_id=str(task_id))
            self.storage.save_snapshot(creator_snapshot)
        elif responsible:
            self.storage.set_conversation_state(sender, last_task_id="")
            self.storage.save_snapshot(TaskSnapshot(responsible.tg_id, str(task_id), draft.title, draft.deadline or None, priority_value))
        if responsible:
            self.storage.register_managed_task(task_id, sender, responsible.tg_id, draft.title)
        self.tg.answer_callback(callback_id, "Создано")
        if responsible and responsible.tg_id == sender:
            self._task_detail(chat_id, responsible, creator_snapshot)
        else:
            self.tg.send(chat_id, f"Задача #{task_id} создана в Bitrix24 и отправлена исполнителю. Статус и обновления появятся в «👥 Команда».", reply_keyboard=MAIN_MENU)
        if responsible and responsible.tg_id != sender:
            creator = self._user(sender)
            priority_label = {"high": "Высокий", "medium": "Обычный", "low": "Низкий"}.get(draft.priority, "Обычный")
            try:
                self.tg.send(
                    responsible.tg_id,
                    f"📥 Новая задача от {creator.display_name if creator else 'партнёра'}\n"
                    f"Срок: {draft.deadline[:16] if draft.deadline else 'без срока'}\nПриоритет: {priority_label}\n\n{draft.title}",
                    keyboard=self._assignment_keyboard(task_id),
                )
            except TelegramError:
                LOG.warning("Assignment notification delivery failed for Telegram user %s", responsible.tg_id)

    def process(self, update: dict) -> None:
        update_id = int(update["update_id"])
        if self.storage.seen_update(update_id):
            return
        if "message" in update:
            self._handle_message(update["message"])
        elif "callback_query" in update:
            self._handle_callback(update["callback_query"])
        self.storage.mark_update(update_id)

    def run(self) -> None:
        me = self.tg.get_me()
        LOG.info("TaskBot started as @%s", me.get("username", "unknown"))
        while True:
            try:
                self._run_daily_routines()
                self._run_reminders()
                self._run_backup()
                updates = self.tg.get_updates(self.offset)
                for update in updates:
                    self.process(update)
                    self.offset = int(update["update_id"]) + 1
            except TelegramError as exc:
                LOG.warning("Telegram polling error: %s", exc)
                time.sleep(3)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        with SingleInstance("TenderBot_TaskBot_8709670956"):
            App(Config.load()).run()
    except AlreadyRunning:
        LOG.info("TaskBot is already running; second launch skipped")


if __name__ == "__main__":
    main()
