from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Draft:
    id: str
    title: str
    responsible_id: int
    creator_tg_id: int
    deadline: str
    priority: str
    status: str


@dataclass(frozen=True)
class TaskSnapshot:
    tg_id: int
    task_id: str
    title: str
    deadline: str | None
    priority: str


@dataclass(frozen=True)
class ManagedTask:
    task_id: str
    creator_tg_id: int
    responsible_tg_id: int
    title: str
    created_at: str
    accepted_at: str | None
    completed_at: str | None


@dataclass(frozen=True)
class PendingAction:
    id: str
    tg_id: int
    kind: str
    task_id: str
    payload: str | None


@dataclass(frozen=True)
class ConversationState:
    tg_id: int
    last_task_id: str | None
    last_draft_id: str | None


@dataclass(frozen=True)
class InboxItem:
    id: str
    tg_id: int
    text: str
    status: str
    created_at: str


@dataclass(frozen=True)
class Project:
    id: str
    tg_id: int
    title: str
    status: str


@dataclass(frozen=True)
class Goal:
    id: str
    project_id: str | None
    tg_id: int
    title: str
    horizon: str
    status: str


@dataclass(frozen=True)
class TaskRuntime:
    task_id: str
    responsible_tg_id: int | None
    state: str
    next_step: str | None
    last_progress: str | None
    blocker: str | None
    started_at: str | None
    updated_at: str


@dataclass(frozen=True)
class TaskCard:
    tg_id: int
    task_id: str
    chat_id: int
    message_id: int


class Storage:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.row_factory = sqlite3.Row
        self._db.execute("""CREATE TABLE IF NOT EXISTS processed_updates (
            update_id INTEGER PRIMARY KEY, processed_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS drafts (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, responsible_id INTEGER NOT NULL,
            creator_tg_id INTEGER NOT NULL, deadline TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL,
            created_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS routine_sends (
            kind TEXT NOT NULL, date TEXT NOT NULL, tg_id INTEGER NOT NULL,
            sent_at TEXT NOT NULL, PRIMARY KEY (kind, date, tg_id))""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS conversation_modes (
            tg_id INTEGER PRIMARY KEY, mode TEXT NOT NULL, value TEXT, updated_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS task_snapshots (
            tg_id INTEGER NOT NULL, task_id TEXT NOT NULL, title TEXT NOT NULL,
            deadline TEXT, priority TEXT NOT NULL, synced_at TEXT NOT NULL,
            PRIMARY KEY (tg_id, task_id))""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS reminder_sends (
            tg_id INTEGER NOT NULL, task_id TEXT NOT NULL, kind TEXT NOT NULL,
            bucket TEXT NOT NULL, sent_at TEXT NOT NULL,
            PRIMARY KEY (tg_id, task_id, kind, bucket))""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS task_snoozes (
            tg_id INTEGER NOT NULL, task_id TEXT NOT NULL, until_at TEXT NOT NULL,
            PRIMARY KEY (tg_id, task_id))""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS runtime_state (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS managed_tasks (
            task_id TEXT PRIMARY KEY, creator_tg_id INTEGER NOT NULL, responsible_tg_id INTEGER NOT NULL,
            title TEXT NOT NULL, created_at TEXT NOT NULL, accepted_at TEXT, completed_at TEXT)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS task_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL, actor_tg_id INTEGER NOT NULL,
            kind TEXT NOT NULL, payload TEXT, created_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS pending_actions (
            id TEXT PRIMARY KEY, tg_id INTEGER NOT NULL, kind TEXT NOT NULL, task_id TEXT NOT NULL,
            payload TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS conversation_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id INTEGER NOT NULL, role TEXT NOT NULL,
            text TEXT NOT NULL, created_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS conversation_state (
            tg_id INTEGER PRIMARY KEY, last_task_id TEXT, last_draft_id TEXT, updated_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS ai_corrections (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id INTEGER NOT NULL, draft_id TEXT,
            original_text TEXT, correction TEXT NOT NULL, created_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS user_memories (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id INTEGER NOT NULL, memory TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS inbox_items (
            id TEXT PRIMARY KEY, tg_id INTEGER NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS daily_focus (
            tg_id INTEGER NOT NULL, date TEXT NOT NULL, task_id TEXT NOT NULL, selected_at TEXT NOT NULL,
            PRIMARY KEY (tg_id, date, task_id))""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, tg_id INTEGER NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS goals (
            id TEXT PRIMARY KEY, project_id TEXT, tg_id INTEGER NOT NULL, title TEXT NOT NULL,
            horizon TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS task_context (
            tg_id INTEGER NOT NULL, task_id TEXT NOT NULL, project_id TEXT, estimate_minutes INTEGER,
            PRIMARY KEY (tg_id, task_id))""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS task_runtime (
            task_id TEXT PRIMARY KEY, responsible_tg_id INTEGER, state TEXT NOT NULL DEFAULT 'planned',
            next_step TEXT, last_progress TEXT, blocker TEXT, started_at TEXT, updated_at TEXT NOT NULL)""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS task_cards (
            tg_id INTEGER NOT NULL, task_id TEXT NOT NULL, chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
            PRIMARY KEY (tg_id, task_id))""")
        self._db.execute("""CREATE TABLE IF NOT EXISTS task_message_context (
            tg_id INTEGER NOT NULL, chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL, task_id TEXT NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY (tg_id, chat_id, message_id))""")
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(drafts)")}
        if "priority" not in columns:
            self._db.execute("ALTER TABLE drafts ADD COLUMN priority TEXT NOT NULL DEFAULT 'medium'")
        self._db.commit()

    def seen_update(self, update_id: int) -> bool:
        row = self._db.execute("SELECT 1 FROM processed_updates WHERE update_id=?", (update_id,)).fetchone()
        return row is not None

    def mark_update(self, update_id: int) -> None:
        self._db.execute("INSERT OR IGNORE INTO processed_updates VALUES (?, ?)", (update_id, datetime.now(timezone.utc).isoformat()))
        self._db.commit()

    def create_draft(self, title: str, responsible_id: int, creator_tg_id: int, deadline: str, priority: str = "medium") -> Draft:
        draft = Draft(uuid.uuid4().hex[:16], title, responsible_id, creator_tg_id, deadline, priority, "pending")
        self._db.execute("INSERT INTO drafts (id,title,responsible_id,creator_tg_id,deadline,priority,status,created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (*draft.__dict__.values(), datetime.now(timezone.utc).isoformat()))
        self._db.commit()
        return draft

    def get_pending(self, draft_id: str) -> Draft | None:
        row = self._db.execute("SELECT id,title,responsible_id,creator_tg_id,deadline,priority,status FROM drafts WHERE id=? AND status='pending'", (draft_id,)).fetchone()
        return Draft(**dict(row)) if row else None

    def latest_pending_draft(self, creator_tg_id: int) -> Draft | None:
        row = self._db.execute(
            "SELECT id,title,responsible_id,creator_tg_id,deadline,priority,status FROM drafts WHERE creator_tg_id=? AND status='pending' ORDER BY created_at DESC LIMIT 1",
            (creator_tg_id,),
        ).fetchone()
        return Draft(**dict(row)) if row else None

    def remember(self, tg_id: int, role: str, text: str) -> None:
        self._db.execute(
            "INSERT INTO conversation_memory (tg_id,role,text,created_at) VALUES (?, ?, ?, ?)",
            (tg_id, role, text[:2000], datetime.now(timezone.utc).isoformat()),
        )
        self._db.execute(
            "DELETE FROM conversation_memory WHERE tg_id=? AND id NOT IN (SELECT id FROM conversation_memory WHERE tg_id=? ORDER BY id DESC LIMIT 30)",
            (tg_id, tg_id),
        )
        self._db.commit()

    def recent_memory(self, tg_id: int, limit: int = 12) -> list[tuple[str, str]]:
        rows = self._db.execute(
            "SELECT role,text FROM conversation_memory WHERE tg_id=? ORDER BY id DESC LIMIT ?", (tg_id, limit)
        ).fetchall()
        return [(str(row["role"]), str(row["text"])) for row in reversed(rows)]

    def conversation_state(self, tg_id: int) -> ConversationState:
        row = self._db.execute("SELECT tg_id,last_task_id,last_draft_id FROM conversation_state WHERE tg_id=?", (tg_id,)).fetchone()
        return ConversationState(**dict(row)) if row else ConversationState(tg_id, None, None)

    def set_conversation_state(self, tg_id: int, *, last_task_id: str | None = None, last_draft_id: str | None = None) -> None:
        previous = self.conversation_state(tg_id)
        task_id = last_task_id if last_task_id is not None else previous.last_task_id
        draft_id = last_draft_id if last_draft_id is not None else previous.last_draft_id
        self._db.execute(
            "INSERT INTO conversation_state (tg_id,last_task_id,last_draft_id,updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(tg_id) DO UPDATE SET last_task_id=excluded.last_task_id,last_draft_id=excluded.last_draft_id,updated_at=excluded.updated_at",
            (tg_id, task_id, draft_id, datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()

    def record_correction(self, tg_id: int, draft_id: str | None, original_text: str | None, correction: str) -> None:
        self._db.execute(
            "INSERT INTO ai_corrections (tg_id,draft_id,original_text,correction,created_at) VALUES (?, ?, ?, ?, ?)",
            (tg_id, draft_id, original_text, correction[:2000], datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()

    def recent_corrections(self, tg_id: int, limit: int = 5) -> list[tuple[str | None, str]]:
        rows = self._db.execute(
            "SELECT original_text,correction FROM ai_corrections WHERE tg_id=? ORDER BY id DESC LIMIT ?", (tg_id, limit)
        ).fetchall()
        return [(str(row["original_text"]) if row["original_text"] else None, str(row["correction"])) for row in reversed(rows)]

    def remember_fact(self, tg_id: int, memory: str) -> None:
        normalized = memory.strip()[:500]
        if not normalized:
            return
        now = datetime.now(timezone.utc).isoformat()
        row = self._db.execute("SELECT id FROM user_memories WHERE tg_id=? AND lower(memory)=lower(?)", (tg_id, normalized)).fetchone()
        if row:
            self._db.execute("UPDATE user_memories SET updated_at=? WHERE id=?", (now, row["id"]))
        else:
            self._db.execute("INSERT INTO user_memories (tg_id,memory,created_at,updated_at) VALUES (?, ?, ?, ?)", (tg_id, normalized, now, now))
        self._db.execute(
            "DELETE FROM user_memories WHERE tg_id=? AND id NOT IN (SELECT id FROM user_memories WHERE tg_id=? ORDER BY updated_at DESC LIMIT 30)",
            (tg_id, tg_id),
        )
        self._db.commit()

    def memories(self, tg_id: int, limit: int = 12) -> list[str]:
        rows = self._db.execute("SELECT memory FROM user_memories WHERE tg_id=? ORDER BY updated_at DESC LIMIT ?", (tg_id, limit)).fetchall()
        return [str(row["memory"]) for row in rows]

    def forget_memories(self, tg_id: int, query: str) -> int:
        value = query.strip().lower()
        if not value:
            return 0
        rows = self._db.execute("SELECT id,memory FROM user_memories WHERE tg_id=?", (tg_id,)).fetchall()
        ids = [int(row["id"]) for row in rows if value.casefold() in str(row["memory"]).casefold()]
        if not ids:
            return 0
        marks = ",".join("?" for _ in ids)
        cursor = self._db.execute(f"DELETE FROM user_memories WHERE id IN ({marks})", ids)
        self._db.commit()
        return int(cursor.rowcount)

    def capture_inbox(self, tg_id: int, text: str) -> InboxItem:
        now = datetime.now(timezone.utc).isoformat()
        item = InboxItem(uuid.uuid4().hex[:16], tg_id, text.strip()[:2000], "new", now)
        self._db.execute("INSERT INTO inbox_items (id,tg_id,text,status,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?)", (*item.__dict__.values(), now))
        self._db.commit()
        return item

    def inbox_items(self, tg_id: int, limit: int = 20) -> list[InboxItem]:
        rows = self._db.execute(
            "SELECT id,tg_id,text,status,created_at FROM inbox_items WHERE tg_id=? AND status='new' ORDER BY created_at DESC LIMIT ?", (tg_id, limit)
        ).fetchall()
        return [InboxItem(**dict(row)) for row in rows]

    def inbox_item(self, tg_id: int, item_id: str) -> InboxItem | None:
        row = self._db.execute("SELECT id,tg_id,text,status,created_at FROM inbox_items WHERE tg_id=? AND id=?", (tg_id, item_id)).fetchone()
        return InboxItem(**dict(row)) if row else None

    def set_inbox_status(self, item_id: str, status: str) -> None:
        self._db.execute("UPDATE inbox_items SET status=?,updated_at=? WHERE id=?", (status, datetime.now(timezone.utc).isoformat(), item_id))
        self._db.commit()

    def focus_task_ids(self, tg_id: int, date: str) -> list[str]:
        rows = self._db.execute("SELECT task_id FROM daily_focus WHERE tg_id=? AND date=? ORDER BY selected_at", (tg_id, date)).fetchall()
        return [str(row["task_id"]) for row in rows]

    def add_focus(self, tg_id: int, date: str, task_id: str) -> bool:
        if task_id in self.focus_task_ids(tg_id, date):
            return True
        if len(self.focus_task_ids(tg_id, date)) >= 3:
            return False
        cursor = self._db.execute("INSERT OR IGNORE INTO daily_focus VALUES (?, ?, ?, ?)", (tg_id, date, task_id, datetime.now(timezone.utc).isoformat()))
        self._db.commit()
        return cursor.rowcount == 1

    def remove_focus(self, tg_id: int, date: str, task_id: str) -> None:
        self._db.execute("DELETE FROM daily_focus WHERE tg_id=? AND date=? AND task_id=?", (tg_id, date, task_id))
        self._db.commit()

    def create_project(self, tg_id: int, title: str) -> Project:
        now = datetime.now(timezone.utc).isoformat()
        project = Project(uuid.uuid4().hex[:12], tg_id, title.strip()[:200], "active")
        self._db.execute("INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?)", (*project.__dict__.values(), now, now))
        self._db.commit()
        return project

    def projects(self, tg_id: int) -> list[Project]:
        rows = self._db.execute("SELECT id,tg_id,title,status FROM projects WHERE tg_id=? AND status='active' ORDER BY updated_at DESC", (tg_id,)).fetchall()
        return [Project(**dict(row)) for row in rows]

    def project(self, tg_id: int, project_id: str) -> Project | None:
        row = self._db.execute("SELECT id,tg_id,title,status FROM projects WHERE tg_id=? AND id=? AND status='active'", (tg_id, project_id)).fetchone()
        return Project(**dict(row)) if row else None

    def set_task_project(self, tg_id: int, task_id: str, project_id: str | None) -> None:
        self._db.execute("INSERT INTO task_context (tg_id,task_id,project_id) VALUES (?, ?, ?) ON CONFLICT(tg_id,task_id) DO UPDATE SET project_id=excluded.project_id", (tg_id, task_id, project_id))
        self._db.commit()

    def task_project(self, tg_id: int, task_id: str) -> Project | None:
        row = self._db.execute(
            "SELECT p.id,p.tg_id,p.title,p.status FROM task_context c JOIN projects p ON p.id=c.project_id WHERE c.tg_id=? AND c.task_id=?",
            (tg_id, task_id),
        ).fetchone()
        return Project(**dict(row)) if row else None

    def task_runtime(self, task_id: int | str) -> TaskRuntime | None:
        row = self._db.execute(
            "SELECT task_id,responsible_tg_id,state,next_step,last_progress,blocker,started_at,updated_at FROM task_runtime WHERE task_id=?",
            (str(task_id),),
        ).fetchone()
        return TaskRuntime(**dict(row)) if row else None

    def update_task_runtime(
        self,
        task_id: int | str,
        *,
        responsible_tg_id: int | None = None,
        state: str | None = None,
        next_step: str | None = None,
        last_progress: str | None = None,
        blocker: str | None = None,
        clear_blocker: bool = False,
        started: bool = False,
    ) -> TaskRuntime:
        previous = self.task_runtime(task_id)
        now = datetime.now(timezone.utc).isoformat()
        runtime = TaskRuntime(
            task_id=str(task_id),
            responsible_tg_id=responsible_tg_id if responsible_tg_id is not None else (previous.responsible_tg_id if previous else None),
            state=state or (previous.state if previous else "planned"),
            next_step=next_step if next_step is not None else (previous.next_step if previous else None),
            last_progress=last_progress if last_progress is not None else (previous.last_progress if previous else None),
            blocker=None if clear_blocker else (blocker if blocker is not None else (previous.blocker if previous else None)),
            started_at=now if started and not (previous and previous.started_at) else (previous.started_at if previous else None),
            updated_at=now,
        )
        self._db.execute(
            """INSERT INTO task_runtime (task_id,responsible_tg_id,state,next_step,last_progress,blocker,started_at,updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(task_id) DO UPDATE SET responsible_tg_id=excluded.responsible_tg_id,state=excluded.state,
               next_step=excluded.next_step,last_progress=excluded.last_progress,blocker=excluded.blocker,
               started_at=excluded.started_at,updated_at=excluded.updated_at""",
            tuple(runtime.__dict__.values()),
        )
        self._db.commit()
        return runtime

    def task_events(self, task_id: int | str, limit: int = 8) -> list[tuple[str, str | None, str]]:
        rows = self._db.execute(
            "SELECT kind,payload,created_at FROM task_events WHERE task_id=? ORDER BY id DESC LIMIT ?", (str(task_id), limit)
        ).fetchall()
        return [(str(row["kind"]), str(row["payload"]) if row["payload"] else None, str(row["created_at"])) for row in reversed(rows)]

    def remember_task_card(self, tg_id: int, task_id: int | str, chat_id: int, message_id: int) -> None:
        self._db.execute(
            "INSERT INTO task_cards VALUES (?, ?, ?, ?) ON CONFLICT(tg_id,task_id) DO UPDATE SET chat_id=excluded.chat_id,message_id=excluded.message_id",
            (tg_id, str(task_id), chat_id, message_id),
        )
        self.bind_task_message(tg_id, task_id, chat_id, message_id, commit=False)
        self._db.commit()

    def task_card(self, tg_id: int, task_id: int | str) -> TaskCard | None:
        row = self._db.execute("SELECT tg_id,task_id,chat_id,message_id FROM task_cards WHERE tg_id=? AND task_id=?", (tg_id, str(task_id))).fetchone()
        return TaskCard(**dict(row)) if row else None

    def bind_task_message(self, tg_id: int, task_id: int | str, chat_id: int, message_id: int, *, commit: bool = True) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO task_message_context (tg_id,chat_id,message_id,task_id,created_at) VALUES (?, ?, ?, ?, ?)",
            (tg_id, chat_id, message_id, str(task_id), datetime.now(timezone.utc).isoformat()),
        )
        self._db.execute(
            "DELETE FROM task_message_context WHERE tg_id=? AND rowid NOT IN (SELECT rowid FROM task_message_context WHERE tg_id=? ORDER BY created_at DESC LIMIT 200)",
            (tg_id, tg_id),
        )
        if commit:
            self._db.commit()

    def task_for_message(self, tg_id: int, chat_id: int, message_id: int) -> str | None:
        row = self._db.execute(
            "SELECT task_id FROM task_message_context WHERE tg_id=? AND chat_id=? AND message_id=?",
            (tg_id, chat_id, message_id),
        ).fetchone()
        return str(row["task_id"]) if row else None

    def create_goal(self, tg_id: int, project_id: str | None, title: str, horizon: str = "активная") -> Goal:
        goal = Goal(uuid.uuid4().hex[:12], project_id, tg_id, title.strip()[:300], horizon[:80], "active")
        self._db.execute("INSERT INTO goals VALUES (?, ?, ?, ?, ?, ?, ?)", (*goal.__dict__.values(), datetime.now(timezone.utc).isoformat()))
        self._db.commit()
        return goal

    def goals(self, tg_id: int, project_id: str | None = None) -> list[Goal]:
        if project_id:
            rows = self._db.execute("SELECT id,project_id,tg_id,title,horizon,status FROM goals WHERE tg_id=? AND project_id=? AND status='active' ORDER BY created_at DESC", (tg_id, project_id)).fetchall()
        else:
            rows = self._db.execute("SELECT id,project_id,tg_id,title,horizon,status FROM goals WHERE tg_id=? AND status='active' ORDER BY created_at DESC", (tg_id,)).fetchall()
        return [Goal(**dict(row)) for row in rows]

    def set_status(self, draft_id: str, status: str) -> None:
        self._db.execute("UPDATE drafts SET status=? WHERE id=?", (status, draft_id))
        self._db.commit()

    def update_draft(
        self,
        draft_id: str,
        *,
        title: str | None = None,
        responsible_id: int | None = None,
        deadline: str | None = None,
        priority: str | None = None,
    ) -> Draft | None:
        draft = self.get_pending(draft_id)
        if not draft:
            return None
        updated = Draft(
            id=draft.id,
            title=title.strip() if title is not None else draft.title,
            responsible_id=responsible_id if responsible_id is not None else draft.responsible_id,
            creator_tg_id=draft.creator_tg_id,
            deadline=deadline if deadline is not None else draft.deadline,
            priority=priority if priority is not None else draft.priority,
            status=draft.status,
        )
        if not updated.title:
            return None
        self._db.execute(
            "UPDATE drafts SET title=?,responsible_id=?,deadline=?,priority=? WHERE id=? AND status='pending'",
            (updated.title, updated.responsible_id, updated.deadline, updated.priority, updated.id),
        )
        self._db.commit()
        return updated

    def close(self) -> None:
        self._db.close()

    def claim_routine(self, kind: str, date: str, tg_id: int) -> bool:
        cursor = self._db.execute(
            "INSERT OR IGNORE INTO routine_sends VALUES (?, ?, ?, ?)",
            (kind, date, tg_id, datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()
        return cursor.rowcount == 1

    def set_mode(self, tg_id: int, mode: str, value: str | None = None) -> None:
        self._db.execute(
            "INSERT INTO conversation_modes VALUES (?, ?, ?, ?) ON CONFLICT(tg_id) DO UPDATE SET mode=excluded.mode,value=excluded.value,updated_at=excluded.updated_at",
            (tg_id, mode, value, datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()

    def pop_mode(self, tg_id: int) -> tuple[str, str | None] | None:
        row = self._db.execute("SELECT mode,value FROM conversation_modes WHERE tg_id=?", (tg_id,)).fetchone()
        if not row:
            return None
        self._db.execute("DELETE FROM conversation_modes WHERE tg_id=?", (tg_id,))
        self._db.commit()
        return str(row["mode"]), row["value"]

    @staticmethod
    def _task_value(task: dict, lower: str, upper: str) -> str | None:
        value = task.get(lower, task.get(upper))
        return str(value) if value not in (None, "") else None

    def sync_task_snapshots(self, tg_id: int, tasks: list[dict]) -> list[TaskSnapshot]:
        now = datetime.now(timezone.utc).isoformat()
        snapshots: list[TaskSnapshot] = []
        ids: list[str] = []
        for task in tasks:
            task_id = self._task_value(task, "id", "ID")
            title = self._task_value(task, "title", "TITLE")
            if not task_id or not title:
                continue
            snapshot = TaskSnapshot(
                tg_id=tg_id,
                task_id=task_id,
                title=title,
                deadline=self._task_value(task, "deadline", "DEADLINE"),
                priority=(self._task_value(task, "priority", "PRIORITY") or "0"),
            )
            self._db.execute(
                "INSERT INTO task_snapshots VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tg_id,task_id) DO UPDATE SET title=excluded.title,deadline=excluded.deadline,priority=excluded.priority,synced_at=excluded.synced_at",
                (*snapshot.__dict__.values(), now),
            )
            snapshots.append(snapshot)
            ids.append(task_id)
        if ids:
            marks = ",".join("?" for _ in ids)
            self._db.execute(f"DELETE FROM task_snapshots WHERE tg_id=? AND task_id NOT IN ({marks})", (tg_id, *ids))
        else:
            self._db.execute("DELETE FROM task_snapshots WHERE tg_id=?", (tg_id,))
        self._db.commit()
        return snapshots

    def get_snapshot(self, tg_id: int, task_id: str) -> TaskSnapshot | None:
        row = self._db.execute("SELECT tg_id,task_id,title,deadline,priority FROM task_snapshots WHERE tg_id=? AND task_id=?", (tg_id, task_id)).fetchone()
        return TaskSnapshot(**dict(row)) if row else None

    def save_snapshot(self, snapshot: TaskSnapshot) -> None:
        self._db.execute(
            "INSERT INTO task_snapshots VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tg_id,task_id) DO UPDATE SET title=excluded.title,deadline=excluded.deadline,priority=excluded.priority,synced_at=excluded.synced_at",
            (*snapshot.__dict__.values(), datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()

    def reminder_was_sent(self, tg_id: int, task_id: str, kind: str, bucket: str) -> bool:
        row = self._db.execute("SELECT 1 FROM reminder_sends WHERE tg_id=? AND task_id=? AND kind=? AND bucket=?", (tg_id, task_id, kind, bucket)).fetchone()
        return row is not None

    def mark_reminder_sent(self, tg_id: int, task_id: str, kind: str, bucket: str) -> None:
        self._db.execute("INSERT OR IGNORE INTO reminder_sends VALUES (?, ?, ?, ?, ?)", (tg_id, task_id, kind, bucket, datetime.now(timezone.utc).isoformat()))
        self._db.commit()

    def set_snooze(self, tg_id: int, task_id: str, until_at: str) -> None:
        self._db.execute("INSERT INTO task_snoozes VALUES (?, ?, ?) ON CONFLICT(tg_id,task_id) DO UPDATE SET until_at=excluded.until_at", (tg_id, task_id, until_at))
        self._db.commit()

    def get_snooze(self, tg_id: int, task_id: str) -> str | None:
        row = self._db.execute("SELECT until_at FROM task_snoozes WHERE tg_id=? AND task_id=?", (tg_id, task_id)).fetchone()
        return str(row["until_at"]) if row else None

    def clear_snooze(self, tg_id: int, task_id: str) -> None:
        self._db.execute("DELETE FROM task_snoozes WHERE tg_id=? AND task_id=?", (tg_id, task_id))
        self._db.commit()

    def register_managed_task(self, task_id: int | str, creator_tg_id: int, responsible_tg_id: int, title: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._db.execute(
            "INSERT OR IGNORE INTO managed_tasks (task_id,creator_tg_id,responsible_tg_id,title,created_at) VALUES (?, ?, ?, ?, ?)",
            (str(task_id), creator_tg_id, responsible_tg_id, title, now),
        )
        self.record_event(str(task_id), creator_tg_id, "created")
        self.update_task_runtime(task_id, responsible_tg_id=responsible_tg_id)
        self._db.commit()

    def update_managed_title(self, task_id: int | str, title: str) -> None:
        self._db.execute("UPDATE managed_tasks SET title=? WHERE task_id=?", (title[:500], str(task_id)))
        self._db.commit()

    def managed_task(self, task_id: int | str) -> ManagedTask | None:
        row = self._db.execute(
            "SELECT task_id,creator_tg_id,responsible_tg_id,title,created_at,accepted_at,completed_at FROM managed_tasks WHERE task_id=?",
            (str(task_id),),
        ).fetchone()
        return ManagedTask(**dict(row)) if row else None

    def incoming_tasks(self, tg_id: int) -> list[ManagedTask]:
        rows = self._db.execute(
            "SELECT task_id,creator_tg_id,responsible_tg_id,title,created_at,accepted_at,completed_at FROM managed_tasks WHERE responsible_tg_id=? AND accepted_at IS NULL AND completed_at IS NULL ORDER BY created_at DESC",
            (tg_id,),
        ).fetchall()
        return [ManagedTask(**dict(row)) for row in rows]

    def delegated_tasks(self, tg_id: int) -> list[ManagedTask]:
        rows = self._db.execute(
            "SELECT task_id,creator_tg_id,responsible_tg_id,title,created_at,accepted_at,completed_at FROM managed_tasks WHERE creator_tg_id=? AND responsible_tg_id<>? AND completed_at IS NULL ORDER BY created_at DESC",
            (tg_id, tg_id),
        ).fetchall()
        return [ManagedTask(**dict(row)) for row in rows]

    def mark_accepted(self, task_id: int | str) -> None:
        self._db.execute(
            "UPDATE managed_tasks SET accepted_at=COALESCE(accepted_at, ?) WHERE task_id=?",
            (datetime.now(timezone.utc).isoformat(), str(task_id)),
        )
        self._db.commit()

    def mark_completed(self, task_id: int | str) -> None:
        self._db.execute(
            "UPDATE managed_tasks SET completed_at=COALESCE(completed_at, ?) WHERE task_id=?",
            (datetime.now(timezone.utc).isoformat(), str(task_id)),
        )
        self._db.commit()

    def record_event(self, task_id: int | str, actor_tg_id: int, kind: str, payload: str | None = None) -> None:
        self._db.execute(
            "INSERT INTO task_events (task_id,actor_tg_id,kind,payload,created_at) VALUES (?, ?, ?, ?, ?)",
            (str(task_id), actor_tg_id, kind, payload, datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()

    def create_pending_action(self, tg_id: int, kind: str, task_id: int | str, payload: str | None = None) -> PendingAction:
        action = PendingAction(uuid.uuid4().hex[:16], tg_id, kind, str(task_id), payload)
        self._db.execute(
            "INSERT INTO pending_actions (id,tg_id,kind,task_id,payload,status,created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (*action.__dict__.values(), datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()
        return action

    def get_pending_action(self, action_id: str) -> PendingAction | None:
        row = self._db.execute(
            "SELECT id,tg_id,kind,task_id,payload FROM pending_actions WHERE id=? AND status='pending'", (action_id,)
        ).fetchone()
        return PendingAction(**dict(row)) if row else None

    def set_action_status(self, action_id: str, status: str) -> None:
        self._db.execute("UPDATE pending_actions SET status=? WHERE id=? AND status='pending'", (status, action_id))
        self._db.commit()

    def weekly_summary(self, tg_id: int, since: str) -> dict[str, int]:
        rows = self._db.execute(
            "SELECT kind, count(*) AS total FROM task_events WHERE created_at>=? AND (actor_tg_id=? OR task_id IN (SELECT task_id FROM managed_tasks WHERE creator_tg_id=? OR responsible_tg_id=?)) GROUP BY kind",
            (since, tg_id, tg_id, tg_id),
        ).fetchall()
        result = {str(row["kind"]): int(row["total"]) for row in rows}
        result["open"] = int(self._db.execute(
            "SELECT count(*) FROM managed_tasks WHERE responsible_tg_id=? AND completed_at IS NULL", (tg_id,)
        ).fetchone()[0])
        return result

    def heartbeat(self, value: str) -> None:
        self.set_state("heartbeat", value)

    def set_state(self, key: str, value: str) -> None:
        self._db.execute("INSERT INTO runtime_state VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", (key, value, datetime.now(timezone.utc).isoformat()))
        self._db.commit()

    def get_state(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM runtime_state WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def snapshot_count(self, tg_id: int) -> int:
        return int(self._db.execute("SELECT count(*) FROM task_snapshots WHERE tg_id=?", (tg_id,)).fetchone()[0])

    def backup(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(path)
        try:
            self._db.backup(target)
        finally:
            target.close()
