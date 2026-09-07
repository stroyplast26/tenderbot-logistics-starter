import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace

from taskbot.app import App, MOSCOW
from taskbot.directory import User
from taskbot.storage import TaskSnapshot


class ReminderStorage:
    def __init__(self, snapshots):
        self.snapshots = snapshots
        self.marked = []

    def heartbeat(self, _value):
        pass

    def sync_task_snapshots(self, _tg_id, _tasks):
        return self.snapshots

    def managed_task(self, _task_id):
        return None

    def task_runtime(self, _task_id):
        return None

    def reminder_was_sent(self, *_args):
        return False

    def get_snooze(self, *_args):
        return None

    def mark_reminder_sent(self, tg_id, task_id, kind, bucket):
        self.marked.append((tg_id, task_id, kind, bucket))


class ReminderTelegram:
    def __init__(self):
        self.messages = []

    def send(self, *args, **kwargs):
        self.messages.append((args, kwargs))


class ReminderTests(unittest.TestCase):
    def test_multiple_due_tasks_send_one_digest(self):
        app = App.__new__(App)
        deadline = (datetime.now(MOSCOW) + timedelta(hours=3)).isoformat()
        snapshots = [
            TaskSnapshot(1, "1", "Первая", deadline, "1"),
            TaskSnapshot(1, "2", "Вторая", deadline, "1"),
        ]
        app.storage = ReminderStorage(snapshots)
        app.tg = ReminderTelegram()
        app.bitrix = SimpleNamespace(list_my_open_tasks=lambda _user_id: [])
        app.users = SimpleNamespace(users=lambda: [User(1, 13, "owner", "owner", "Дмитрий")])
        app.config = SimpleNamespace(reminder_sync_seconds=300, notify_from_hour=0, notify_until_hour=24)
        app._next_reminder_sync = 0

        app._run_reminders()

        self.assertEqual(len(app.tg.messages), 1)
        self.assertIn("Задачи требуют внимания", app.tg.messages[0][0][1])
        self.assertEqual(len(app.storage.marked), 2)


if __name__ == "__main__":
    unittest.main()
