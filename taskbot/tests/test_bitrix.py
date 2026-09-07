import unittest
from unittest.mock import Mock, patch

from taskbot.bitrix import BitrixCanaryHold, BitrixMethodRejected, BitrixTasks
from taskbot.app import App


class BitrixTasksTests(unittest.TestCase):
    def test_create_task_uses_bitrix_priority_scale(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        calls = []

        def fake_call(method, payload=None):
            calls.append((method, payload))
            return {"task": {"id": "42"}}

        client._call = fake_call
        client.create_task(title="Высокая", responsible_id=13, deadline="2026-08-19T10:00:00+03:00", priority="high", creator_tg_id=1)
        self.assertEqual(calls[0][1]["fields"]["PRIORITY"], "2")

    def test_create_task_omits_deadline_when_it_is_not_set(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        calls = []

        def fake_call(method, payload=None):
            calls.append((method, payload))
            return {"task": {"id": "42"}}

        client._call = fake_call
        client.create_task(title="Без срока", responsible_id=13, deadline=None, priority="medium", creator_tg_id=1)
        self.assertNotIn("DEADLINE", calls[0][1]["fields"])

    def test_explicit_no_deadline_is_recognised(self):
        self.assertTrue(App._explicitly_no_deadline("без срока, я исполнитель"))
        self.assertTrue(App._explicitly_no_deadline("Дедлайн не ставь"))
        self.assertFalse(App._explicitly_no_deadline("срок завтра в 10"))

    def test_task_field_supports_bitrix_get_camel_case(self):
        task = {"responsibleId": "13", "createdBy": "15", "priority": "1"}
        self.assertEqual(App._field(task, "RESPONSIBLE_ID"), "13")
        self.assertEqual(App._field(task, "CREATED_BY"), "15")
        self.assertEqual(App._field(task, "PRIORITY"), "1")

    def test_list_open_tasks_filters_status_after_bitrix_response(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        calls = []

        def fake_call(method, payload):
            calls.append((method, payload))
            return {"tasks": [{"id": "1", "status": "2"}, {"id": "2", "status": "5"}, {"id": "3", "STATUS": "6"}]}

        client._call = fake_call
        self.assertEqual([task["id"] for task in client.list_my_open_tasks(13)], ["1", "3"])
        self.assertEqual(calls[0][1]["filter"], {"RESPONSIBLE_ID": 13})

    def test_task_detail_and_update_payloads(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        calls = []

        def fake_call(method, payload=None):
            calls.append((method, payload))
            if method == "tasks.task.get":
                return {"task": {"id": "42", "title": "Согласовать смету", "description": "С заказчиком"}}
            return True

        client._call = fake_call
        task = client.get_task(42)
        client.update_task(42, {"TITLE": "Уточнить смету"})
        client.delete_task(42)

        self.assertEqual(task["title"], "Согласовать смету")
        self.assertEqual(calls[0][0], "tasks.task.get")
        self.assertEqual(calls[1], ("tasks.task.update", {"taskId": 42, "fields": {"TITLE": "Уточнить смету"}}))
        self.assertEqual(calls[2], ("tasks.task.delete", {"taskId": 42}))

    def test_add_result_uses_rest_v3_route(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        calls = []

        def fake_call_v3(method, payload=None):
            calls.append((method, payload))
            return {"item": {"id": 1}}

        client._call_v3 = fake_call_v3
        client.add_result(42, "Работа выполнена")
        self.assertEqual(calls, [("tasks.task.result.add", {"fields": {"taskId": 42, "text": "Работа выполнена"}})])

    def test_all_task_mutations_hold_without_http_during_live_factory_canary(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=True),
            patch.object(client, "_call") as rest,
            patch.object(client, "_call_v3") as rest_v3,
        ):
            with self.assertRaises(BitrixCanaryHold):
                client.create_task(title="fixture", responsible_id=1, deadline=None, priority="low", creator_tg_id=1)
            for method, args in (
                (client.complete_task, (1,)),
                (client.start_task, (1,)),
                (client.update_task, (1, {"TITLE": "fixture"})),
                (client.add_result, (1, "fixture")),
                (client.delete_task, (1,)),
            ):
                with self.assertRaises(BitrixCanaryHold):
                    method(*args)
        self.assertEqual(rest.call_count, 0)
        self.assertEqual(rest_v3.call_count, 0)

    def test_raw_taskbot_allows_only_inventoried_reads_during_canary(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"result": {"task": {"id": "1"}}}
        with (
            patch(
                "taskbot.bitrix.guarded_manual_egress_call",
                side_effect=lambda _operation, transport, *args, **kwargs: transport(
                    *args, **kwargs
                ),
            ),
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=True),
            patch.object(client._http, "post", return_value=response) as post,
        ):
            self.assertEqual(client._call("tasks.task.get", {"taskId": 1}), {"task": {"id": "1"}})
            for method in ("batch", "tasks.future.inspect"):
                with self.assertRaisesRegex(BitrixMethodRejected, "TASKBOT_BITRIX_METHOD_REJECTED"):
                    client._call(method, {})
            with self.assertRaises(BitrixCanaryHold):
                client._call("TaSkS.TaSk.AdD", {})
            for method in ("batch", "tasks.task.get"):
                with self.assertRaisesRegex(BitrixMethodRejected, "TASKBOT_BITRIX_METHOD_REJECTED"):
                    client._call_v3(method, {})
            with self.assertRaises(BitrixCanaryHold):
                client._call_v3("TaSkS.TaSk.ReSuLt.AdD", {})
        self.assertEqual(post.call_count, 1)

    def test_raw_taskbot_unknown_method_fails_closed_without_canary(self):
        client = BitrixTasks("https://example.test/rest/1/token")
        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=False),
            patch.object(client._http, "post") as post,
        ):
            with self.assertRaisesRegex(BitrixMethodRejected, "TASKBOT_BITRIX_METHOD_REJECTED"):
                client._call("future.method", {})
            with self.assertRaisesRegex(BitrixMethodRejected, "TASKBOT_BITRIX_METHOD_REJECTED"):
                client._call_v3("future.method", {})
        self.assertEqual(post.call_count, 0)


if __name__ == "__main__":
    unittest.main()
