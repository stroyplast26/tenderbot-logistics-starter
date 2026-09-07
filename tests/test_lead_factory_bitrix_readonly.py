from __future__ import annotations

import importlib
import unittest
from unittest.mock import patch

import tb_bitrix_readonly


class _Response:
    def __init__(self, value=None):
        self._value = value if value is not None else {"result": []}

    def json(self):
        return self._value


class DiagnosticBitrixReadOnlyTests(unittest.TestCase):
    MODULE_READS = (
        ("tb_callnow", "crm.deal.list"),
        ("tb_fetch_kp", "disk.file.get"),
        ("tb_funnel_diag", "crm.lead.list"),
        ("tb_probe_kp", "crm.deal.get"),
        ("tb_winners", "crm.company.list"),
        ("_dbg", "crm.timeline.comment.list"),
    )

    def test_six_diagnostic_helpers_reject_writes_batch_and_unknown_before_http(self):
        for module_name, _ in self.MODULE_READS:
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                with (
                    patch.object(module, "WH", "https://fixture.invalid/rest/1/token"),
                    patch.object(tb_bitrix_readonly.requests, "post") as post,
                ):
                    results = [
                        module.call("crm.lead.add", {"fields": {"TITLE": "fixture"}}),
                        module.call("batch", {"cmd": {"write": "crm.lead.add"}}),
                        module.call("crm.future.inspect", {}),
                    ]
                self.assertEqual(
                    results,
                    [{"error": tb_bitrix_readonly.METHOD_REJECTED}] * 3,
                )
                self.assertEqual(post.call_count, 0)

    def test_each_current_diagnostic_read_still_reaches_http_once(self):
        for module_name, method in self.MODULE_READS:
            with self.subTest(module=module_name, method=method):
                module = importlib.import_module(module_name)
                with (
                    patch.object(
                        module,
                        "WH",
                        "https://fixture.bitrix24.ru/rest/1/token",
                    ),
                    patch.object(
                        tb_bitrix_readonly,
                        "guarded_manual_http_call",
                        side_effect=lambda _operation, _method, _source, url, transport,
                        *args, **kwargs: transport(
                            url, *args, **kwargs
                        ),
                    ),
                    patch.object(
                        tb_bitrix_readonly.requests,
                        "post",
                        return_value=_Response(),
                    ) as post,
                ):
                    result = module.call(method, {})
                self.assertEqual(result, {"result": []})
                self.assertEqual(post.call_count, 1)
                self.assertTrue(post.call_args.args[0].endswith(f"/{method}.json"))
                self.assertIs(post.call_args.kwargs["allow_redirects"], False)

    def test_global_read_inventory_cannot_expand_a_scripts_local_allowlist(self):
        module = importlib.import_module("tb_winners")
        self.assertIn("crm.contact.list", tb_bitrix_readonly.READ_ONLY_METHODS)
        with (
            patch.object(module, "WH", "https://fixture.invalid/rest/1/token"),
            patch.object(tb_bitrix_readonly.requests, "post") as post,
        ):
            result = module.call("crm.contact.list", {})
        self.assertEqual(result, {"error": tb_bitrix_readonly.METHOD_REJECTED})
        self.assertEqual(post.call_count, 0)


if __name__ == "__main__":
    unittest.main()
