from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNTIME = (ROOT / "lead_factory" / "canary_runtime.py").resolve()
BOUNDARY = (ROOT / "lead_factory" / "bitrix_rest.py").resolve()
DIRECT_BITRIX_HTTP_SINKS = frozenset({
    (ROOT / "lead_factory" / "bitrix_rest.py").resolve(),
    (ROOT / "taskbot" / "bitrix.py").resolve(),
    (ROOT / "tb_bitrix.py").resolve(),
    (ROOT / "tb_bitrix_readonly.py").resolve(),
    (ROOT / "tb_leaddocs.py").resolve(),
})
_HTTP_MUTATION_CALLS = frozenset({"delete", "patch", "post", "put", "request"})
_GUARDED_HTTP_CALLS = frozenset({
    "guarded_manual_egress_attempt",
    "guarded_manual_egress_call",
    "guarded_manual_http_call",
})
_COMMAND_SINK_CALLS = frozenset({
    "call",
    "check_call",
    "check_output",
    "popen",
    "run",
    "system",
})
_BITRIX_URL_IDENTIFIERS = frozenset({
    "_base",
    "_webhook_url",
    "_wh",
    "api_base",
    "base",
    "webhook",
    "wh",
})


def _production_python_files():
    ignored_roots = {
        ".venv",
        "__pycache__",
        "tests",
        "state",
        "logs",
        "outputs",
        "reports",
        "_diagnostics",
    }
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT)
        if any(part in ignored_roots for part in relative.parts):
            continue
        if len(relative.parts) >= 2 and relative.parts[0] == "taskbot" and relative.parts[1] == "tests":
            continue
        yield path.resolve()


def _is_direct_bitrix_http_sink(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Attribute):
        call_name = node.func.attr.casefold()
    elif isinstance(node.func, ast.Name):
        call_name = node.func.id.casefold()
    else:
        return False
    identifiers = {
        child.id.casefold()
        for child in ast.walk(node)
        if isinstance(child, ast.Name)
    }
    identifiers.update(
        child.attr.casefold()
        for child in ast.walk(node)
        if isinstance(child, ast.Attribute)
    )
    string_values = " ".join(
        child.value.casefold()
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    )
    has_bitrix_target = bool(identifiers & _BITRIX_URL_IDENTIFIERS) or any(
        marker in string_values for marker in ("bitrix", "/rest/", "crm.", "tasks.")
    )
    if not has_bitrix_target:
        return False
    if call_name in _HTTP_MUTATION_CALLS or call_name == "urlopen":
        return True
    if call_name in _GUARDED_HTTP_CALLS and identifiers & _HTTP_MUTATION_CALLS:
        return True
    # Do not let a future raw ``curl``/PowerShell command route around the
    # reviewed Python transports.  Ordinary subprocesses are not Bitrix sinks.
    return call_name in _COMMAND_SINK_CALLS and any(
        marker in string_values for marker in ("curl", "invoke-restmethod", "invoke-webrequest")
    )


class RuntimeIntegrityTests(unittest.TestCase):
    """Keep the credential-bearing canary composition single-path by default.

    Python private names are not a security sandbox.  This static regression
    therefore fails if future production code starts importing the generic
    executor or minting Bitrix write capabilities outside the reviewed sealed
    runtime.  Tests may still exercise those primitives with fake transports.
    """

    def test_only_sealed_runtime_imports_executor_or_mints_write_capability(self):
        violations: list[str] = []
        for path in _production_python_files():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError) as exc:
                self.fail(f"cannot inspect production source {path}: {type(exc).__name__}")
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = str(node.module or "")
                    if module.endswith("canary_executor") and any(
                        alias.name == "CanaryExecutor" for alias in node.names
                    ) and path != RUNTIME:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}: CanaryExecutor import"
                        )
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "_mint_write_capability"
                    and path != RUNTIME
                ):
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: write capability mint"
                    )
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "BitrixWriteCapability"
                    and path != BOUNDARY
                ):
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: direct capability construction"
                    )
        self.assertEqual(violations, [], "\n".join(violations))

    def test_direct_bitrix_http_sinks_match_reviewed_inventory(self):
        """A new raw Bitrix transport is a reviewed security-boundary change."""
        discovered: set[Path] = set()
        locations: dict[Path, list[int]] = {}
        for path in _production_python_files():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError) as exc:
                self.fail(f"cannot inspect production source {path}: {type(exc).__name__}")
            for node in ast.walk(tree):
                if _is_direct_bitrix_http_sink(node):
                    discovered.add(path)
                    locations.setdefault(path, []).append(node.lineno)

        missing = DIRECT_BITRIX_HTTP_SINKS - discovered
        unexpected = discovered - DIRECT_BITRIX_HTTP_SINKS
        detail = [
            f"unexpected {path.relative_to(ROOT)}:{','.join(map(str, locations[path]))}"
            for path in sorted(unexpected)
        ]
        detail.extend(f"missing {path.relative_to(ROOT)}" for path in sorted(missing))
        self.assertEqual((unexpected, missing), (set(), set()), "\n".join(detail))

    def test_sink_detector_covers_urlopen_and_command_line_bypasses(self):
        samples = (
            "urlopen(webhook + '/crm.lead.add.json')",
            "subprocess.run(['curl', '-X', 'POST', webhook + '/crm.lead.add.json'])",
            "subprocess.Popen(['powershell', 'Invoke-RestMethod', '-Uri', webhook])",
        )
        for source in samples:
            with self.subTest(source=source):
                call = next(
                    node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
                )
                self.assertTrue(_is_direct_bitrix_http_sink(call))

        harmless = next(
            node
            for node in ast.walk(ast.parse("subprocess.run(['python', 'worker.py'])"))
            if isinstance(node, ast.Call)
        )
        self.assertFalse(_is_direct_bitrix_http_sink(harmless))


if __name__ == "__main__":
    unittest.main()
