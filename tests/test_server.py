import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from mcp_portal import delegate, server


STUB = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path
    counter = Path(os.environ["MCP_PORTAL_STUB_COUNTER"])
    counter.write_text(str(int(counter.read_text() or "0") + 1))
    sys.stdin.read()
    mode = os.environ.get("MCP_PORTAL_STUB_MODE", "bulk")
    if mode == "code":
        body = "```python\\nprint('generated')\\n```"
        print(json.dumps({"type": "result", "subtype": "success", "result": body}))
    else:
        answer = {"findings": [{"file": "fixture.txt", "start": 1, "end": 1, "quote": "hello", "fact": "Says hello."}], "gaps": []}
        print(json.dumps({"type": "result", "subtype": "success", "result": json.dumps(answer)}))
    """
)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="mcp-portal-"))
        self.counter = self.home / "stub-count.txt"
        self.counter.write_text("0", encoding="utf-8")
        stub_path = self.home / "stub-cli.py"
        stub_path.write_text(STUB, encoding="utf-8")
        stub_path.chmod(0o755)
        self.root = self.home / "workspace"
        self.root.mkdir()
        (self.root / "fixture.txt").write_text("hello\n", encoding="utf-8")
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        self.env["MCP_PORTAL_HOME"] = str(self.home)
        self.env["MCP_PORTAL_CLI"] = str(stub_path)
        self.env["MCP_PORTAL_STUB_COUNTER"] = str(self.counter)
        self.env["MCP_PORTAL_STUB_MODE"] = "bulk"
        self.env.pop("CURSOR_DELEGATE_DEPTH", None)
        import time

        cache_dir = self.home / "cache"
        cache_dir.mkdir(exist_ok=True)
        (cache_dir / "models.json").write_text(
            json.dumps({"ts": time.time(), "model_ids": ["composer-2.5", "cursor-grok-4.6-high"]}),
            encoding="utf-8",
        )

    def rpc(self, method, params=None, req_id=1):
        req = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            req["params"] = params
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_portal.server"],
            input=json.dumps(req) + "\n",
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
            cwd=str(self.root),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = proc.stdout.strip().splitlines()[-1]
        return json.loads(line)

    def tool_text(self, response):
        self.assertIn("result", response)
        content = response["result"]["content"][0]["text"]
        return json.loads(content)

    def test_tools_list(self):
        resp = self.rpc("tools/list")
        names = {tool["name"] for tool in resp["result"]["tools"]}
        self.assertEqual(names, {"bulk_read", "code_write", "status"})

    def test_bulk_read_and_cache(self):
        args = {
            "paths": [str(self.root / "fixture.txt")],
            "question": "What is in the file?",
            "root": str(self.root),
        }
        first = self.tool_text(self.rpc("tools/call", {"name": "bulk_read", "arguments": args}))
        self.assertEqual(first["status"], "PASS")
        self.assertTrue(first["metrics"].get("cache_hit") in (False, None) or not first["metrics"].get("cache_hit"))
        self.assertEqual(self.counter.read_text().strip(), "1")
        second = self.tool_text(self.rpc("tools/call", {"name": "bulk_read", "arguments": args}, req_id=2))
        self.assertEqual(second["status"], "PASS")
        self.assertTrue(second["metrics"].get("cache_hit"))
        self.assertEqual(self.counter.read_text().strip(), "1")

    def test_refusal_structured(self):
        outside = self.home / "outside.txt"
        outside.write_text("secret-ish but safe text\n", encoding="utf-8")
        args = {"paths": [str(outside)], "question": "q?", "root": str(self.root)}
        payload = self.tool_text(self.rpc("tools/call", {"name": "bulk_read", "arguments": args}, req_id=3))
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("error", payload)

    def test_code_write_strips_fence(self):
        self.env["MCP_PORTAL_STUB_MODE"] = "code"
        target = self.root / "out.py"
        ref = self.root / "fixture.txt"
        args = {
            "spec": "emit a one-line program",
            "reference_path": str(ref),
            "target_path": str(target),
        }
        payload = self.tool_text(
            self.rpc("tools/call", {"name": "code_write", "arguments": args}, req_id=4)
        )
        self.assertEqual(payload["status"], "PASS")
        self.assertTrue(target.is_file())
        self.assertEqual(target.read_text(encoding="utf-8"), "print('generated')")
        self.assertGreater(payload["bytes_written"], 0)

    def test_code_write_without_target_returns_code(self):
        self.env["MCP_PORTAL_STUB_MODE"] = "code"
        ref = self.root / "fixture.txt"
        args = {"spec": "emit a one-line program", "reference_path": str(ref)}
        payload = self.tool_text(
            self.rpc("tools/call", {"name": "code_write", "arguments": args}, req_id=5)
        )
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["code"], "print('generated')")
        self.assertIsNone(payload["target_path"])

    def test_code_write_refuses_blocked_target(self):
        self.env["MCP_PORTAL_STUB_MODE"] = "code"
        blocked = self.root / ".secrets" / "out.py"
        ref = self.root / "fixture.txt"
        args = {
            "spec": "emit a one-line program",
            "reference_path": str(ref),
            "target_path": str(blocked),
        }
        payload = self.tool_text(
            self.rpc("tools/call", {"name": "code_write", "arguments": args}, req_id=6)
        )
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("CREDENTIAL_PATH", payload.get("error", ""))
        self.assertFalse(blocked.is_file())

    def test_status_model_policy(self):
        roster = ["composer-2.5", "cursor-grok-4.6-high"]
        with mock.patch.object(delegate, "available_models", return_value=(roster, None)):
            payload = server.call_tool("status", {})
        self.assertIn("model_policy", payload)
        self.assertEqual(payload["model_policy"]["preferred"][0], "composer-2.5")
        self.assertIn("-fast", payload["model_policy"]["forbid_suffixes"][0])

    def test_normalize_path_skips_wslpath_on_native_windows(self):
        with patch.object(server, "_host_is_native_windows", return_value=True), patch.object(
            delegate, "run_bounded"
        ) as run_bounded:
            path = "C:\\Users\\runner\\workspace\\fixture.txt"
            self.assertEqual(server.normalize_path(path), path)
            run_bounded.assert_not_called()

    def test_stub_cli_spawn_argv_starts_with_sys_executable_on_windows(self):
        """backend() builds argv via _cli_argv; on Windows a .py stub must run under sys.executable."""
        stub = self.home / "stub-cli.py"
        with patch.object(delegate.os, "name", "nt"):
            argv = delegate._cli_argv(
                stub,
                ["--print", "--mode", "ask", "--output-format", "stream-json", "--model", "composer-2.5"],
            )
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(Path(argv[1]), stub)

    def test_garbage_stdin_does_not_crash(self):
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_portal.server"],
            input="not json at all\n",
            capture_output=True,
            text=True,
            env=self.env,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("error", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
