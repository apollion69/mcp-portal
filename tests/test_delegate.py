import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mcp_portal import delegate as d


class DelegateTests(unittest.TestCase):
    def setUp(self):
        # Resolved roots must not live under blocked path segments (e.g. .claude in worktrees).
        self.root = Path(tempfile.mkdtemp(prefix=f"{sys.platform}-delegate-"))
        (self.root / "данные file.txt").write_text("port = 8123\nretries = 3\n", encoding="utf-8")

    def request(self):
        return d.build_request(self.root, ["данные file.txt"], "Which port?", "composer-2.5", 5)

    def answer(self):
        return {"findings": [{"file": "данные file.txt", "start": 1, "end": 1, "quote": "port = 8123", "fact": "Port 8123."}], "gaps": []}

    def test_unicode_spaces_and_hash(self):
        r = self.request()
        self.assertEqual(r["files"][0]["sha256"], d.digest((self.root / "данные file.txt").read_bytes()))
        self.assertEqual(d.checked_answer(json.dumps(self.answer()), r)[0], self.answer())

    def test_traversal_absolute_and_credentials(self):
        for p in ("../outside", "/etc/passwd", "C:/secret", "a\\b", ".env", ".secrets/x", "a/secret.key", ".cursor/cli-config.json"):
            with self.subTest(p=p), self.assertRaises(d.Refused):
                d.build_request(self.root, [p], "q", "composer-2.5", 5)

    def test_secret_content_and_question(self):
        for value in ("password = highly-private-value", "-----BEGIN RSA " + "PRIVATE KEY-----", "Bearer abcdefghijklmnop"):
            (self.root / "leak.txt").write_text(value)
            with self.assertRaises(d.Refused):
                d.build_request(self.root, ["leak.txt"], "q", "composer-2.5", 5)
            with self.assertRaises(d.Refused):
                d.build_request(self.root, ["данные file.txt"], value, "composer-2.5", 5)

    def test_json_credentials(self):
        for key in ("password", "api_key", "access_token", "refresh_token", "client_secret", "secret"):
            for text in (json.dumps({key: "synthetic-credential-value"}), json.dumps({key: "abc"}), '{"\\u0070assword": "synthetic-value"}'):
                with self.subTest(text=text), self.assertRaises(d.Refused):
                    d.safe_text(text)

    def test_credential_root(self):
        root = self.root / ".secrets"
        root.mkdir()
        (root / "innocent.txt").write_text("synthetic")
        with self.assertRaisesRegex(d.Refused, "CREDENTIAL_ROOT"):
            d.build_request(root, ["innocent.txt"], "q", "composer-2.5", 5)

    def test_symlink_escape_and_alias_to_credentials(self):
        outside = self.root.parent / (self.root.name + "-outside.txt")
        outside.write_text("outside")
        try:
            (self.root / "alias.txt").symlink_to(outside)
        except OSError:
            self.skipTest("Symlink creation unavailable to this Windows token")
        with self.assertRaises(d.Refused):
            d.build_request(self.root, ["alias.txt"], "q", "composer-2.5", 5)
        (self.root / ".env").write_text("innocuous")
        (self.root / "env-alias.txt").symlink_to(self.root / ".env")
        with self.assertRaises(d.Refused):
            d.build_request(self.root, ["env-alias.txt"], "q", "composer-2.5", 5)

    def test_input_limit_binary_duplicate(self):
        (self.root / "large.txt").write_bytes(b"x" * (d.MAX_INPUT + 1))
        (self.root / "binary.txt").write_bytes(b"hi\0there")
        for names in (["large.txt"], ["binary.txt"], ["данные file.txt"] * 2, []):
            with self.assertRaises(d.Refused):
                d.build_request(self.root, names, "q", "composer-2.5", 5)

    def test_recursion(self):
        with patch.dict(os.environ, {"CURSOR_DELEGATE_DEPTH": "1"}):
            with self.assertRaises(d.Refused):
                self.request()

    def test_model_timeout_and_hash(self):
        for key, value in (("model", "--force"), ("timeout", 91), ("timeout", True), ("question", "")):
            r = self.request()
            r[key] = value
            with self.assertRaises(d.Refused):
                d.validate_request(r)
        r = self.request()
        r["files"][0]["sha256"] = "bad"
        with self.assertRaises(d.Refused):
            d.validate_request(r)

    def test_malformed_answers(self):
        for text in ("not json", "[]", "{}", "x" * (d.MAX_ANSWER + 1), '{"findings":[],"gaps":[]}'):
            with self.assertRaises(d.Refused):
                d.checked_answer(text, self.request())

    def test_false_citations(self):
        for key, val in (("file", "missing"), ("start", 0), ("end", 999), ("fact", "")):
            a = self.answer()
            a["findings"][0][key] = val
            with self.assertRaises(d.Refused):
                d.checked_answer(json.dumps(a), self.request())

    def test_elided_quote_dropped_not_fatal(self):
        (self.root / "multi.py").write_text("alpha\nbeta\n", encoding="utf-8")
        r = d.build_request(self.root, ["multi.py"], "q", "composer-2.5", 5)
        a = {
            "findings": [
                {"file": "multi.py", "start": 1, "end": 1, "quote": "alpha", "fact": "Has alpha."},
                {"file": "multi.py", "start": 1, "end": 2, "quote": "alpha\n...\nbeta", "fact": "Elided."},
            ],
            "gaps": [],
        }
        out, stats = d.checked_answer(json.dumps(a), r)
        self.assertEqual(out["findings"], [a["findings"][0]])
        self.assertEqual(stats, {"findings_returned": 1, "findings_dropped": 1})
        self.assertTrue(any("dropped unverifiable citation: multi.py:1-2" in g for g in out["gaps"]))

    def test_all_bad_quotes_raise_citation_quote(self):
        (self.root / "multi.py").write_text("alpha\n", encoding="utf-8")
        r = d.build_request(self.root, ["multi.py"], "q", "composer-2.5", 5)
        a = {"findings": [{"file": "multi.py", "start": 1, "end": 1, "quote": "missing", "fact": "x"}], "gaps": []}
        with self.assertRaisesRegex(d.Refused, "CITATION_QUOTE"):
            d.checked_answer(json.dumps(a), r)

    def test_bad_finding_schema_still_fatal(self):
        (self.root / "multi.py").write_text("alpha\n", encoding="utf-8")
        r = d.build_request(self.root, ["multi.py"], "q", "composer-2.5", 5)
        a = {"findings": [{"file": "multi.py", "start": 1, "end": 1, "quote": "alpha", "fact": "ok", "extra": 1}], "gaps": []}
        with self.assertRaisesRegex(d.Refused, "FINDING_SCHEMA"):
            d.checked_answer(json.dumps(a), r)

    def test_worktree_checkout_carveout(self):
        wt = self.root / ".claude" / "worktrees" / "wt"
        (wt / "src").mkdir(parents=True)
        (wt / "src" / "app.py").write_text("ok\n", encoding="utf-8")
        (wt / ".secrets").mkdir()
        (wt / ".secrets" / "token.env").write_text("token=synthetic\n", encoding="utf-8")
        d.build_request(wt, ["src/app.py"], "q", "composer-2.5", 5)
        with self.assertRaises(d.Refused):
            d.build_request(wt, [".secrets/token.env"], "q", "composer-2.5", 5)
        claude_root = self.root / ".claude"
        (claude_root / "settings.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(d.Refused, "CREDENTIAL_ROOT"):
            d.build_request(claude_root, ["settings.json"], "q", "composer-2.5", 5)

    def test_stream_filters_reasoning_and_rejects_tools(self):
        r = self.request()
        events = [{"type": "thinking", "text": "must not be returned"}, {"type": "result", "subtype": "success", "result": json.dumps(self.answer())}]
        answer, meta = d.parse_stream("\n".join(map(json.dumps, events)), r)
        self.assertNotIn("must not be returned", json.dumps([answer, meta]))
        events.insert(0, {"type": "tool_call", "subtype": "started"})
        with self.assertRaises(d.Refused):
            d.parse_stream("\n".join(map(json.dumps, events)), r)

    def test_missing_failed_duplicate_results(self):
        good = {"type": "result", "subtype": "success", "result": json.dumps(self.answer())}
        for events in ([], [dict(good, is_error=True)], [good, good], [{"type": "result", "subtype": "error"}]):
            with self.assertRaises(d.Refused):
                d.parse_stream("\n".join(map(json.dumps, events)), self.request())

    def test_process_timeout(self):
        with self.assertRaisesRegex(d.Refused, "TIMEOUT"):
            d.run_bounded([sys.executable, "-c", "import time; time.sleep(5)"], b"", self.root, os.environ.copy(), .2)

    def test_process_output_limit(self):
        with self.assertRaisesRegex(d.Refused, "OUTPUT_LIMIT"):
            d.run_bounded([sys.executable, "-c", "print('x'*100000)"], b"", self.root, os.environ.copy(), 5, 1024)

    @unittest.skipIf(os.name == "nt", "Cursor process group is owned by the WSL backend")
    def test_timeout_kills_child_after_parent_exit(self):
        import time
        child = self.root / "child.py"
        child.write_text("import time\nfrom pathlib import Path\ntime.sleep(0.7)\nPath('child-survived').write_text('bad')\n")
        parent = self.root / "parent.py"
        parent.write_text("import subprocess, sys\nsubprocess.Popen([sys.executable, 'child.py'])\n")
        with self.assertRaisesRegex(d.Refused, "TIMEOUT"):
            d.run_bounded([sys.executable, str(parent)], b"", self.root, os.environ.copy(), .2)
        time.sleep(.8)
        self.assertFalse((self.root / "child-survived").exists())

    def test_process_nonzero_and_unicode_stdin(self):
        code, out, _ = d.run_bounded([sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.exit(7)"], "привет".encode(), self.root, os.environ.copy(), 5)
        self.assertEqual((code, out), (7, "привет"))

    @unittest.skipIf(os.name == "nt", "Backend lock is WSL-owned; Windows callers use it over bridge")
    def test_shared_lock(self):
        with d.exclusive_lock(self.root / "test.lock"):
            with self.assertRaisesRegex(d.Refused, "BUSY"):
                with d.exclusive_lock(self.root / "test.lock"):
                    pass
        with d.exclusive_lock(self.root / "test.lock"):
            pass


class ModelPolicyTests(unittest.TestCase):
    ROSTER = [
        "composer-2.5",
        "composer-2.5-fast",
        "cursor-grok-4.6-high",
        "gpt-5.6-sol-medium",
    ]

    def _patch_roster(self, roster):
        return patch.object(d, "available_models", return_value=(roster, None))

    def test_default_preferred(self):
        with self._patch_roster(self.ROSTER):
            model, decision = d.resolve_model(None)
        self.assertEqual(model, "composer-2.5")
        self.assertEqual(decision["reason"], "default_preferred")

    def test_fast_suffix_stripped(self):
        with self._patch_roster(self.ROSTER):
            model, decision = d.resolve_model("composer-2.5-fast")
        self.assertEqual(model, "composer-2.5")
        self.assertEqual(decision["reason"], "fast_suffix_stripped")

    def test_cursor_native_explicit(self):
        with self._patch_roster(self.ROSTER):
            model, decision = d.resolve_model("cursor-grok-4.6-high")
        self.assertEqual(model, "cursor-grok-4.6-high")
        self.assertEqual(decision["reason"], "cursor_native_explicit")

    def test_explicit_other_vendor_available(self):
        with self._patch_roster(self.ROSTER):
            model, decision = d.resolve_model("gpt-5.6-sol-medium")
        self.assertEqual(model, "gpt-5.6-sol-medium")
        self.assertEqual(decision["reason"], "explicit_other_vendor")

    def test_explicit_other_vendor_unavailable(self):
        with self._patch_roster(["composer-2.5", "cursor-grok-4.6-high"]):
            model, decision = d.resolve_model("gpt-5.6-sol-medium")
        self.assertEqual(model, "composer-2.5")
        self.assertEqual(decision["reason"], "requested_unavailable_fallback")

    def test_unreadable_policy_builtin_fallback(self):
        with patch.object(d, "_POLICY_PATH", Path("/nonexistent/model-policy.json")):
            policy = d.load_policy()
        self.assertEqual(policy["policy_source"], "builtin_fallback")
        self.assertEqual(policy["preferred"][0], "composer-2.5")


class WindowsBridgeRoutingTests(unittest.TestCase):
    def _nt(self):
        return patch.object(d.os, "name", "nt")

    def test_auto_uses_local_when_mcp_portal_cli_set(self):
        with self._nt(), patch.dict(os.environ, {"MCP_PORTAL_CLI": "C:\\stub\\cli.py"}, clear=False):
            self.assertFalse(d.execution_uses_wsl_bridge("auto"))

    def test_native_cli_on_path_detects_which_hit(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            cli = Path(tmp.name)
        cli.write_text("stub", encoding="utf-8")
        try:
            with patch.object(d.shutil, "which", side_effect=lambda name: str(cli) if name == "cursor-agent" else None):
                self.assertTrue(d._native_cli_on_path())
        finally:
            cli.unlink(missing_ok=True)

    def test_auto_uses_local_when_native_cli_on_path(self):
        with self._nt(), patch.object(d, "_native_cli_on_path", return_value=True):
            self.assertFalse(d.execution_uses_wsl_bridge("auto"))

    def test_auto_uses_wsl_when_no_local_cli(self):
        with self._nt():
            env = {k: v for k, v in os.environ.items() if k not in ("MCP_PORTAL_CLI", "MCP_PORTAL_BACKEND")}
            with patch.dict(os.environ, env, clear=True):
                with patch.object(d.shutil, "which", return_value=None):
                    self.assertTrue(d.execution_uses_wsl_bridge("auto"))

    def test_mcp_portal_backend_forces_wsl(self):
        with self._nt(), patch.dict(os.environ, {"MCP_PORTAL_BACKEND": "wsl"}, clear=False):
            with patch.object(d.shutil, "which", return_value="C:\\Tools\\cursor-agent.exe"):
                self.assertTrue(d.execution_uses_wsl_bridge("auto"))

    def test_mcp_portal_backend_forces_local(self):
        with self._nt(), patch.dict(os.environ, {"MCP_PORTAL_BACKEND": "local"}, clear=False):
            with patch.object(d.shutil, "which", return_value=None):
                self.assertFalse(d.execution_uses_wsl_bridge("auto"))

    def test_linux_auto_never_uses_wsl_bridge(self):
        with patch.object(d.os, "name", "posix"):
            self.assertFalse(d.execution_uses_wsl_bridge("auto"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
