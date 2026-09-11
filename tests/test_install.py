"""Contract for install.py: the edit is additive, and it leaves the file looking as it found it.

The formatting case is not cosmetic. `.codex/hooks.json` ships minified on one line; the first
version of the renderer pretty-printed it, turning a one-entry addition into a 925-line diff. An
edit nobody can review is not an additive edit.
"""
import json
import unittest
from pathlib import Path
import sys
import tempfile

from mcp_portal import install  # noqa: E402


class RenderJson(unittest.TestCase):
    def test_minified_stays_minified(self):
        original = b'{"hooks":{"PreToolUse":[{"matcher":"Bash"}]}}'
        out = install.render_json(json.loads(original), original)
        self.assertEqual(out.count(b"\n"), 0)
        self.assertIn(b'":', out)

    def test_pretty_stays_pretty(self):
        original = b'{\n  "hooks": {\n    "PreToolUse": []\n  }\n}\n'
        out = install.render_json(json.loads(original), original)
        self.assertGreater(out.count(b"\n"), 3)
        self.assertTrue(out.endswith(b"\n"))

    def test_four_space_indent_is_preserved(self):
        original = b'{\n    "a": {\n        "b": 1\n    }\n}\n'
        out = install.render_json(json.loads(original), original)
        self.assertIn(b'\n    "a"', out)


class Transform(unittest.TestCase):
    def test_mcp_entry_is_added_once_then_noop(self):
        original = b'{"mcpServers":{"other":{"command":"x"}}}'
        action, after, _ = install.transform("claude-mcp", original, replace=False)
        self.assertEqual(action, "added")
        data = json.loads(after)
        self.assertIn("other", data["mcpServers"])
        self.assertIn("mcp-portal", data["mcpServers"])
        again, _, _ = install.transform("claude-mcp", after, replace=False)
        self.assertEqual(again, "noop")

    def test_differing_entry_is_a_conflict_not_an_overwrite(self):
        original = json.dumps({"mcpServers": {"mcp-portal": {"command": "somethingelse"}}}).encode()
        action, after, detail = install.transform("claude-mcp", original, replace=False)
        self.assertEqual(action, "conflict")
        self.assertEqual(after, original)
        self.assertTrue(detail)

    def test_stale_router_hook_is_migrated_not_duplicated(self):
        original = json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "Read|Bash", "hooks": [{"type": "command",
                                                "command": "python3 /x/cursor_delegate/router.py --client claude"}]},
        ]}}).encode()
        action, after, detail = install.transform("claude-hook", original, replace=False)
        self.assertEqual(action, "migrated")
        entries = json.loads(after)["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 1)
        self.assertNotIn("cursor_delegate", json.dumps(entries))
        self.assertIn("mcp_portal.router", json.dumps(entries))
        self.assertIn("stale", detail)

    def test_unrelated_keys_and_entries_survive(self):
        original = json.dumps({"otherKey": [1, 2], "hooks": {
            "PreToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "keep-me"}]}],
            "Stop": [{"matcher": "*"}],
        }}).encode()
        _, after, _ = install.transform("claude-hook", original, replace=False)
        data = json.loads(after)
        self.assertEqual(data["otherKey"], [1, 2])
        self.assertIn("Stop", data["hooks"])
        self.assertIn("keep-me", json.dumps(data["hooks"]["PreToolUse"]))

    def test_enable_list_appends_without_reordering(self):
        original = b'{"enabledMcpjsonServers":["a","b"]}'
        _, after, _ = install.transform("claude-enable", original, replace=False)
        self.assertEqual(json.loads(after)["enabledMcpjsonServers"], ["a", "b", "mcp-portal"])

    def test_codex_toml_section_is_appended_and_parses(self):
        original = b'[mcp_servers.other]\ncommand = "x"\n'
        action, after, _ = install.transform("codex-mcp", original, replace=False)
        self.assertEqual(action, "added")
        self.assertTrue(after.startswith(original))
        import tomllib
        parsed = tomllib.loads(after.decode("utf-8"))
        self.assertIn("mcp-portal", parsed["mcp_servers"])
        self.assertIn("other", parsed["mcp_servers"])


class CanonicalRoot(unittest.TestCase):
    """A registration must never name a worktree: the path dies when the worktree is removed."""

    def test_worktree_resolves_to_the_trunk(self):
        wt = Path("/tmp/example-repo") / ('.' + 'claude') / "worktrees" / "some-name"
        self.assertEqual(install.canonical_root(wt), Path("/tmp/example-repo"))

    def test_a_plain_checkout_is_its_own_root(self):
        repo = Path("/tmp/example-repo")
        self.assertEqual(install.canonical_root(repo), repo)

    def test_a_claude_directory_that_is_not_a_worktree_is_left_alone(self):
        repo = Path("/srv") / ('.' + 'claude') / "something" / "else"
        self.assertEqual(install.canonical_root(repo), repo)

    def test_the_registered_paths_point_at_the_trunk(self):
        self.assertNotIn("worktrees", install.hook_command("claude"))
        self.assertNotIn("worktrees", json.dumps(install.mcp_server_entry(wsl=True)))


class Replace(unittest.TestCase):
    """--replace must replace. Appending beside the old entry leaves two gates on every read."""

    def _settings_with(self, command):
        return json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "Read|Bash", "hooks": [{"type": "command", "command": command}]},
        ]}}).encode()

    def test_claude_hook_replace_leaves_exactly_one_entry(self):
        stale = "bash /old/worktree/" + "." + "claude" + "/hooks/mcp-portal-read-gate.sh claude bash"
        action, after, detail = install.transform("claude-hook", self._settings_with(stale), replace=True)
        entries = json.loads(after)["hooks"]["PreToolUse"]
        self.assertEqual(action, "replaced")
        self.assertEqual(len(entries), 1)
        self.assertNotIn("/old/worktree/", json.dumps(entries))
        self.assertIn("repointed", detail)

    def test_codex_hook_replace_leaves_exactly_one_entry(self):
        stale = "bash /old/worktree/" + "." + "claude" + "/hooks/mcp-portal-read-gate.sh codex bash"
        action, after, _ = install.transform("codex-hook", self._settings_with(stale), replace=True)
        entries = json.loads(after)["hooks"]["PreToolUse"]
        self.assertEqual(action, "replaced")
        self.assertEqual(len(entries), 1)

    def test_replace_does_not_disturb_other_hooks(self):
        doc = json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "Write", "hooks": [{"type": "command", "command": "keep-me"}]},
            {"matcher": "Read|Bash", "hooks": [{"type": "command", "command": "bash /old/mcp-portal-read-gate.sh claude bash"}]},
        ]}}).encode()
        _, after, _ = install.transform("claude-hook", doc, replace=True)
        entries = json.loads(after)["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 2)
        self.assertIn("keep-me", json.dumps(entries))


class Symlink(unittest.TestCase):
    def test_symlink_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.json"
            real.write_text("{}", encoding="utf-8")
            link = Path(tmp) / "link.json"
            link.symlink_to(real)
            with self.assertRaises(install.Conflict):
                install.read(link)


if __name__ == "__main__":
    unittest.main()
