import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from mcp_portal import router


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'large file.txt').write_text('example\n' * 351, encoding='utf-8')
        (self.root / 'small.txt').write_text('example\n' * 350, encoding='utf-8')

    def payload(self, **data):
        return {'cwd': str(self.root), 'tool_name': 'Read', 'tool_input': data}

    def test_full_read_is_denied_before_contents(self):
        enforce = {'claude-wsl': 'deny'}
        health = {'ok': True, 'checked_at': '2099-01-01T00:00:00Z'}
        with self._portal_env(enforce=enforce, health=health):
            result = router.route(self.payload(file_path='large file.txt'), 'claude', 'bash')
        self.assertEqual(result['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertIn('mcp_portal.bulk_read', result['hookSpecificOutput']['permissionDecisionReason'])
        self.assertNotIn('example\n', json.dumps(result))

    def _portal_env(self, enforce=None, health=None):
        home = self.root / 'portal-home'
        home.mkdir(exist_ok=True)
        if enforce is not None:
            (home / 'enforce.json').write_text(json.dumps(enforce), encoding='utf-8')
        if health is not None:
            (home / 'health.json').write_text(json.dumps(health), encoding='utf-8')
        return patch.dict(os.environ, {'MCP_PORTAL_HOME': str(home)})

    def test_targeted_reads_allowed(self):
        for part in ({'offset': 4}, {'limit': 12}, {'start_line': 10, 'end_line': 20}):
            self.assertEqual(router.route(self.payload(file_path='large file.txt', **part), 'codex', 'bash'), {})

    def test_small_missing_allowed(self):
        for path in ('small.txt', 'missing.txt'):
            self.assertEqual(router.route(self.payload(file_path=path), 'claude', 'bash'), {})

    def test_shell_quotes_multifile_and_commands(self):
        self.assertEqual(router.shell_paths('cat "large file.txt" small.txt'), ['large file.txt', 'small.txt'])
        self.assertEqual(router.shell_paths('pwd; cat "large file.txt" && cat small.txt'), ['large file.txt', 'small.txt'])
        self.assertEqual(router.shell_paths('cat large.txt; echo ok > status.txt'), ['large.txt'])
        self.assertEqual(router.shell_paths('cat -n large.txt'), ['large.txt'])
        self.assertEqual(router.shell_paths("bash -lc 'cat large.txt'"), ['large.txt'])
        self.assertEqual(router.shell_paths('tail -n +1 large.txt'), ['large.txt'])
        self.assertEqual(router.shell_paths('tail --lines=+1 large.txt'), ['large.txt'])
        self.assertEqual(router.shell_paths('head --lines=-10 large.txt'), ['large.txt'])
        self.assertEqual(router.shell_paths('cd nested && cat large.txt', str(self.root)), [str(self.root / 'nested/large.txt')])

    def test_shell_targeted_and_nonread_allowed(self):
        for command in ('head a', 'tail a', 'head -n 12 a', 'tail -20 a', 'cat a | grep x', 'cat a > b', 'git status'):
            self.assertEqual(router.shell_paths(command), [])

    def test_oversized_file_cannot_hide_later_lines(self):
        path = self.root / 'long.txt'
        path.write_text('a' * 150000 + '\n' * 400, encoding='utf-8')
        self.assertEqual(router.large_paths(['long.txt'], self.root), [path])

    def test_cursor_before_read_shape(self):
        payload = {'hook_event_name': 'beforeReadFile', 'cwd': str(self.root), 'file_path': 'large file.txt'}
        enforce = {'cursor-wsl': 'deny'}
        health = {'ok': True, 'checked_at': '2099-01-01T00:00:00Z'}
        with self._portal_env(enforce=enforce, health=health):
            self.assertEqual(router.route(payload, 'cursor', 'bash')['permission'], 'deny')

    def test_codex_command_shape(self):
        payload = {'tool_name': 'Bash', 'cwd': str(self.root), 'tool_input': {'command': 'cat "large file.txt"'}}
        enforce = {'codex-wsl': 'deny'}
        health = {'ok': True, 'checked_at': '2099-01-01T00:00:00Z'}
        with self._portal_env(enforce=enforce, health=health):
            self.assertEqual(router.route(payload, 'codex', 'bash')['hookSpecificOutput']['permissionDecision'], 'deny')
            payload['cwd'] = str(self.root.parent)
            payload['tool_input']['workdir'] = str(self.root)
            self.assertEqual(router.route(payload, 'codex', 'bash')['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_no_recursive_routing(self):
        with patch.dict(os.environ, {'CURSOR_DELEGATE_DEPTH': '1'}):
            self.assertEqual(router.route(self.payload(file_path='large file.txt'), 'claude', 'bash'), {})

    def test_invocation_argument_quoting(self):
        command = router.invocation([self.root / 'large file.txt'], 'powershell')
        self.assertTrue(command.startswith('& '))
        self.assertIn("'large file.txt'", command)

    @unittest.skipUnless(os.name == 'nt', 'PowerShell parser runs natively on Windows')
    def test_powershell_real_parser(self):
        self.assertEqual(router.powershell_paths("Get-Content 'a.txt','b.txt'"), ['a.txt', 'b.txt'])
        self.assertEqual(router.powershell_paths("Get-Content -LiteralPath a.txt -Encoding UTF8"), ['a.txt'])
        for command in ("Get-Content -LiteralPath 'large file.txt' -Raw", "gc 'large file.txt'", "type 'large file.txt'"):
            self.assertEqual(router.powershell_paths(command), ['large file.txt'])
        for command in ("Get-Content 'large file.txt' -TotalCount 10", "Get-Content 'large file.txt' | Select-Object -First 10", 'Write-Output 12'):
            self.assertEqual(router.powershell_paths(command), [])

    def test_hook_executable_json(self):
        import sys
        env = os.environ.copy()
        env['MCP_PORTAL_HOME'] = str(self.root / 'portal-home')
        (self.root / 'portal-home').mkdir()
        health = {'ok': True, 'checked_at': '2099-01-01T00:00:00Z'}
        (self.root / 'portal-home' / 'health.json').write_text(json.dumps(health), encoding='utf-8')
        enforce = {'claude-wsl': 'deny'}
        (self.root / 'portal-home' / 'enforce.json').write_text(json.dumps(enforce), encoding='utf-8')
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
        result = subprocess.run([sys.executable, '-m', 'mcp_portal.router', '--client', 'claude', '--shell', 'bash', '--receipt-dir', str(self.root / 'receipts')],
                                input=json.dumps(self.payload(file_path='large file.txt')), text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')
        receipt = json.loads(next((self.root / 'receipts').glob('*.json')).read_text())
        self.assertEqual(receipt['decision'], 'deny')
        self.assertIn(receipt['route_id'], result.stdout)
        self.assertNotIn('example', json.dumps(receipt))

    def test_threshold_from_environment(self):
        small = self.root / 'medium.txt'
        small.write_text('line\n' * 360, encoding='utf-8')
        with patch.dict(os.environ, {'MCP_PORTAL_MIN_LINES': '400'}):
            self.assertEqual(router.route(self.payload(file_path='medium.txt'), 'claude', 'bash'), {})
        enforce = {'claude-wsl': 'deny'}
        health = {'ok': True, 'checked_at': '2099-01-01T00:00:00Z'}
        with self._portal_env(enforce=enforce, health=health), patch.dict(os.environ, {'MCP_PORTAL_MIN_LINES': '300'}):
            self.assertEqual(router.route(self.payload(file_path='medium.txt'), 'claude', 'bash')['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_warn_mode_additional_context_only(self):
        enforce = {'claude-wsl': 'warn'}
        with self._portal_env(enforce=enforce):
            result = router.route(self.payload(file_path='large file.txt'), 'claude', 'bash')
        out = result['hookSpecificOutput']
        self.assertIn('additionalContext', out)
        self.assertNotIn('permissionDecision', out)
        self.assertIn('mcp__mcp-portal__bulk_read', out['additionalContext'])

    def test_deny_mode_permission_decision(self):
        enforce = {'claude-wsl': 'deny'}
        health = {'ok': True, 'checked_at': '2099-01-01T00:00:00Z'}
        with self._portal_env(enforce=enforce, health=health):
            result = router.route(self.payload(file_path='large file.txt'), 'claude', 'bash')
        self.assertEqual(result['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_deny_without_fresh_health_downgrades_to_warn(self):
        enforce = {'claude-wsl': 'deny'}
        with self._portal_env(enforce=enforce):
            result = router.route(self.payload(file_path='large file.txt'), 'claude', 'bash')
        self.assertIn('additionalContext', result['hookSpecificOutput'])
        self.assertNotIn('permissionDecision', result['hookSpecificOutput'])

    def test_malformed_enforce_json_warns(self):
        home = self.root / 'portal-home'
        home.mkdir()
        (home / 'enforce.json').write_text('{not json', encoding='utf-8')
        with patch.dict(os.environ, {'MCP_PORTAL_HOME': str(home)}):
            result = router.route(self.payload(file_path='large file.txt'), 'claude', 'bash')
        self.assertIn('additionalContext', result['hookSpecificOutput'])

    def test_garbage_stdin_prints_nothing(self):
        import sys
        env = os.environ.copy()
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
        result = subprocess.run(
            [sys.executable, '-m', 'mcp_portal.router', '--client', 'claude', '--shell', 'bash'],
            input='not-json{{{', text=True, capture_output=True, env=env,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
