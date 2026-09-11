"""Installer tests use disposable fixtures, never user configuration."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
import threading
from unittest.mock import patch

from mcp_portal import install_router as installer


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.source = self.root / 'source'
        (self.source / 'docs' / 'skills' / 'cursor-bulk-reader').mkdir(parents=True)
        (self.source / 'docs/skills/cursor-bulk-reader/SKILL.md').write_text('---\nname: cursor-bulk-reader\n---\nFixture skill')
        (self.source / 'src' / 'mcp_portal').mkdir(parents=True)
        (self.source / 'src/mcp_portal/router.py').write_text('# Fixture')

    def prepare(self, client='claude', **kwargs):
        options = dict(home=self.home, client=client, python='/fixture/python', source=self.source,
                       state_root=self.root / 'private', shell='bash', command_shell='bash')
        options.update(kwargs)
        return installer.prepare(**options)

    def config(self, client='claude'):
        if client == 'claude':
            return self.home / ('.' + 'claude') / 'settings.json'
        return self.home / ('.' + client) / 'hooks.json'

    def _claude_skill(self):
        return self.home / ('.' + 'claude') / 'skills' / 'cursor-bulk-reader' / 'SKILL.md'

    def test_additive_all_clients_and_exact_rollback(self):
        for client in ('claude', 'codex', 'cursor'):
            with self.subTest(client=client):
                path = self.config(client)
                path.parent.mkdir(parents=True, exist_ok=True)
                event = 'preToolUse' if client == 'cursor' else 'PreToolUse'
                previous_entry = {'command': 'existing', 'matcher': 'Read'} if client == 'cursor' else {'matcher': 'Read', 'hooks': [{'type': 'command', 'command': 'existing'}]}
                previous = {'unknown': {'keep': [3, 2, 1]}, 'hooks': {event: [previous_entry], 'other': []}}
                before = json.dumps(previous, separators=(',', ':')).encode()
                path.write_bytes(before)
                transaction = self.prepare(client)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(installer.report(transaction)['status'], 'prepared')
                installer.operate(transaction)
                after = json.loads(path.read_bytes())
                self.assertEqual(after['unknown'], previous['unknown'])
                self.assertEqual(after['hooks'][event][0], previous_entry)
                self.assertEqual(len(after['hooks'][event]), 2)
                second = self.prepare(client)
                self.assertEqual(installer.report(second)['changes'], [])
                installer.operate(transaction, rollback=True)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(installer.report(transaction)['status'], 'rolled_back')

    def test_new_files_removed_on_rollback(self):
        transaction = self.prepare()
        installer.operate(transaction)
        self.assertTrue(self.config().exists())
        installer.operate(transaction, rollback=True)
        self.assertFalse(self.config().exists())
        self.assertFalse(self._claude_skill().exists())

    def test_preimage_conflict_makes_no_other_changes(self):
        transaction = self.prepare()
        path = self.config()
        path.parent.mkdir(parents=True)
        path.write_text('{"concurrent":true}')
        with self.assertRaises(installer.Conflict):
            installer.operate(transaction)
        self.assertEqual(json.loads(path.read_text()), {'concurrent': True})
        self.assertFalse((self.home / ('.' + 'claude') / 'skills').exists())

    def test_rollback_refuses_intervening_edit(self):
        transaction = self.prepare()
        installer.operate(transaction)
        self.config().write_text('{"concurrent":true}')
        with self.assertRaises(installer.Conflict):
            installer.operate(transaction, rollback=True)
        self.assertTrue(self._claude_skill().exists())

    def test_different_existing_router_refused(self):
        for dialect in ('cmd', 'bash', 'powershell'):
            old = installer.candidate_config(None, 'codex', installer.command('/old/python', '/old/router.py', 'codex', 'bash', dialect))
            with self.assertRaises(installer.Conflict):
                installer.candidate_config(old, 'codex', 'different')

    def test_exact_entry_does_not_hide_duplicate_or_conflict(self):
        for client in ('claude', 'codex', 'cursor'):
            hook = installer.command('/python', '/source/src/mcp_portal/router.py', client, 'bash', 'bash')
            current = json.loads(installer.candidate_config(None, client, hook))
            event = 'preToolUse' if client == 'cursor' else 'PreToolUse'
            current['hooks'][event] *= 2
            with self.assertRaises(installer.Conflict):
                installer.candidate_config(json.dumps(current).encode(), client, hook)
            changed = json.loads(installer.candidate_config(None, client, hook + ' --extra'))
            current['hooks'][event][1] = changed['hooks'][event][0]
            with self.assertRaises(installer.Conflict):
                installer.candidate_config(json.dumps(current).encode(), client, hook)

    def test_two_transactions_share_destination_lock(self):
        first = self.prepare()
        second = self.prepare(state_root=self.root / 'different-private')
        entered, release = threading.Event(), threading.Event()
        failures = []
        original = installer.atomic_write
        def paused(path, data, expected):
            if path == self.config() and threading.current_thread().name == 'first-installer':
                entered.set()
                if not release.wait(15):
                    raise RuntimeError('fixture synchronization timeout')
            return original(path, data, expected)
        def run_first():
            try:
                installer.operate(first)
            except Exception as error:
                failures.append(type(error).__name__)
        with patch.object(installer, 'atomic_write', paused):
            thread = threading.Thread(target=run_first, name='first-installer')
            thread.start()
            try:
                self.assertTrue(entered.wait(15))
                self.assertFalse(self.config().exists())  # Same preimage is still available.
                with self.assertRaises(installer.LockConflict):
                    installer.operate(second)
            finally:
                release.set()
                thread.join(15)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(installer.report(first)['status'], 'applied')
        self.assertEqual(installer.report(second)['status'], 'prepared')
        self.assertTrue(all(x['state'] == 'ABSENT' for x in installer.report(first)['locks']))

    def test_stale_lock_is_liveness_unverified(self):
        transaction = self.prepare()
        lock = self.config().with_name('.settings.json.cursor-router.lock')
        lock.mkdir(parents=True)
        states = installer.report(transaction)['locks']
        self.assertIn({'path': os.path.normcase(str(lock.resolve())), 'state': 'LIVENESS_UNVERIFIED'}, states)
        with self.assertRaises(installer.LockConflict):
            installer.operate(transaction)
        self.assertTrue(lock.exists())

    def test_existing_skill_refused(self):
        path = self._claude_skill()
        path.parent.mkdir(parents=True)
        path.write_text('foreign skill')
        with self.assertRaises(installer.Conflict):
            self.prepare()
        self.assertEqual(path.read_text(), 'foreign skill')

    def test_reports_do_not_include_config_bodies(self):
        path = self.config()
        path.parent.mkdir(parents=True)
        path.write_text('{"credential_fixture":"DO_NOT_REPORT_THIS"}')
        report = json.dumps(installer.report(self.prepare()))
        self.assertNotIn('DO_NOT_REPORT_THIS', report)
        self.assertNotIn('credential_fixture', report)

    def test_cmd_quoting_rejects_expansion_characters(self):
        for path in ('C:/%TEMP%/python.exe', 'C:/bang!/python.exe', 'C:/quote"/python.exe'):
            with self.assertRaises(installer.Conflict):
                installer.command(path, 'router.py', 'cursor', 'powershell', 'cmd')
        self.assertIn('"C:/Program Files/python.exe"', installer.command('C:/Program Files/python.exe', 'router.py', 'cursor', 'powershell', 'cmd'))

    @unittest.skipUnless(os.name == 'nt', 'Native Windows ACL preservation')
    def test_windows_acl_fixture(self):
        path = self.root / 'acl-fixture'
        path.write_bytes(b'before')
        def acl():
            script = "$ErrorActionPreference='Stop'; Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'); (Get-Acl -LiteralPath $env:CURSOR_ROUTER_TEST_ACL).Sddl"
            return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                   installer.base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
                                  env=dict(os.environ, CURSOR_ROUTER_TEST_ACL=str(path)), capture_output=True, check=True).stdout
        inherited_acl = acl()
        installer.atomic_write(path, b'before', b'before')
        # Set-Acl may mark the inherited DACL AI (auto-inheritance processed).
        # Ignore only that marker; owner/group, protection and every ACE stay exact.
        self.assertEqual(acl().replace(b'D:AI', b'D:'), inherited_acl.replace(b'D:AI', b'D:'))
        identity = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, check=True)
        sid = next(installer.csv.reader(installer.io.StringIO(identity.stdout)))[1]
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', '*' + sid + ':F'], capture_output=True, check=True)
        before_acl = acl()
        original = installer.subprocess.run
        checked = []
        def inspect_empty_then_apply(*args, **kwargs):
            if 'CURSOR_ROUTER_ACL_DEST' in kwargs.get('env', {}):
                destination = Path(kwargs['env']['CURSOR_ROUTER_ACL_DEST'])
                self.assertEqual(destination.read_bytes(), b'')
                checked.append(True)
            return original(*args, **kwargs)
        try:
            with patch.object(installer.subprocess, 'run', inspect_empty_then_apply):
                installer.atomic_write(path, b'after', b'before')
        except subprocess.CalledProcessError as error:
            self.fail(error.stderr.decode('utf-8', errors='replace'))
        self.assertEqual(path.read_bytes(), b'after')
        self.assertEqual(checked, [True])
        self.assertEqual(acl(), before_acl)

    def test_transaction_integrity_and_operation_lock(self):
        transaction = self.prepare()
        (transaction / 'operation.lock').mkdir()
        with self.assertRaises(installer.Conflict):
            installer.operate(transaction)
        (transaction / 'operation.lock').rmdir()
        path = transaction / 'transaction.json'
        record = json.loads(path.read_text())
        record['entries'][0]['before_sha256'] = 'wrong'
        path.write_text(json.dumps(record))
        with self.assertRaises(installer.Conflict):
            installer.operate(transaction)

    def test_interrupted_apply_recovery(self):
        transaction = self.prepare()
        original = installer.atomic_write
        def interrupted(path, data, expected):
            original(path, data, expected)
            if path == self.config():
                raise OSError('fixture interruption after replacement')
        with patch.object(installer, 'atomic_write', interrupted):
            with self.assertRaises(OSError):
                installer.operate(transaction)
        self.assertTrue(self.config().exists())
        installer.operate(transaction, rollback=True)
        self.assertFalse(self.config().exists())

    @unittest.skipIf(os.name == 'nt', 'Windows ACL is applied through icacls')
    def test_private_transaction_and_symlink_refusal(self):
        transaction = self.prepare()
        self.assertEqual(transaction.stat().st_mode & 0o777, 0o700)
        path = self.config()
        path.parent.mkdir(parents=True)
        path.symlink_to(self.source / 'router.py')
        with self.assertRaises(installer.Conflict):
            installer.operate(transaction)


if __name__ == '__main__':
    unittest.main()
