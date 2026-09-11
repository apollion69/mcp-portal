"""Prepare private, additive router transactions. Preparation never changes clients.

Locks coordinate this installer only, not arbitrary external settings writers.
An abrupt process termination may leave operation.lock or destination lock
directories. Their presence is LIVENESS_UNVERIFIED, not proof of a live process.
Recovery is manual: stop cooperating installers; verify recorded PID ownership
and that no installer remains alive; preserve the private journal and compare
each destination with its before/after hash; remove only the verified stale
lock directories shown by status; then run rollback for a partial transaction.
Never remove a lock merely because an observation timed out. Exception-recovery
tests do not prove recovery after a hard process kill or power failure.
"""
import argparse
import base64
import csv
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import uuid

OWNER = 'cursor-bulk-reader'


class Conflict(Exception):
    pass


class LockConflict(Conflict):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def read(path):
    if path.is_symlink():
        raise Conflict('Symlink destination refused')
    return path.read_bytes() if path.exists() else None


def private_directory(path):
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    if os.name == 'nt':
        identity = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, check=True)
        sid = next(csv.reader(io.StringIO(identity.stdout)))[1]
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F'],
                       capture_output=True, check=True)
    else:
        path.chmod(0o700)


def atomic_write(path, data, expected):
    if read(path) != expected:
        raise Conflict('Preimage changed')
    path.parent.mkdir(parents=True, exist_ok=True)
    if data is None:
        path.unlink()
        return
    fd, temporary = tempfile.mkstemp(prefix='.cursor-router-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            if path.exists() and os.name != 'nt':
                os.chmod(temporary, path.stat().st_mode & 0o777)
            elif path.exists():
                env = dict(os.environ, CURSOR_ROUTER_ACL_SOURCE=str(path), CURSOR_ROUTER_ACL_DEST=temporary)
                script = "$ErrorActionPreference='Stop'; Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'); Get-Acl -LiteralPath $env:CURSOR_ROUTER_ACL_SOURCE | Set-Acl -LiteralPath $env:CURSOR_ROUTER_ACL_DEST"
                subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
                               env=env, capture_output=True, check=True)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if read(path) != expected:
            raise Conflict('Preimage changed before replacement')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(python, router, client, shell, command_shell):
    args = [Path(python).as_posix() if command_shell == 'bash' else str(python),
            '-m', 'mcp_portal.router', '--client', client, '--shell', shell]
    if command_shell == 'powershell':
        return '& ' + ' '.join("'" + x.replace("'", "''") + "'" for x in args)
    if command_shell == 'cmd':
        # cmd expands percent and delayed-expansion markers even inside quotes.
        if any(any(c in x for c in '%!\r\n"') for x in args):
            raise Conflict('Unsupported cmd path characters')
        return ' '.join('"' + x + '"' for x in args)
    return shlex.join(args)


def candidate_config(before, client, hook_command):
    config = json.loads(before.decode('utf-8-sig')) if before is not None else {}
    if not isinstance(config, dict):
        raise Conflict('Configuration must be an object')
    hooks = config.setdefault('hooks', {})
    if not isinstance(hooks, dict):
        raise Conflict('Hooks must be an object')
    event = 'preToolUse' if client == 'cursor' else 'PreToolUse'
    entries = hooks.setdefault(event, [])
    if not isinstance(entries, list):
        raise Conflict('Hook event must be an array')
    if client == 'cursor':
        entry = {'command': hook_command, 'matcher': 'Read|Shell'}
        config.setdefault('version', 1)
    else:
        entry = {'matcher': 'Read|Bash', 'hooks': [{'type': 'command', 'command': hook_command}]}
    # Refuse a previous router configuration instead of silently adding a second hook.
    owned = []
    for existing in entries:
        if isinstance(existing, dict):
            nested = existing.get('hooks', [])
            if not isinstance(nested, list):
                raise Conflict('Existing hook group malformed')
            commands = [existing.get('command', '')] + [h.get('command', '') for h in nested if isinstance(h, dict)]
            owned.extend(existing for c in commands if isinstance(c, str) and 'mcp_portal.router' in c and '--client' in c and client in c)
    if len(owned) > 1 or owned and owned[0] != entry:
        raise Conflict('Duplicate or different router entry already installed')
    if len(owned) == 1:
        return before  # Byte-identical idempotence only after ownership audit.
    entries.append(entry)
    return (json.dumps(config, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def prepare(home, client, python, source, state_root, shell, command_shell, skill_root=None):
    home, source, state_root = Path(home).absolute(), Path(source).absolute(), Path(state_root).absolute()
    router = source / 'src' / 'mcp_portal' / 'router.py'
    skill = source / 'docs' / 'skills' / 'cursor-bulk-reader' / 'SKILL.md'
    if not router.is_file() or not skill.is_file():
        raise Conflict('Router or skill source missing')
    config_path = (home / ('.' + 'claude') / 'settings.json' if client == 'claude'
                   else home / ('.' + client) / 'hooks.json')
    skill_root = Path(skill_root).absolute() if skill_root else home / ('.agents' if client == 'codex' else '.' + client) / 'skills'
    skill_path = skill_root / OWNER / 'SKILL.md'
    old_config, old_skill = read(config_path), read(skill_path)
    new_config = candidate_config(old_config, client, command(python, str(router), client, shell, command_shell))
    new_skill = skill.read_bytes()
    if old_skill is not None and old_skill != new_skill:
        raise Conflict('Existing skill differs; manual review required')
    entries = []
    for path, before, after in [(config_path, old_config, new_config), (skill_path, old_skill, new_skill)]:
        if before != after:
            entries.append({'path': str(path), 'before': base64.b64encode(before).decode() if before is not None else None,
                            'after': base64.b64encode(after).decode(), 'before_sha256': digest(before), 'after_sha256': digest(after)})
    transaction = state_root / uuid.uuid4().hex
    private_directory(transaction)
    record = {'version': 1, 'client': client, 'status': 'prepared', 'applied': [], 'entries': entries,
              'trust': 'UNRESOLVED' if client == 'codex' else 'NOT_ASSESSED'}
    (transaction / 'transaction.json').write_text(json.dumps(record), encoding='utf-8')
    return transaction


def unpack(entry, side):
    value = entry[side]
    body = base64.b64decode(value, validate=True) if value is not None else None
    if digest(body) != entry[side + '_sha256']:
        raise Conflict('Snapshot integrity mismatch')
    return body


def save_record(path, record):
    atomic_write(path, json.dumps(record).encode('utf-8'), read(path))


def destination_locks(entries):
    # Sibling locks are shared even when transactions use different state roots.
    paths = {os.path.normcase(str(Path(e['path']).resolve())) for e in entries}
    return [Path(p).with_name('.' + Path(p).name + '.cursor-router.lock') for p in sorted(paths)]


@contextmanager
def locked_destinations(entries):
    acquired = []
    try:
        for lock in destination_locks(entries):
            lock.parent.mkdir(parents=True, exist_ok=True)
            try:
                lock.mkdir(mode=0o700)
            except FileExistsError:
                raise LockConflict('Destination lock present: LIVENESS_UNVERIFIED; manual recovery required')
            acquired.append(lock)
            (lock / 'owner.json').write_text(json.dumps({'pid': os.getpid()}), encoding='utf-8')
        yield
    finally:
        for lock in reversed(acquired):
            (lock / 'owner.json').unlink(missing_ok=True)
            lock.rmdir()


def operate(transaction, rollback=False):
    transaction = Path(transaction)
    lock = transaction / 'operation.lock'
    try:
        lock.mkdir()
    except FileExistsError:
        raise LockConflict('Transaction lock present: LIVENESS_UNVERIFIED; manual recovery required')
    try:
        (lock / 'owner.json').write_text(json.dumps({'pid': os.getpid()}), encoding='utf-8')
        record_path = transaction / 'transaction.json'
        record = json.loads(record_path.read_text(encoding='utf-8'))
        if not rollback and record['status'] == 'prepared':
            # Avoid creating destination directories for an already-known conflict.
            # The authoritative preimage check is repeated while holding locks.
            for entry in record['entries']:
                if read(Path(entry['path'])) != unpack(entry, 'before'):
                    raise Conflict('Destination changed; transaction refused')
        with locked_destinations(record['entries']):
            operate_locked(transaction, record_path, record, rollback)
    finally:
        (lock / 'owner.json').unlink(missing_ok=True)
        lock.rmdir()
    return report(transaction)


def operate_locked(transaction, record_path, record, rollback):
        status = record['status']
        if status == ('rolled_back' if rollback else 'applied'):
            return report(transaction)
        if status not in (('applied', 'partial') if rollback else ('prepared',)):
            raise Conflict('Invalid transaction state')
        entries = record['entries']
        pending = record.get('in_flight')
        if pending is not None:
            # A failed operation can leave its journal ahead of the filesystem.
            entry = entries[pending]
            current = read(Path(entry['path']))
            if current == unpack(entry, 'after') and pending not in record['applied']:
                record['applied'].append(pending)
            elif current == unpack(entry, 'before') and pending in record['applied']:
                record['applied'].remove(pending)
            elif current not in (unpack(entry, 'before'), unpack(entry, 'after')):
                raise Conflict('Interrupted destination changed')
        selected = list(reversed(record['applied'])) if rollback else list(range(len(entries)))
        before_side, after_side = ('after', 'before') if rollback else ('before', 'after')
        for i in selected:
            if read(Path(entries[i]['path'])) != unpack(entries[i], before_side):
                raise Conflict('Destination changed; transaction refused')
        for i in selected:
            entry = entries[i]
            record['status'], record['in_flight'] = 'partial', i
            save_record(record_path, record)
            atomic_write(Path(entry['path']), unpack(entry, after_side), unpack(entry, before_side))
            if rollback:
                record['applied'].remove(i)
            else:
                record['applied'].append(i)
            record['in_flight'] = None
            save_record(record_path, record)
        record['status'] = 'rolled_back' if rollback else 'applied'
        record['in_flight'] = None
        save_record(record_path, record)
        return report(transaction)


def report(transaction):
    record = json.loads((Path(transaction) / 'transaction.json').read_text(encoding='utf-8'))
    return {'transaction': str(transaction), 'status': record['status'], 'client': record['client'],
            'trust': record['trust'],
            'locks': [{'path': str(p), 'state': 'LIVENESS_UNVERIFIED' if p.exists() else 'ABSENT'}
                      for p in [Path(transaction) / 'operation.lock', *destination_locks(record['entries'])]],
            'changes': [{**{k: e[k] for k in ('path', 'before_sha256', 'after_sha256')},
                         'current_sha256': digest(read(Path(e['path'])))} for e in record['entries']]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--home', type=Path, default=Path.home())
    prep.add_argument('--client', choices=['claude', 'codex', 'cursor'], required=True)
    prep.add_argument('--python', required=True)
    prep.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    prep.add_argument('--state-root', type=Path, required=True)
    prep.add_argument('--shell', choices=['bash', 'powershell'], required=True)
    prep.add_argument('--command-shell', choices=['bash', 'cmd', 'powershell'], required=True)
    prep.add_argument('--skill-root', type=Path)
    for name in ('apply', 'rollback', 'status'):
        sub.add_parser(name).add_argument('transaction', type=Path)
    args = vars(parser.parse_args())
    operation = args.pop('operation')
    try:
        if operation == 'prepare':
            result = report(prepare(**args))
        elif operation == 'status':
            result = report(args['transaction'])
        else:
            result = operate(args['transaction'], rollback=operation == 'rollback')
        print(json.dumps(result))
        return 0
    except LockConflict:
        print(json.dumps({'status': 'REFUSED', 'reason': 'Lock present: LIVENESS_UNVERIFIED. Follow manual recovery in module documentation.'}))
        return 2
    except (Conflict, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({'status': 'REFUSED', 'reason': 'Invalid input, access failure or state conflict; inspect private transaction locally.'}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
