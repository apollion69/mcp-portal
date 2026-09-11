"""Register mcp-portal in agent profiles. Additive, transactional, byte-exact rollback."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

def default_repo() -> Path:
    raw = os.environ.get('MCP_PORTAL_REPO')
    return Path(raw).expanduser().resolve() if raw else Path.cwd().resolve()


def canonical_root(repo: Path) -> Path:
    """The checkout a registration should NAME, which is not always the one it is written into.

    A temporary worktree checkout is not a stable path for hook commands or MCP argv. Destinations
    stay in the current checkout so a worktree branch carries its own registration; stable paths
    inside them should point at the trunk checkout when applicable.
    """
    parts = repo.parts
    for i in range(len(parts) - 2):
        if parts[i] == '.claude' and parts[i + 1] == 'worktrees':
            return Path(*parts[:i])
    return repo


STATE_ROOT = Path.home() / '.cache' / 'mcp-portal' / 'transactions'
STALE_ROUTER = 'cursor_delegate/router.py'
_WSL_DISTRO = os.environ.get('WSL_DISTRO', 'Ubuntu')


class Conflict(Exception):
    pass


class LockConflict(Conflict):
    pass


def digest(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def read(path: Path) -> bytes | None:
    if path.is_symlink():
        raise Conflict(f'Symlink refused: {path}')
    return path.read_bytes() if path.is_file() else None


def detect_indent(text: str) -> int:
    match = re.search(r'\n( +)"', text)
    return len(match.group(1)) if match else 2


def render_json(data: dict, original: bytes | None) -> bytes:
    text = '' if original is None else original.decode('utf-8-sig')
    # A minified file stays minified. .codex/hooks.json ships as one line; pretty-printing it
    # turned a one-entry addition into a 925-line diff, which is not an additive edit.
    if text.strip() and '\n' not in text.strip():
        rendered = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    else:
        rendered = json.dumps(data, ensure_ascii=False, indent=detect_indent(text) if text else 2)
    if text.endswith('\n') or not text:
        rendered += '\n'
    return rendered.encode('utf-8')


def atomic_write(path: Path, data: bytes | None, expected: bytes | None) -> None:
    if read(path) != expected:
        raise Conflict(f'Preimage changed: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    if data is None:
        path.unlink(missing_ok=True)
        return
    fd, temporary = tempfile.mkstemp(prefix='.mcp-portal-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            if path.is_file() and os.name != 'nt':
                os.chmod(temporary, path.stat().st_mode & 0o777)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if read(path) != expected:
            raise Conflict(f'Preimage changed before replace: {path}')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def hook_command(client: str, shell: str = 'bash') -> str:
    py = os.environ.get('MCP_PORTAL_PYTHON', 'python3')
    return f'{py} -m mcp_portal.router --client {client} --shell {shell}'


def mcp_server_entry(*, wsl: bool) -> dict:
    if wsl:
        return {'command': 'uvx', 'args': ['mcp-portal']}
    return {'command': 'wsl.exe', 'args': ['-d', _WSL_DISTRO, '--', 'uvx', 'mcp-portal']}


def targets(repo: Path) -> dict[str, Path]:
    return {
        'claude-mcp': repo / '.mcp.json',
        'claude-enable': repo / '.claude' / 'settings.local.json',
        'claude-hook': repo / '.claude' / 'settings.json',
        'codex-hook': repo / '.codex' / 'hooks.json',
        'codex-mcp': Path.home() / '.codex' / 'config.toml',
        'windows-claude-mcp': Path.home() / '.claude.json',
    }


def transform(name: str, before: bytes | None, *, replace: bool) -> tuple[str, bytes | None, str]:
    """Return action, after bytes, detail message (no secret values)."""
    if name == 'claude-mcp':
        return _json_mcp(before, mcp_server_entry(wsl=True), replace)
    if name == 'windows-claude-mcp':
        return _json_mcp(before, mcp_server_entry(wsl=False), replace)
    if name == 'claude-enable':
        return _json_enable(before, replace)
    if name == 'claude-hook':
        return _json_claude_hook(before, replace)
    if name == 'codex-hook':
        return _json_codex_hook(before, replace)
    if name == 'codex-mcp':
        return _toml_codex_mcp(before, replace)
    raise Conflict(f'Unknown target: {name}')


def _json_mcp(before: bytes | None, wanted: dict, replace: bool) -> tuple[str, bytes | None, str]:
    if before is None:
        raise Conflict('Destination missing')
    data = json.loads(before.decode('utf-8-sig'))
    if not isinstance(data, dict):
        raise Conflict('Root must be object')
    servers = data.setdefault('mcpServers', {})
    if not isinstance(servers, dict):
        raise Conflict('mcpServers must be object')
    current = servers.get('mcp-portal')
    if current == wanted:
        return 'noop', before, ''
    if current is not None and not replace:
        return 'conflict', before, 'mcp-portal entry differs'
    servers['mcp-portal'] = wanted
    return 'added', render_json(data, before), ''


def _json_enable(before: bytes | None, replace: bool) -> tuple[str, bytes | None, str]:
    if before is None:
        raise Conflict('Destination missing')
    data = json.loads(before.decode('utf-8-sig'))
    if not isinstance(data, dict):
        raise Conflict('Root must be object')
    enabled = data.setdefault('enabledMcpjsonServers', [])
    if not isinstance(enabled, list):
        raise Conflict('enabledMcpjsonServers must be array')
    if 'mcp-portal' in enabled:
        return 'noop', before, ''
    enabled.append('mcp-portal')
    return 'added', render_json(data, before), ''


def _claude_hook_entry() -> dict:
    return {
        'matcher': 'Read|Bash',
        'hooks': [{'type': 'command', 'command': hook_command('claude')}],
    }


def _codex_hook_entry() -> dict:
    return {
        'matcher': 'Bash',
        'hooks': [{'type': 'command', 'command': hook_command('codex')}],
    }


def _hook_commands(entry: dict) -> list[str]:
    out = []
    if isinstance(entry, dict):
        if isinstance(entry.get('command'), str):
            out.append(entry['command'])
        for hook in entry.get('hooks') or []:
            if isinstance(hook, dict) and isinstance(hook.get('command'), str):
                out.append(hook['command'])
    return out


def _json_claude_hook(before: bytes | None, replace: bool) -> tuple[str, bytes | None, str]:
    if before is None:
        raise Conflict('Destination missing')
    data = json.loads(before.decode('utf-8-sig'))
    hooks = data.setdefault('hooks', {})
    entries = hooks.setdefault('PreToolUse', [])
    wanted = _claude_hook_entry()
    migrated = False
    kept = []
    for entry in entries:
        if any(STALE_ROUTER in cmd for cmd in _hook_commands(entry)):
            migrated = True
            continue
        kept.append(entry)
    entries[:] = kept
    for entry in entries:
        if entry.get('matcher') == wanted['matcher'] and _hook_commands(entry) == _hook_commands(wanted):
            if migrated:
                return 'migrated', render_json(data, before), 'removed stale router hook'
            return 'noop', before, ''
        if any(_is_portal_hook_command(c) for c in _hook_commands(entry)) and not replace:
            return 'conflict', before, 'different mcp-portal hook present'
    # --replace must REPLACE. Appending beside the old entry leaves two gates firing on every
    # read, and the stale one names a path that may no longer exist.
    replaced = False
    if replace:
        surviving = [e for e in entries if not any(_is_portal_hook_command(c) for c in _hook_commands(e))]
        replaced = len(surviving) != len(entries)
        entries[:] = surviving
    entries.append(wanted)
    action = 'migrated' if migrated else ('replaced' if replaced else 'added')
    detail = 'removed stale router hook' if migrated else ('repointed existing entry' if replaced else '')
    return action, render_json(data, before), detail


def _is_portal_hook_command(command: str) -> bool:
    return 'mcp-portal-read-gate.sh' in command or 'mcp_portal.router' in command


def _json_codex_hook(before: bytes | None, replace: bool) -> tuple[str, bytes | None, str]:
    if before is None:
        raise Conflict('Destination missing')
    data = json.loads(before.decode('utf-8-sig'))
    hooks = data.setdefault('hooks', {})
    entries = hooks.setdefault('PreToolUse', [])
    wanted = _codex_hook_entry()
    migrated = False
    kept = []
    for entry in entries:
        if any(STALE_ROUTER in cmd for cmd in _hook_commands(entry)):
            migrated = True
            continue
        kept.append(entry)
    entries[:] = kept
    for entry in entries:
        if entry.get('matcher') == wanted['matcher'] and _hook_commands(entry) == _hook_commands(wanted):
            if migrated:
                return 'migrated', render_json(data, before), 'removed stale router hook'
            return 'noop', before, ''
        if any(_is_portal_hook_command(c) for c in _hook_commands(entry)):
            if not replace:
                return 'conflict', before, 'different mcp-portal hook present'
    replaced = False
    if replace:
        surviving = [e for e in entries if not any(_is_portal_hook_command(c) for c in _hook_commands(e))]
        replaced = len(surviving) != len(entries)
        entries[:] = surviving
    entries.append(wanted)
    action = 'migrated' if migrated else ('replaced' if replaced else 'added')
    detail = 'removed stale router hook' if migrated else ('repointed existing entry' if replaced else '')
    return action, render_json(data, before), detail


def _toml_block() -> str:
    return (
        '\n[mcp_servers.mcp-portal]\n'
        'command = "uvx"\n'
        'args = ["mcp-portal"]\n'
        'tool_timeout_sec = 150\n'
    )


def _wanted_codex_mcp_section() -> dict:
    return {'command': 'uvx', 'args': ['mcp-portal'], 'tool_timeout_sec': 150}


def _parse_mcp_portal_toml_section(text: str) -> dict | None:
    """Minimal stdlib parser for the single section we write (no tomllib on 3.10)."""
    marker = '[mcp_servers.mcp-portal]'
    if marker not in text:
        return None
    block = text.split(marker, 1)[1].split('\n[', 1)[0]
    cmd = re.search(r'^command\s*=\s*"([^"]*)"\s*$', block, re.M)
    args = re.search(r'^args\s*=\s*\["([^"]*)"\]\s*$', block, re.M)
    timeout = re.search(r'^tool_timeout_sec\s*=\s*(\d+)\s*$', block, re.M)
    if not cmd or not args or not timeout:
        raise Conflict('config.toml parse error: mcp-portal section malformed')
    return {
        'command': cmd.group(1),
        'args': [args.group(1)],
        'tool_timeout_sec': int(timeout.group(1)),
    }


def _assert_appended_toml_valid(text: str) -> None:
    for fragment in (
        '[mcp_servers.mcp-portal]',
        'command = "uvx"',
        'args = ["mcp-portal"]',
        'tool_timeout_sec = 150',
    ):
        if fragment not in text:
            raise Conflict(f'appended TOML invalid: missing {fragment}')


def _toml_codex_mcp(before: bytes | None, replace: bool) -> tuple[str, bytes | None, str]:
    if before is None:
        raise Conflict('Destination missing')
    text = before.decode('utf-8')
    wanted = _wanted_codex_mcp_section()
    if '[mcp_servers.mcp-portal]' in text:
        section = _parse_mcp_portal_toml_section(text)
        if section == wanted:
            return 'noop', before, ''
        if not replace:
            return 'conflict', before, 'mcp-portal section differs'
        raise Conflict('TOML replace for existing section is not implemented')
    after_text = text.rstrip() + _toml_block()
    _assert_appended_toml_valid(after_text)
    return 'added', after_text.encode('utf-8'), ''


def readback(name: str, path: Path, after: bytes) -> None:
    current = read(path)
    if current != after:
        raise Conflict(f'Readback mismatch: {path}')
    if name in ('claude-mcp', 'windows-claude-mcp'):
        data = json.loads(current.decode('utf-8-sig'))
        if data.get('mcpServers', {}).get('mcp-portal') != mcp_server_entry(wsl=name != 'windows-claude-mcp'):
            raise Conflict('mcp-portal server entry missing after write')
    elif name == 'claude-enable':
        if 'mcp-portal' not in json.loads(current.decode('utf-8-sig')).get('enabledMcpjsonServers', []):
            raise Conflict('enabledMcpjsonServers missing mcp-portal')
    elif name == 'claude-hook':
        entries = json.loads(current.decode('utf-8-sig')).get('hooks', {}).get('PreToolUse', [])
        if not any(_hook_commands(e) == _hook_commands(_claude_hook_entry()) for e in entries):
            raise Conflict('claude hook missing')
    elif name == 'codex-hook':
        entries = json.loads(current.decode('utf-8-sig')).get('hooks', {}).get('PreToolUse', [])
        if not any(
            e.get('matcher') == 'Bash' and _hook_commands(e) == _hook_commands(_codex_hook_entry()) for e in entries
        ):
            raise Conflict('codex hook missing')
    elif name == 'codex-mcp':
        body = current.decode('utf-8')
        if '[mcp_servers.mcp-portal]' not in body:
            raise Conflict('TOML section missing')
        if _parse_mcp_portal_toml_section(body) != _wanted_codex_mcp_section():
            raise Conflict('TOML section missing or differs')


def destination_lock(path: Path) -> Path:
    return path.with_name('.' + path.name + '.mcp-portal.lock')


@contextmanager
def locked(paths: list[Path]):
    locks = []
    try:
        for path in sorted({os.path.normcase(str(p.resolve())) for p in paths}, key=str):
            lock = Path(path).with_name('.' + Path(path).name + '.mcp-portal.lock')
            lock.parent.mkdir(parents=True, exist_ok=True)
            try:
                lock.mkdir(mode=0o700)
            except FileExistsError as exc:
                raise LockConflict(f'Lock present: {lock}') from exc
            locks.append(lock)
            (lock / 'owner.json').write_text(json.dumps({'pid': os.getpid()}), encoding='utf-8')
        yield
    finally:
        for lock in reversed(locks):
            (lock / 'owner.json').unlink(missing_ok=True)
            lock.rmdir()


def save_preimage(transaction: Path, target: str, before: bytes | None) -> Path:
    folder = transaction / target
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / 'before.bin'
    if before is None:
        (folder / 'missing').write_text('1', encoding='utf-8')
    else:
        dest.write_bytes(before)
    return dest


def plan(selected: list[str], *, replace: bool) -> list[dict]:
    mapping = targets(default_repo())
    rows = []
    for name in selected:
        path = mapping[name]
        if not path.is_file():
            rows.append({'target': name, 'file': str(path), 'action': 'skip', 'preimage': '-', 'detail': 'missing'})
            continue
        before = read(path)
        action, after, detail = transform(name, before, replace=replace)
        rows.append({'target': name, 'file': str(path), 'action': action, 'preimage': '-', 'detail': detail})
    return rows


def apply(selected: list[str], *, replace: bool) -> str:
    mapping = targets(default_repo())
    transaction = STATE_ROOT / uuid.uuid4().hex
    transaction.mkdir(parents=True, mode=0o700)
    record = {'version': 1, 'status': 'prepared', 'entries': [], 'applied': []}
    paths = []
    for name in selected:
        path = mapping[name]
        if not path.is_file():
            continue
        before = read(path)
        action, after, detail = transform(name, before, replace=replace)
        if action in ('noop', 'conflict'):
            print_line(name, path, action, '-', detail)
            continue
        preimage = save_preimage(transaction, name, before)
        record['entries'].append(
            {
                'target': name,
                'path': str(path),
                'action': action,
                'detail': detail,
                'before': base64.b64encode(before).decode() if before is not None else None,
                'after': base64.b64encode(after).decode(),
                'before_sha256': digest(before),
                'after_sha256': digest(after),
                'preimage': str(preimage),
            }
        )
        paths.append(path)
    if not record['entries']:
        (transaction / 'transaction.json').write_text(json.dumps(record), encoding='utf-8')
        return str(transaction)
    (transaction / 'transaction.json').write_text(json.dumps(record), encoding='utf-8')
    with locked(paths):
        operate(transaction, rollback=False)
    return str(transaction)


def unpack(entry: dict, side: str) -> bytes | None:
    raw = entry[side]
    body = base64.b64decode(raw, validate=True) if raw is not None else None
    if digest(body) != entry[side + '_sha256']:
        raise Conflict('Snapshot integrity mismatch')
    return body


def operate(transaction: Path, *, rollback: bool) -> None:
    record_path = transaction / 'transaction.json'
    record = json.loads(record_path.read_text(encoding='utf-8'))
    lock = transaction / 'operation.lock'
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise LockConflict('Transaction lock present') from exc
    try:
        (lock / 'owner.json').write_text(json.dumps({'pid': os.getpid()}), encoding='utf-8')
        entries = record['entries']
        paths = [Path(e['path']) for e in entries]
        order = list(reversed(range(len(entries)))) if rollback else list(range(len(entries)))
        before_side, after_side = ('after', 'before') if rollback else ('before', 'after')
        for i in order:
            entry = entries[i]
            path = Path(entry['path'])
            if read(path) != unpack(entry, before_side):
                raise Conflict(f'Destination changed; refused: {path}')
        for i in order:
            entry = entries[i]
            path = Path(entry['path'])
            after = unpack(entry, after_side)
            before = unpack(entry, before_side)
            if not rollback:
                atomic_write(path, after, before)
                readback(entry['target'], path, after)
                print_line(entry['target'], path, entry['action'], entry['preimage'], entry.get('detail', ''))
            else:
                atomic_write(path, before, after)
                print_line(entry['target'], path, 'rolled_back', entry['preimage'], '')
        record['status'] = 'rolled_back' if rollback else 'applied'
        record_path.write_text(json.dumps(record), encoding='utf-8')
    finally:
        (lock / 'owner.json').unlink(missing_ok=True)
        lock.rmdir()


def status(transaction: Path) -> dict:
    record = json.loads((transaction / 'transaction.json').read_text(encoding='utf-8'))
    rows = []
    for entry in record.get('entries', []):
        path = Path(entry['path'])
        current = digest(read(path))
        rows.append(
            {
                'target': entry['target'],
                'file': entry['path'],
                'status': record.get('status'),
                'current_sha256': current,
                'after_sha256': entry.get('after_sha256'),
                'preimage': entry.get('preimage'),
            }
        )
    return {'transaction': str(transaction), 'status': record.get('status'), 'entries': rows}


def print_line(target: str, path: Path, action: str, preimage: str, detail: str) -> None:
    msg = f'target={target} file={path} action={action} preimage={preimage}'
    if detail:
        msg += f' detail={detail}'
    print(msg)


def resolve_targets(raw: list[str]) -> list[str]:
    repo = default_repo()
    known = list(targets(repo))
    mapping = targets(repo)
    if not raw or raw == ['all']:
        return [n for n in known if mapping[n].is_file()]
    bad = [t for t in raw if t not in known]
    if bad:
        raise Conflict(f'Unknown targets: {", ".join(bad)}')
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='plan', choices=['plan', 'apply', 'rollback', 'status'])
    parser.add_argument('transaction', nargs='?', type=Path)
    parser.add_argument('--target', action='append', default=[])
    parser.add_argument('--replace', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'rollback':
            if not args.transaction:
                raise Conflict('rollback requires transaction id')
            operate(args.transaction, rollback=True)
            return 0
        if args.command == 'status':
            if not args.transaction:
                raise Conflict('status requires transaction id')
            print(json.dumps(status(args.transaction), indent=2))
            return 0
        selected = resolve_targets(args.target)
        if args.command == 'plan':
            for row in plan(selected, replace=args.replace):
                print_line(row['target'], Path(row['file']), row['action'], row['preimage'], row.get('detail', ''))
            return 0
        if args.command == 'apply':
            apply(selected, replace=args.replace)
            return 0
        return 1
    except LockConflict as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return 2
    except Conflict as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
