"""Read routing policy, not a security boundary. No source text leaves this hook."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import sys
import uuid
import hashlib

DEFAULT_LINE_THRESHOLD = 350
READERS = {'cat', 'head', 'tail', 'less', 'more'}


def portal_home():
    raw = os.environ.get('MCP_PORTAL_HOME')
    return Path(raw).expanduser() if raw else Path.home() / '.cache' / 'mcp-portal'


def line_threshold():
    raw = os.environ.get('MCP_PORTAL_MIN_LINES')
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return DEFAULT_LINE_THRESHOLD


def surface_key(client):
    return f'{client}-{"win" if os.name == "nt" else "wsl"}'


def health_ok():
    path = portal_home() / 'health.json'
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or data.get('ok') is not True:
            return False
        checked_at = data.get('checked_at')
        if not isinstance(checked_at, str):
            return False
        checked = datetime.fromisoformat(checked_at.replace('Z', '+00:00'))
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - checked).total_seconds() < 86400
    except (OSError, ValueError, TypeError):
        return False


def mode(client):
    path = portal_home() / 'enforce.json'
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            return 'warn'
        configured = data.get(surface_key(client))
        if configured not in ('deny', 'warn'):
            return 'warn'
        if configured == 'deny' and not health_ok():
            return 'warn'
        return configured
    except (OSError, ValueError, json.JSONDecodeError):
        return 'warn'


def shell_paths(command, cwd=None):
    """Recognize ordinary full-read commands; unknown syntax is not executed."""
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=';&|<>')
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return []
    result, group = [], []
    changed_dir = None
    for token in tokens + [';']:
        if token in (';', '&&', '||'):
            first_new = len(result)
            if len(group) == 2 and group[0] == 'cd' and '$' not in group[1]:
                changed_dir = str((Path(changed_dir or cwd or os.getcwd()) / group[1]).resolve())
            if group and Path(group[0]).name in READERS:
                args = group[1:]
                reader = Path(group[0]).name
                unbounded = reader not in ('head', 'tail')
                if reader == 'tail' and any(x.startswith(('+', '--lines=+', '--bytes=+')) for x in args):
                    unbounded = True
                if reader == 'head' and (any(x.startswith('-') and x[1:].isdigit() for x in args[1:]) or any(x.startswith(('--lines=-', '--bytes=-')) for x in args)):
                    unbounded = True
                full_flags = {'--', '-n', '-b', '-s', '-E', '-T', '-v', '-A', '-e', '-t', '--number', '--number-nonblank'} if reader == 'cat' else {'--'}
                if unbounded and not any(x in group for x in ('|', '>', '>>', '<', '<<')):
                    if reader in ('head', 'tail'):
                        result.extend(x for x in args if not x.startswith(('-', '+')) and not x.isdigit())
                    elif all(not x.startswith('-') or x in full_flags for x in args):
                        result.extend(x for x in args if x not in full_flags)
            elif len(group) >= 3 and Path(group[0]).name in ('bash', 'sh') and group[1] in ('-c', '-lc'):
                result.extend(shell_paths(group[2], changed_dir or cwd))
            if changed_dir:
                result[first_new:] = [str(Path(changed_dir) / p) if not Path(p).is_absolute() else p for p in result[first_new:]]
            group = []
        else:
            group.append(token)
    return result


def input_paths(payload, shell='bash'):
    tool = payload.get('tool_name', '')
    data = payload.get('tool_input') or {}
    if not isinstance(data, dict):
        return []
    if tool in ('Read', 'read_file') or payload.get('hook_event_name') == 'beforeReadFile':
        data = data if tool else payload
        if any(data.get(k) is not None for k in ('offset', 'limit', 'start_line', 'end_line')):
            return []
        return [data.get('file_path') or data.get('path')] if data.get('file_path') or data.get('path') else []
    if tool in ('Bash', 'Shell', 'exec_command', 'shell_command') or payload.get('hook_event_name') == 'beforeShellExecution':
        command = data.get('command') or data.get('cmd') or payload.get('command', '')
        if not isinstance(command, str):
            return []
        if shell == 'powershell':
            return powershell_paths(command)
        return shell_paths(command, data.get('workdir') or data.get('working_directory') or payload.get('cwd'))
    return []


def _parse_read_script() -> Path:
    env = os.environ.get('MCP_PORTAL_PARSE_READ_PS1')
    if env:
        return Path(env)
    bundled = Path(__file__).resolve().parent / 'parse_read.ps1'
    if bundled.is_file():
        return bundled
    return Path(__file__).resolve().parents[2] / 'clients' / 'windows' / 'parse_read.ps1'


def powershell_paths(command):
    """Use PowerShell's parser rather than interpret quoted user commands."""
    import subprocess
    script = _parse_read_script()
    try:
        run = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script)],
                             input=command, text=True, encoding='utf-8', capture_output=True, timeout=5)
        result = json.loads(run.stdout) if run.returncode == 0 else []
        return result if isinstance(result, list) and all(isinstance(x, str) for x in result) else []
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def large_paths(paths, cwd):
    threshold = line_threshold()
    result = []
    for name in paths[:32]:
        if not isinstance(name, str) or not name or any(c in name for c in '*?\x00'):
            continue
        path = Path(name)
        if not path.is_absolute():
            path = Path(cwd) / path
        try:
            path = path.resolve(strict=True)
            if not path.is_file():
                continue
            with path.open('rb') as handle:
                body = handle.read(128 * 1024 + 1)
            if len(body) > 128 * 1024 or body.count(b'\n') + bool(body and not body.endswith(b'\n')) > threshold:
                result.append(path)
        except (OSError, ValueError):
            continue
    return list(dict.fromkeys(result))


def invocation(paths, shell):
    root = Path(os.path.commonpath([str(p.parent) for p in paths]))
    args = [Path(sys.executable).as_posix(), '-m', 'mcp_portal.bulk_read',
            '--root', str(root), '--paths', *[str(p.relative_to(root)) for p in paths],
            '--question', 'State your specific analysis question here']
    if shell == 'powershell':
        return '& ' + ' '.join("'" + a.replace("'", "''") + "'" for a in args)
    return shlex.join(args)


def mcp_invocation(paths):
    # Absolute paths: the tool resolves its own root, and the hint must not depend on the
    # reader's current directory, which is not the one this hook ran in.
    return ('mcp__mcp-portal__bulk_read(paths=' + json.dumps([str(p) for p in paths])
            + ', question="<your question>")')


def denial_reason(paths, shell, verb='blocked'):
    threshold = line_threshold()
    return ('Large full-file read ' + verb + ' (>' + str(threshold) + ' lines or >128 KiB). '
            'Use cursor-bulk-reader via MCP first: ' + mcp_invocation(paths)
            + '. Fallback CLI: ' + invocation(paths, shell)
            + '. Replace the question placeholder. Use the PASS result and run_id; verify cited lines before edits. '
              'For exact editing context, a targeted read with offset/limit or an explicit line count remains allowed. '
              'If delegation refuses the payload, report its error and use bounded reads; do not retry a full read.')


def route(payload, client, shell):
    if os.environ.get('CURSOR_DELEGATE_DEPTH'):
        return {}
    data = payload.get('tool_input') or {}
    execution_dir = (data.get('workdir') or data.get('working_directory')) if isinstance(data, dict) else None
    paths = large_paths(input_paths(payload, shell), execution_dir or payload.get('cwd') or os.getcwd())
    if not paths:
        return {}
    enforcement = mode(client)
    reason = denial_reason(paths, shell, 'blocked' if enforcement == 'deny' else 'is worth delegating')
    if enforcement == 'warn':
        if client == 'cursor':
            return {}
        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'additionalContext': reason}}
    if client == 'cursor':
        return {'permission': 'deny', 'user_message': reason, 'agent_message': reason}
    return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                                   'permissionDecisionReason': reason}}


def write_health():
    from mcp_portal import delegate
    status = delegate.portal_status()
    cli = Path(status.get('cli_path', ''))
    ok = cli.is_file() and bool(status.get('authenticated'))
    payload = {'ok': ok, 'checked_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    home = portal_home()
    home.mkdir(parents=True, exist_ok=True)
    (home / 'health.json').write_text(json.dumps(payload), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--health-write', action='store_true', help='Write health.json from portal status')
    parser.add_argument('--client', choices=['claude', 'codex', 'cursor'])
    parser.add_argument('--shell', choices=['bash', 'powershell'])
    parser.add_argument('--receipt-dir', help='Optional test-run receipt directory; no input bodies are persisted')
    args = parser.parse_args()
    if args.health_write:
        write_health()
        return
    if not args.client or not args.shell:
        parser.error('--client and --shell are required unless --health-write is used')
    try:
        raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
        payload = json.loads(raw) if len(raw) <= 2 * 1024 * 1024 else {}
        result = route(payload, args.client, args.shell) if isinstance(payload, dict) else {}
        route_id = 'route-' + uuid.uuid4().hex
        if result:
            suffix = ' Routing receipt: ' + route_id
            if args.client == 'cursor':
                result['agent_message'] += suffix
                result['user_message'] += suffix
            elif 'hookSpecificOutput' in result:
                if 'permissionDecisionReason' in result['hookSpecificOutput']:
                    result['hookSpecificOutput']['permissionDecisionReason'] += suffix
                elif 'additionalContext' in result['hookSpecificOutput']:
                    result['hookSpecificOutput']['additionalContext'] += suffix
        if args.receipt_dir and isinstance(payload, dict):
            try:
                folder = Path(args.receipt_dir)
                folder.mkdir(parents=True, exist_ok=True, mode=0o700)
                data = payload.get('tool_input')
                receipt = {'route_id': route_id, 'decision': 'deny' if result else 'allow', 'client': args.client,
                           'tool_name': payload.get('tool_name'), 'tool_use_id': payload.get('tool_use_id'),
                           'input_sha256': hashlib.sha256(raw).hexdigest(), 'input_type': type(data).__name__,
                           'input_keys': list(data) if isinstance(data, dict) else [],
                           'path_basenames': {k: Path(data[k]).name for k in ('path', 'file_path', 'target_file') if isinstance(data, dict) and isinstance(data.get(k), str)},
                           'line_fields': {k: data[k] for k in ('offset', 'limit', 'start_line', 'end_line', 'startLine', 'endLine') if isinstance(data, dict) and k in data and (data[k] is None or type(data[k]) is int)}}
                (folder / (route_id + '.json')).write_text(json.dumps(receipt), encoding='utf-8')
            except OSError:
                pass
    except (ValueError, OSError, TypeError):
        result = {}
    # Allow is silence. An empty object on the wire is still stdout, and PreToolUse
    # inventories treat that as unexpected output on a benign command.
    if result:
        print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
