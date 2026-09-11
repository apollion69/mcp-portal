# mcp-portal

<!-- mcp-name: io.github.apollion69/mcp-portal -->

[![CI](https://github.com/apollion69/mcp-portal/actions/workflows/ci.yml/badge.svg)](https://github.com/apollion69/mcp-portal/actions/workflows/ci.yml)

**mcp-portal** is a stdio [Model Context Protocol](https://modelcontextprotocol.io/) server that lets a frontier agent (Claude Code, Codex, Cursor, or any MCP host) delegate two jobs to the **Cursor CLI on its own quota**: bounded **`bulk_read`** (read explicitly selected files, answer with verified quotes) and **`code_write`** (generate boilerplate from a reference file + spec; the **server** writes the target file). Python stdlib only—no Node runtime and no MCP SDK dependency.

On 2026-09-08, `composer-2.5-fast` generated roughly **5× faster** than a frontier model on the same brief (line-rate measurement). Cursor quota is separate from the host model's.

## Quick start

Until the first PyPI release lands, install straight from GitHub:

```bash
uvx --from git+https://github.com/apollion69/mcp-portal mcp-portal
```

After the PyPI release the short forms work:

```bash
uvx mcp-portal
pipx install mcp-portal
pip install mcp-portal
```

Requirements: Python 3.10+, the [Cursor CLI](https://cursor.com/docs/cli) (`cursor-agent`) installed and logged in.

Doctor (CLI inventory, no model call):

```bash
mcp-portal-doctor
```

## Configure per host

### Claude Code

```bash
claude mcp add --scope user mcp-portal -- uvx mcp-portal
```

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.mcp-portal]
command = "uvx"
args = ["mcp-portal"]
tool_timeout_sec = 150
```

### Cursor (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "mcp-portal": {
      "command": "uvx",
      "args": ["mcp-portal"]
    }
  }
}
```

### VS Code (`.vscode/mcp.json`, `servers` key)

```json
{
  "servers": {
    "mcp-portal": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-portal"]
    }
  }
}
```

### Generic `mcpServers` JSON

```json
{
  "mcpServers": {
    "mcp-portal": {
      "command": "uvx",
      "args": ["mcp-portal"]
    }
  }
}
```

Environment (optional):

| Variable | Purpose |
|----------|---------|
| `MCP_PORTAL_HOME` | Cache, receipts, evidence (default `~/.cache/mcp-portal`) |
| `MCP_PORTAL_CLI` | Path to `cursor-agent` / `agent` |

## Tools

### `bulk_read`

| Argument | Required | Description |
|----------|----------|-------------|
| `paths` | yes | 1–16 file paths (relative to `root` or absolute) |
| `question` | yes | Question answered only from those files |
| `root` | no | Common root; default = longest common parent of `paths` |
| `model` | no | Override model; policy applies when omitted |

Returns `status`, `run_id`, `answer.findings[]` (`file`, `start`, `end`, `quote`, `fact`), `gaps[]`, `metrics`, `model_decision`.

### `code_write`

| Argument | Required | Description |
|----------|----------|-------------|
| `spec` | yes | What to generate |
| `reference_path` | yes | Style/context reference file |
| `target_path` | no | If set, server writes this path |
| `model` | no | Override model |

Returns generated `code`, optional `bytes_written`, `run_id`, `metrics`.

### `status`

No arguments. Returns CLI path, auth hint, default model, policy summary, cache location, receipt counters.

## Model policy

Shipped in `model-policy.json` (package data). Defaults:

- Prefer Cursor-native models (`composer-2.5`, then `cursor-grok-*`)
- Strip `-fast` suffixes (never auto-select fast variants)
- Other vendors only when **explicitly** requested and listed by `cursor-agent --list-models`

Override by editing `model-policy.json` in the installed package or setting policy fields via a custom file at `MCP_PORTAL_HOME` (future) — today, replace the package file or patch `preferred` in your fork. Each tool result includes `model_decision.reason` (`default_preferred`, `fast_suffix_stripped`, `cursor_native_explicit`, `explicit_other_vendor`, `requested_unavailable_fallback`).

## How it works

1. **Authorize** — Server reads only listed paths; blocks credential-like paths and secret patterns.
2. **Manifest** — Request JSON includes per-file SHA-256 hashes.
3. **Isolate** — Cursor CLI runs with fresh `CURSOR_CONFIG_DIR`, deny-all permissions, `--mode ask`, sandbox enabled.
4. **Verify** — Every `quote` in `bulk_read` answers must appear verbatim in the cited line range; bad citations are dropped or fail closed.
5. **Evidence** — Per-run directory under `MCP_PORTAL_HOME/runs/<run_id>/` with manifest (hashes, metrics; not full source).
6. **Budgets** — 16 files, 128 KiB combined input, 90s timeout, bounded stdio frames.

## Windows

Native Windows execution of the Cursor worker is not verified; use **WSL**:

- MCP config can use `wsl.exe` + `uvx mcp-portal`
- Helpers in `clients/windows/` (`delegate.ps1`, `parse_read.ps1`)
- Set `MCP_PORTAL_WORKER` to customize the WSL worker (default: `wsl.exe -- python3 -m mcp_portal.delegate --worker`)
- `MCP_PORTAL_WSL_CD` sets the WSL working directory (default `~`)

## Optional Claude Code routing hook

Install read gate + skill (generic, transactional):

```bash
python3 -m mcp_portal.install_router prepare --client claude --python python3 \
  --state-root ~/.cache/mcp-portal/router-tx --shell bash --command-shell bash
# then apply with the printed transaction id
```

See `docs/skills/cursor-bulk-reader/SKILL.md` for agent-facing guidance. The router blocks or warns on large full-file reads (>350 lines or >128 KiB) and points agents at `bulk_read`.

Repo-level MCP registration helper:

```bash
python3 -m mcp_portal.install plan
python3 -m mcp_portal.install apply --target claude-mcp
```

## Security

See [SECURITY.md](SECURITY.md). Summary: you choose which files leave the machine; the CLI runs read-only with tools denied; quotes are verified server-side. Not a substitute for secret hygiene.

## Related projects

Several **Node-based** bridges expose Cursor via MCP (different tradeoffs: SDK/Node stack, varying isolation and verification):

- [lipey1/cursor-agent-mcp](https://github.com/lipey1/cursor-agent-mcp)
- [andreilungeanu/cursor-delegate-mcp](https://github.com/andreilungeanu/cursor-delegate-mcp)
- [sailay1996/cursor-agent-mcp](https://github.com/sailay1996/cursor-agent-mcp)
- [ai-nuke/cursor-agent-mcp](https://github.com/ai-nuke/cursor-agent-mcp)
- [JaimeJunr/cursor-mcp-bridge](https://github.com/JaimeJunr/cursor-mcp-bridge)

**mcp-portal** focuses on stdlib Python, hash-pinned manifests, quote verification, server-side writes for `code_write`, model policy, and WSL-first Windows support.

## License

MIT — see [LICENSE](LICENSE).
