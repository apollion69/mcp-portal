# Security

## Threat model

**What leaves the machine:** Selected file contents and your question or spec are sent to the Cursor CLI, which contacts Cursor's cloud models. Only bounded excerpts you authorize via `paths` / `reference_path` are read locally and forwarded. The MCP host still sees tool JSON responses (findings, code, metrics).

**What stays local:** Hash-pinned manifests, per-run evidence directories under `MCP_PORTAL_HOME` (default `~/.cache/mcp-portal`), receipt ledgers, and model-policy configuration. The server blocks common credential paths and secret-shaped content before delegation.

**CLI isolation:** Each run uses a fresh `CURSOR_CONFIG_DIR` with deny-all tool permissions and `--mode ask`. The worker must not read arbitrary files or invoke tools; the MCP server writes `code_write` targets itself.

**Not a sandbox:** Tool permission denials are defense in depth. A compromised or misconfigured Cursor CLI could still exfiltrate data you send it. Do not delegate secrets, keys, or private environment files.

## Reporting

Please report vulnerabilities privately via GitHub Security Advisories on [apollion69/mcp-portal](https://github.com/apollion69/mcp-portal/security/advisories/new). Include reproduction steps and impact. We aim to acknowledge reports within a few business days.
