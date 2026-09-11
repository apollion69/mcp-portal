# Changelog

## 0.1.0 — 2026-09-11

First public release, extracted from an internal agent harness.

- Stdio MCP server with `bulk_read`, `code_write`, and `status` tools
- Python stdlib only; isolated Cursor CLI runs with deny-all tool permissions
- Hash-pinned manifests, per-run evidence directories, and quote verification
- Server-side model policy with Cursor-native defaults
- Optional read-routing hook installer for Claude Code and related hosts
- Windows client helpers via WSL
