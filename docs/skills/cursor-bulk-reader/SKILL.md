---
name: cursor-bulk-reader
description: Delegate large file analysis to the Cursor worker when a read hook redirects you, when a file exceeds 350 lines, or when you need a concise answer across several files. Keep exact targeted reads for editing.
---

# Cursor bulk reader

Use the exact `mcp-portal-bulk-read` command (or `python -m mcp_portal.bulk_read`) supplied by the read hook. Replace its question placeholder with the question you need answered. The command has named arguments `--root`, `--paths` and `--question`; quote every path for your shell. Do not replace the executable with an improvised pipeline.

The local script reads the selected files and sends their contents to the user's Cursor cloud model. Unless you pass `--model`, the portal applies server-side policy: Cursor-native first (default `composer-2.5`), never a `-fast` variant; another vendor is used only when you name it explicitly and it is available in `cursor-agent --list-models`. The primary agent receives a concise answer with exact source quotes and line ranges, source hashes and a run_id. This is local routing, not offline inference.

Accept only a result with status PASS. Use its findings to answer the original question and retain the run_id as evidence. Verify the relevant source lines with a targeted read before editing. A matching quote proves citation accuracy, not the worker's interpretation.

Each call is independent. Ask a precise follow-up with the same paths when necessary; avoid blindly replaying whole conversations. Current worker limits are 16 files, 128 KiB combined input and 90 seconds. Split a refused oversized corpus into smaller selections, or use bounded targeted reads. Never send credentials or secret-bearing files. Do not retry an unchanged failure or bypass a read denial using another full-file reader.

Small files and bounded reads remain direct. If a read cannot be delegated, report the explicit error and choose a bounded read appropriate to the task. Do not claim delegation succeeded, or that costs fell, merely because a hook was installed.
