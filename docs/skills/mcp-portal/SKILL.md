---
name: mcp-portal
description: Delegate bulk reading and boilerplate generation to the Cursor CLI via the mcp-portal MCP server. Use when a read gate redirects you, a file exceeds 350 lines, a question spans 3+ files, or a file is mostly predictable from a reference. Targeted reads stay here.
---

# mcp-portal

The files go to a Cursor model; only a short answer comes back into this context. Local means the routing and the scripts are local — the selected text still leaves the machine for Cursor, so never delegate credentials or secret-bearing files.

## Reading

```
mcp__mcp-portal__bulk_read(paths=["src/service.py", "docs/config.md"],
                           question="Which failures are retried, and where?")
```

`root` is optional (defaults to the common parent). Omit `model` to use the server policy default: a Cursor-native model with the largest limits (`composer-2.5` first); `-fast` variants are never chosen. Name another vendor's model only when you need it and it appears in your Cursor CLI roster.
A PASS result carries `findings[]` with `file`, `start`, `end`, `quote`, `fact`; `gaps[]`; a
`run_id`; and `metrics` in characters. The server has already checked every quote against the source
text, so a quote proves the citation, not the interpretation.

**Read directly instead when** you are about to edit the file, the file is under about 50 lines, you
need an exact byte or a line number for a patch, or you already know the offset you want. A targeted
read with `offset`/`limit` is never gated.

Each call is independent: the files are not kept between calls, so ask a follow-up with the same
`paths` rather than replaying a conversation. Limits are 16 files, 128 KiB combined, 90 seconds.
A refused oversized corpus is split, not retried whole.

## Generating

```
mcp__mcp-portal__code_write(spec="pytest cases for the retry paths",
                            reference_path="tests/test_client.py",
                            target_path="tests/test_retry.py")
```

`reference_path` is mandatory — it is what makes the output match the surrounding code. Use it where
most of the result is predictable from the reference (tests, config, stubs, docstrings), and review
what comes back: the last fifth usually needs judgement this session owns. Do not delegate edits to
existing files, debugging, or design.

## Reporting

Accept only `status: PASS`; on `FAIL` report the `error` verbatim and fall back to bounded reads.
Never claim delegation happened, or that anything got cheaper, because the tool exists — cite the
`run_id`. Savings are counted in characters: the Cursor CLI returns no token usage.

`mcp__mcp-portal__status` answers whether the route is alive (binary, auth, last successful run).
