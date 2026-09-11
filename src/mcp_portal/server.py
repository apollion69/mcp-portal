"""Stdio JSON-RPC MCP server for Cursor-backed bulk read and code generation."""
from __future__ import annotations

import json
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Any

from mcp_portal import delegate

SERVER_INFO = {"name": "mcp-portal", "version": "0.1.0"}
MAX_STDIO_FRAME_BYTES = 64 * 1024
TOOLS = ("bulk_read", "code_write", "status")


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "bulk_read",
            "description": "Read authorized files and answer a question via Cursor CLI (read-only).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 16},
                    "question": {"type": "string", "minLength": 1},
                    "root": {"type": "string"},
                    "model": {"type": "string"},
                },
                "required": ["paths", "question"],
                "additionalProperties": False,
            },
        },
        {
            "name": "code_write",
            "description": "Generate code from a spec and reference file; optional server-side write.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "spec": {"type": "string", "minLength": 1},
                    "reference_path": {"type": "string", "minLength": 1},
                    "target_path": {"type": "string"},
                    "model": {"type": "string"},
                },
                "required": ["spec", "reference_path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "status",
            "description": "Cursor CLI path, auth, cache location, and receipt counters.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    ]


def _fail(exc: BaseException) -> dict[str, Any]:
    message = str(exc)
    return {
        "status": "FAIL",
        "error": message,
        "error_type": type(exc).__name__,
        "error_message": message,
    }


def _windows_path(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:\\", value) or value.startswith("\\\\wsl"))


def normalize_path(value: str) -> str:
    if _windows_path(value):
        try:
            _, out, _ = delegate.run_bounded(
                ["wslpath", "-u", value], b"", delegate.portal_home(), os.environ.copy(), 5, 8192
            )
            line = out.strip()
            if line:
                return line
        except delegate.Refused:
            pass
    return value


def longest_common_root(paths: list[str]) -> Path:
    resolved = [Path(normalize_path(p)).expanduser().resolve() for p in paths]
    if len(resolved) == 1:
        return resolved[0].parent
    parts = [p.parts for p in resolved]
    common: list[str] = []
    for chunk in zip(*parts):
        if len(set(chunk)) == 1:
            common.append(chunk[0])
        else:
            break
    return Path(*common) if common else resolved[0].parent


def relative_paths(root: Path, paths: list[str]) -> list[str]:
    rel: list[str] = []
    for raw in paths:
        p = Path(normalize_path(raw)).expanduser().resolve()
        try:
            rel.append(p.relative_to(root).as_posix())
        except ValueError:
            raise delegate.Refused("PATH_OUTSIDE_ROOT") from None
    return rel


def strip_code_fences(text: str) -> str:
    stripped = text.strip()
    match = re.match(r"^```(?:[a-zA-Z0-9_+-]*)\n(.*)\n```\s*$", stripped, re.S)
    if match:
        return match.group(1)
    return stripped


def safe_write_target(raw: str) -> Path:
    target = Path(normalize_path(raw)).expanduser().resolve()
    rel = target.as_posix().split(":", 1)[-1].lstrip("/")
    if rel:
        delegate.safe_name(rel)
    return target


def call_tool(name: str, args: object) -> dict[str, Any]:
    if name not in TOOLS or not isinstance(args, dict):
        raise ValueError(f"unknown tool or arguments: {name}")
    if name == "status":
        return delegate.portal_status()
    raw_model = args.get("model")
    if raw_model is not None and not isinstance(raw_model, str):
        raise ValueError("model must be a string")
    model, decision = delegate.resolve_model(raw_model if isinstance(raw_model, str) else None)
    timeout = 90
    if name == "bulk_read":
        paths_raw = args.get("paths")
        if not isinstance(paths_raw, list) or not all(isinstance(p, str) for p in paths_raw):
            raise ValueError("paths must be a string array")
        question = args.get("question")
        if not isinstance(question, str) or not question.strip():
            raise ValueError("question required")
        root_raw = args.get("root")
        if isinstance(root_raw, str) and root_raw.strip():
            root = Path(normalize_path(root_raw)).expanduser().resolve()
        else:
            root = longest_common_root(paths_raw)
        rel = relative_paths(root, paths_raw)
        request = delegate.build_request(str(root), rel, question, model, timeout)
        result = delegate.execute(request, tool="bulk_read", model_reason=decision["reason"])
        result["model_decision"] = decision
        return result
    spec = args.get("spec")
    reference_path = args.get("reference_path")
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("spec required")
    if not isinstance(reference_path, str) or not reference_path.strip():
        raise ValueError("reference_path required")
    ref = Path(normalize_path(reference_path)).expanduser().resolve()
    root = ref.parent
    rel_ref = ref.relative_to(root).as_posix()
    request = delegate.build_code_write_request(str(root), rel_ref, spec, model, timeout)
    backend_result = delegate.execute(request, tool="code_write", model_reason=decision["reason"])
    code = backend_result.get("code", "")
    body = strip_code_fences(code)
    target_path = args.get("target_path")
    payload = {
        "status": backend_result.get("status", "PASS"),
        "run_id": backend_result.get("run_id"),
        "model_decision": decision,
        "metrics": backend_result.get("metrics"),
        "bytes_written": 0,
        "target_path": None,
        "code": body,
    }
    if isinstance(target_path, str) and target_path.strip():
        target = safe_write_target(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        payload["target_path"] = str(target)
        payload["bytes_written"] = len(body.encode("utf-8"))
    return payload


def _tool_result(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False, indent=2)}],
        "isError": value.get("status") == "FAIL",
    }


def _error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    if "id" not in request:
        return None
    method = request.get("method")
    req_id = request.get("id")
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            }
        elif method == "tools/list":
            result = {"tools": tool_definitions()}
        elif method == "tools/call":
            params = request.get("params") or {}
            try:
                value = call_tool(str(params.get("name")), params.get("arguments") or {})
            except delegate.Refused as exc:
                value = _fail(exc)
            result = _tool_result(value)
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    except Exception as exc:  # noqa: BLE001 — JSON-RPC must not crash the server.
        traceback.print_exc(file=sys.stderr)
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": req_id, "result": _tool_result(_fail(exc))}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(exc)}}


def _bounded_stdio_lines(stream: Any):
    while line := stream.readline(MAX_STDIO_FRAME_BYTES + 1):
        if len(line) > MAX_STDIO_FRAME_BYTES:
            while line and not line.endswith(b"\n"):
                line = stream.readline(MAX_STDIO_FRAME_BYTES + 1)
            yield None
        else:
            yield line


def serve() -> int:
    for line in _bounded_stdio_lines(sys.stdin.buffer):
        if line is None:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "request exceeds the stdio frame limit"},
            }
            print(json.dumps(response, ensure_ascii=False), flush=True)
            continue
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        else:
            response = handle_request(request)
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


def main() -> int:
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
