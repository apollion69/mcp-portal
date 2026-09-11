# Contributing

Thanks for helping improve mcp-portal.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"  # or: pip install pytest hatchling && pip install -e .
```

Run tests from the repository root:

```bash
python3 -m pytest -q
```

Tests must not require a live Cursor CLI. Mark or skip any test that needs `cursor-agent` when the binary is absent, with a clear skip reason.

## Style

- Python 3.10+ syntax
- **Stdlib only** for runtime code — no third-party dependencies in `src/mcp_portal/`
- Prefer small, explicit functions over frameworks
- Match existing naming and error shapes (`Refused`, `status: PASS|FAIL`)

## Pull requests

- One logical change per PR when possible
- Include or update tests for behavior changes
- Do not commit secrets, host-specific paths, or credentials
