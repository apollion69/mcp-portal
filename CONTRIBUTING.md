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

## Releasing

1. Bump the version in `pyproject.toml` and `src/mcp_portal/__init__.py` (`__version__`).
2. Add a dated section to `CHANGELOG.md` for the new version.
3. Commit the version bump on `main`.
4. Create and push an annotated tag: `git tag -a vX.Y.Z -m "vX.Y.Z"` then `git push origin vX.Y.Z`.

Pushing a tag matching `v*` runs `.github/workflows/publish.yml`: build artifacts, publish to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/) (OIDC, no API token), and create a GitHub Release with `dist/*` attached and notes taken from `CHANGELOG.md`.

Ensure the PyPI pending publisher matches this repo (`apollion69/mcp-portal`, workflow `publish.yml`, environment `pypi`).
