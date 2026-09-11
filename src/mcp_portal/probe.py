"""Bounded, secret-safe Cursor CLI inventory. No model invocation."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def main():
    result = {"platform": sys.platform, "executables": {}}
    for name in ("agent", "cursor-agent", "cursor"):
        result["executables"][name] = shutil.which(name)
    candidates = [Path.home() / ".local/bin/agent.exe", Path.home() / ".local/bin/cursor-agent.exe"]
    result["native_candidates"] = {str(p): p.is_file() for p in candidates}
    exe = result["executables"]["agent"] or result["executables"]["cursor-agent"]
    if not exe and sys.platform != "win32" and (Path.home() / ".local/bin/agent").is_file():
        exe = str(Path.home() / ".local/bin/agent")
    result["selected_executable"] = exe
    if exe:
        for key, args in (("version", ["--version"]), ("auth", ["status", "--format", "json"]), ("models", ["--list-models"])):
            try:
                p = subprocess.run([exe, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
                out = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", p.stdout + p.stderr)
                item = {"exit_code": p.returncode}
                if key == "version":
                    item["version"] = re.findall(r"\d{4}\.\d{2}\.\d{2}-[a-z0-9]+", out)
                elif key == "auth":
                    try:
                        data = json.loads(p.stdout)
                        item["shape"] = list(data) if isinstance(data, dict) else type(data).__name__
                        item["boolean_fields"] = {k: v for k, v in data.items() if type(v) is bool}
                    except (ValueError, AttributeError):
                        item["json"] = False
                    item["logged_in_marker"] = bool(re.search(r"logged in|authenticated", out, re.I))
                else:
                    # Extract model IDs, never unrestricted diagnostic output.
                    item["model_ids"] = re.findall(r"^\s*([a-z][a-z0-9_.-]+)\s+-\s+", out, re.M)[:100]
                    item["output_chars"] = len(out)
                result[key] = item
            except subprocess.TimeoutExpired:
                result[key] = {"timeout": True}
    print(json.dumps(result, indent=2))
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
