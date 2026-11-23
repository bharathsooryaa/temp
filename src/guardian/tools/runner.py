"""Allow-listed, bounded execution of pinned scanner binaries.

* Only binaries named in ``ALLOWED_TOOLS`` and present in ``tools/bin`` may run.
* argv lists only, never a shell. A fixed minimal environment, so no inherited secrets.
* Every path argument must resolve inside the workspace (the path jail).
* Hard timeout, and stdout/stderr size caps.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[3]
TOOLS_BIN = WORKSPACE / "tools" / "bin"
TOOL_HOME = WORKSPACE / "cache" / "tool-home"

ALLOWED_TOOLS = frozenset({"syft", "grype", "osv-scanner", "trivy", "hadolint", "zizmor"})

# Disable update checks and telemetry. Values are fixed, never read from the target repo.
BASE_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
}

MAX_OUTPUT_BYTES = 64 * 1024 * 1024
UNSHARE = "/usr/bin/unshare"


class ToolError(RuntimeError):
    pass


class PathJailError(ToolError):
    pass


def jail(path: str | Path, workspace: Path = WORKSPACE) -> Path:
    """Resolve ``path`` (relative paths are taken from the workspace) and require it inside."""
    candidate = Path(path)
    resolved = (candidate if candidate.is_absolute() else workspace / candidate).resolve()
    if not resolved.is_relative_to(workspace.resolve()):
        raise PathJailError(f"path escapes workspace: {path}")
    return resolved


def workspace_relative(path: str | Path, workspace: Path = WORKSPACE) -> str:
    return jail(path, workspace).relative_to(workspace.resolve()).as_posix()


@dataclass(frozen=True)
class ToolRun:
    tool: str
    argv: tuple[str, ...]
    returncode: int
    duration_s: float
    stdout: bytes
    stderr: bytes


def tool_path(tool: str) -> Path:
    if tool not in ALLOWED_TOOLS:
        raise ToolError(f"tool not allow-listed: {tool!r}")
    binary = TOOLS_BIN / tool
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ToolError(f"{tool} is not installed in tools/bin (run scripts/install_tools.py)")
    return binary


def run_tool(
    tool: str,
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout_s: float = 600,
    check: bool = True,
    offline: bool = False,
    ok_codes: frozenset[int] = frozenset({0}),
) -> ToolRun:
    """Run an allow-listed tool. Callers must pass any path through ``jail()`` first.

    ``offline=True`` runs the tool in a fresh, empty network namespace (``unshare -rn``),
    so it cannot reach any host, whatever its flags say. ``ok_codes`` lists exit codes that
    are not failures (OSV-Scanner exits 1 when it finds vulnerabilities).
    """
    binary = tool_path(tool)
    TOOL_HOME.mkdir(parents=True, exist_ok=True)
    run_env = {**BASE_ENV, "HOME": str(TOOL_HOME), **(env or {})}
    argv = (*((UNSHARE, "-rn") if offline else ()), str(binary), *args)
    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - allow-listed binary, argv list, no shell
            argv,
            cwd=WORKSPACE,
            env=run_env,
            capture_output=True,
            timeout=timeout_s,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{tool} timed out after {timeout_s}s") from exc
    duration = time.monotonic() - start
    if len(proc.stdout) > MAX_OUTPUT_BYTES or len(proc.stderr) > MAX_OUTPUT_BYTES:
        raise ToolError(f"{tool} output exceeded {MAX_OUTPUT_BYTES} bytes")
    run = ToolRun(tool, argv, proc.returncode, duration, proc.stdout, proc.stderr)
    if check and proc.returncode not in ok_codes:
        tail = proc.stderr.decode(errors="replace")[-2000:]
        raise ToolError(f"{tool} exited {proc.returncode}: {tail}")
    return run


def tool_version(tool: str) -> str:
    """First line of ``<tool> --version``, e.g. 'syft 1.57.2'."""
    run = run_tool(tool, ["--version"], timeout_s=30)
    return run.stdout.decode(errors="replace").strip().splitlines()[0]
