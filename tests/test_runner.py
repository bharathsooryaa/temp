"""Tool runner allow-list and workspace path jail."""

import pytest

from guardian.tools.runner import (
    TOOLS_BIN,
    WORKSPACE,
    PathJailError,
    ToolError,
    jail,
    run_tool,
    tool_path,
    workspace_relative,
)


def test_jail_accepts_workspace_paths():
    assert jail("targets") == (WORKSPACE / "targets").resolve()
    assert workspace_relative(WORKSPACE / "runs" / "x") == "runs/x"


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "runs/../../outside"])
def test_jail_rejects_escapes(path):
    with pytest.raises(PathJailError):
        jail(path)


def test_jail_rejects_symlink_escape(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "link").symlink_to(tmp_path)
    with pytest.raises(PathJailError):
        jail("link/secret", workspace=workspace)


@pytest.mark.parametrize("tool", ["bash", "sh", "curl", "npm", "../bin/sh", "syft;rm"])
def test_only_allow_listed_tools(tool):
    with pytest.raises(ToolError, match="not allow-listed"):
        tool_path(tool)
    with pytest.raises(ToolError):
        run_tool(tool, ["--version"])


@pytest.mark.integration
@pytest.mark.skipif(not (TOOLS_BIN / "syft").exists(), reason="pinned syft not installed")
def test_syft_runs_with_minimal_environment():
    run = run_tool("syft", ["--version"], timeout_s=30)
    assert run.returncode == 0
    assert run.stdout.decode().startswith("syft 1.57.2")
