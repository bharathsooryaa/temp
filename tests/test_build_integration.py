"""End-to-end D1.S3 check on the pinned NodeGoat target (skipped if tools or target missing)."""

import json
import shutil

import pytest

from guardian.sbom.build import TargetError, build, load_target
from guardian.schemas.graph import DependencyGraph
from guardian.tools.runner import TOOLS_BIN, WORKSPACE

TARGET = WORKSPACE / "targets" / "nodegoat"
needs_target = pytest.mark.skipif(
    not (TOOLS_BIN / "syft").exists() or not (TARGET / "package-lock.json").exists(),
    reason="pinned syft or NodeGoat checkout not present",
)


def test_unknown_target_rejected():
    with pytest.raises(TargetError, match="unknown target"):
        load_target("not-registered")


@pytest.mark.integration
@needs_target
def test_nodegoat_build():
    out = WORKSPACE / "runs" / "pytest-d1s3"
    shutil.rmtree(out, ignore_errors=True)
    summary = build("nodegoat", out)

    sbom = json.loads((out / "sbom.cdx.json").read_text())
    assert (sbom["bomFormat"], sbom["specVersion"]) == ("CycloneDX", "1.5")

    g = summary["graph"]
    assert summary["cross_check_vs_sbom"]["agrees"] is True
    assert g["unresolved_required"] == []
    assert g["unreachable_from_root"] == []
    assert len(g["direct"]["runtime"]) == 16
    assert len(g["direct"]["dev"]) == 20
    assert 150 <= g["unique_runtime_packages"] <= 600  # PDF section 8 selection criterion
    assert summary["discovered_files"]["dockerfiles"] == ["targets/nodegoat/Dockerfile"]
    assert len(summary["discovered_files"]["ci"]) == 2

    graph = DependencyGraph.model_validate_json((out / "graph.json").read_text())
    marked = graph.node("node_modules/marked")
    assert graph.path_labels(graph.shortest_path(marked.bom_ref)) == (
        "owasp-nodejs-goat@1.3.0",
        "marked@0.3.5",
    )
    line = marked.locations[0].line
    lock_lines = (TARGET / "package-lock.json").read_text().splitlines()
    assert lock_lines[line - 1].strip() == '"node_modules/marked": {'
