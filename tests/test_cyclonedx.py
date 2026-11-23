"""CycloneDX reader and the lockfile-vs-SBOM cross-check."""

import json

import pytest

from guardian.sbom.cyclonedx import SbomError, cross_check, load_bom
from guardian.schemas import Component, DependencyGraph, DependencyScope, GraphEdge, SbomComponent


def bom(**overrides):
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "root", "type": "file", "name": "t"}},
        "components": [
            {"bom-ref": "a", "type": "library", "name": "a", "version": "1.0.0",
             "purl": "pkg:npm/a@1.0.0",
             "properties": [{"name": "syft:package:foundBy",
                             "value": "javascript-lock-cataloger"}]},
            {"bom-ref": "b", "type": "library", "name": "b", "version": "2.0.0",
             "purl": "pkg:npm/b@2.0.0"},
            {"bom-ref": "gh", "type": "library", "name": "actions/checkout", "version": "v2",
             "purl": "pkg:github/actions/checkout@v2"},
        ],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    }  # fmt: skip
    data.update(overrides)
    return data


def write(tmp_path, data):
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps(data))
    return path


def test_load_bom(tmp_path):
    parsed = load_bom(write(tmp_path, bom()))
    assert parsed.spec_version == "1.5"
    assert len(parsed.components) == 3
    assert [c.name for c in parsed.by_purl_type("npm")] == ["a", "b"]
    assert parsed.components[0].found_by == "javascript-lock-cataloger"
    assert parsed.dependencies == {"a": ("b",)}


@pytest.mark.parametrize("override", [{"specVersion": "1.4"}, {"bomFormat": "SPDX"}])
def test_rejects_wrong_format_or_version(tmp_path, override):
    with pytest.raises(SbomError, match=r"expected CycloneDX 1\.5"):
        load_bom(write(tmp_path, bom(**override)))


def test_rejects_dangling_dependency_refs(tmp_path):
    with pytest.raises(SbomError, match="not in components"):
        load_bom(write(tmp_path, bom(dependencies=[{"ref": "a", "dependsOn": ["ghost"]}])))


def node(ref, name, version, scope=DependencyScope.RUNTIME):
    return SbomComponent(bom_ref=ref, component=Component(name=name, version=version), scope=scope)


def test_cross_check_ignores_dev_and_reports_differences(tmp_path):
    parsed = load_bom(write(tmp_path, bom()))
    graph = DependencyGraph(
        root="a",
        nodes=(
            node("a", "a", "1.0.0"),
            node("b1", "b", "2.0.0"),
            node("b2", "b", "2.0.0"),  # same name@version at a second install path
            node("t", "t", "1.0.0", DependencyScope.DEV),
        ),
        edges=(GraphEdge(source="a", target="b1"),),
    )
    result = cross_check(graph, parsed)
    assert result.agrees
    assert (result.graph_runtime, result.sbom_npm) == (2, 2)

    extra = DependencyGraph(root="a", nodes=(node("a", "a", "1.0.0"), node("z", "z", "9")))
    result = cross_check(extra, parsed)
    assert not result.agrees
    assert result.only_in_graph == ("z@9",)
    assert result.only_in_sbom == ("b@2.0.0",)
