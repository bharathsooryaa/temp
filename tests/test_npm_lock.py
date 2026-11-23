"""npm lockfile parsing, npm resolution, graph building and graph queries."""

import json

import pytest

from guardian.sbom.npm_lock import (
    ROOT_ID,
    LockfileError,
    build_graph,
    parse_lockfile,
    purl,
    resolve,
)
from guardian.schemas.graph import EdgeKind
from guardian.schemas.sbom import DependencyScope

LOCK = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"a": "^1", "@s/b": "^2"},
            "devDependencies": {"t": "^1"},
            "optionalDependencies": {"fse": "^1"},  # not installed -> unresolved optional
        },
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^2"}},
        "node_modules/a/node_modules/c": {"version": "2.0.0"},  # nested copy wins for a
        "node_modules/c": {"version": "1.0.0", "integrity": "sha512-x"},
        "node_modules/@s/b": {
            "version": "2.0.0",
            "dependencies": {"d": "^1"},
            "peerDependencies": {"a": "*"},
        },
        "node_modules/d": {"version": "1.0.0", "dependencies": {"c": "^1"}},
        "node_modules/t": {"version": "1.0.0", "dev": True, "dependencies": {"c": "^1"}},
        "node_modules/x": {"version": "1.0.0", "dependencies": {"ghost": "1"}},  # orphan
    },
}


@pytest.fixture
def lock(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(LOCK, indent=2))
    return parse_lockfile(path, "fixture/package-lock.json"), path.read_text().splitlines()


def test_line_numbers_point_at_entry_keys(lock):
    parsed, lines = lock
    for key in ("", "node_modules/a", "node_modules/@s/b", "node_modules/a/node_modules/c"):
        line = parsed.entries[key].line
        assert line is not None
        assert lines[line - 1].strip().startswith(f'"{key}": {{')


def test_npm_resolution_prefers_nearest_nested_copy(lock):
    parsed, _ = lock
    assert resolve(parsed, "node_modules/a", "c") == "node_modules/a/node_modules/c"
    assert resolve(parsed, "node_modules/d", "c") == "node_modules/c"
    assert resolve(parsed, "node_modules/a/node_modules/c", "a") == "node_modules/a"
    assert resolve(parsed, "", "@s/b") == "node_modules/@s/b"
    assert resolve(parsed, "", "missing") is None


def test_scoped_purl_is_percent_encoded():
    assert purl("@s/b", "2.0.0") == "pkg:npm/%40s/b@2.0.0"
    assert purl("lodash", "4.17.15") == "pkg:npm/lodash@4.17.15"
    assert purl("x", "1.0.0+build.1") == "pkg:npm/x@1.0.0%2Bbuild.1"
    assert purl("x", None) == "pkg:npm/x"


def test_graph_nodes_scope_direct_and_locations(lock):
    parsed, _ = lock
    graph, _ = build_graph(parsed)
    assert graph.root == ROOT_ID
    assert len(graph.nodes) == len(LOCK["packages"])
    assert graph.node("node_modules/t").scope is DependencyScope.DEV
    assert graph.node("node_modules/c").scope is DependencyScope.RUNTIME
    assert graph.node("node_modules/a").direct is True
    assert graph.node("node_modules/@s/b").direct is True
    assert graph.node("node_modules/t").direct is True
    assert graph.node("node_modules/c").direct is False
    assert graph.node(ROOT_ID).direct is None
    loc = graph.node("node_modules/a").locations[0]
    assert loc.file == "fixture/package-lock.json"
    assert loc.line == parsed.entries["node_modules/a"].line


def test_graph_edge_kinds(lock):
    parsed, _ = lock
    graph, _ = build_graph(parsed)
    kinds = {(e.source, e.target): e.kind for e in graph.edges}
    assert kinds[(ROOT_ID, "node_modules/a")] is EdgeKind.DEPENDS_ON
    assert kinds[(ROOT_ID, "node_modules/t")] is EdgeKind.DEV_DEPENDS_ON
    assert kinds[("node_modules/@s/b", "node_modules/a")] is EdgeKind.PEER_DEPENDS_ON
    assert kinds[("node_modules/a", "node_modules/a/node_modules/c")] is EdgeKind.DEPENDS_ON


def test_unresolved_dependencies_reported_not_invented(lock):
    parsed, _ = lock
    _, unresolved = build_graph(parsed)
    assert {(u.source, u.name, u.kind) for u in unresolved} == {
        (ROOT_ID, "fse", EdgeKind.OPTIONAL_DEPENDS_ON),
        ("node_modules/x", "ghost", EdgeKind.DEPENDS_ON),
    }


def test_paths_depths_and_introduced_by(lock):
    parsed, _ = lock
    graph, _ = build_graph(parsed)
    # Shortest overall path goes through the dev dependency t ...
    assert graph.shortest_path("node_modules/c") == (ROOT_ID, "node_modules/t", "node_modules/c")
    # ... but a production install reaches c only through @s/b -> d.
    assert graph.shortest_path("node_modules/c", exclude_dev=True) == (
        ROOT_ID,
        "node_modules/@s/b",
        "node_modules/d",
        "node_modules/c",
    )
    assert graph.path_labels(graph.shortest_path("node_modules/c", exclude_dev=True)) == (
        "demo@1.0.0",
        "@s/b@2.0.0",
        "d@1.0.0",
        "c@1.0.0",
    )
    assert graph.introduced_by("node_modules/c") == ("node_modules/@s/b", "node_modules/t")
    assert graph.introduced_by("node_modules/a") == ("node_modules/@s/b", "node_modules/a")
    assert graph.shortest_path("node_modules/x") is None
    depths = graph.depths()
    assert depths[ROOT_ID] == 0
    assert depths["node_modules/a/node_modules/c"] == 2
    assert "node_modules/x" not in depths


def test_graph_json_round_trip_keeps_queries(lock):
    parsed, _ = lock
    graph, _ = build_graph(parsed)
    again = type(graph).model_validate_json(graph.model_dump_json())
    assert again == graph
    assert again.introduced_by("node_modules/c") == graph.introduced_by("node_modules/c")


def test_rejects_v1_and_invalid_lockfiles(tmp_path):
    v1 = tmp_path / "v1.json"
    v1.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    with pytest.raises(LockfileError, match="lockfileVersion 2 or 3"):
        parse_lockfile(v1, "v1.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(LockfileError, match="invalid JSON"):
        parse_lockfile(bad, "bad.json")
