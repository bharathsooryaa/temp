"""Dependency-graph contract: nodes are components, edges are 'depends on'."""

from __future__ import annotations

from collections import deque
from enum import StrEnum

from pydantic import Field, PrivateAttr, model_validator

from guardian.schemas.common import GuardianModel
from guardian.schemas.sbom import DependencyScope, SbomComponent


class EdgeKind(StrEnum):
    DEPENDS_ON = "depends_on"
    DEV_DEPENDS_ON = "dev_depends_on"  # root -> direct devDependency
    OPTIONAL_DEPENDS_ON = "optional_depends_on"
    PEER_DEPENDS_ON = "peer_depends_on"
    CONTAINS = "contains"  # e.g. image layer contains an OS package


class GraphEdge(GuardianModel):
    source: str = Field(min_length=1, description="Node ID of the dependent.")
    target: str = Field(min_length=1, description="Node ID of the dependency.")
    kind: EdgeKind = EdgeKind.DEPENDS_ON


class DependencyGraph(GuardianModel):
    """Serializable graph, validated so that every edge endpoint is a known node.

    Kept dependency-free. The graph-store choice (NetworkX or otherwise) is deferred.
    """

    root: str = Field(min_length=1, description="Node ID of the application itself.")
    nodes: tuple[SbomComponent, ...]
    edges: tuple[GraphEdge, ...] = ()

    _index: dict[str, SbomComponent] = PrivateAttr(default_factory=dict)
    _out: dict[str, list[str]] = PrivateAttr(default_factory=dict)
    _in: dict[str, list[str]] = PrivateAttr(default_factory=dict)

    @model_validator(mode="after")
    def _consistent(self) -> DependencyGraph:
        index = {n.bom_ref: n for n in self.nodes}
        if len(index) != len(self.nodes):
            raise ValueError("duplicate bom_ref in nodes")
        if self.root not in index:
            raise ValueError(f"root {self.root!r} is not a node")
        out: dict[str, list[str]] = {}
        inc: dict[str, list[str]] = {}
        for edge in self.edges:
            missing = {edge.source, edge.target} - index.keys()
            if missing:
                raise ValueError(f"edge references unknown node(s): {sorted(missing)}")
            out.setdefault(edge.source, []).append(edge.target)
            inc.setdefault(edge.target, []).append(edge.source)
        self._index, self._out, self._in = index, out, inc
        return self

    def node(self, bom_ref: str) -> SbomComponent:
        return self._index[bom_ref]

    def children(self, bom_ref: str) -> tuple[str, ...]:
        return tuple(self._out.get(bom_ref, ()))

    def _bfs(self, start: str, exclude_dev: bool = False) -> dict[str, str | None]:
        dev_edges = (
            {(e.source, e.target) for e in self.edges if e.kind is EdgeKind.DEV_DEPENDS_ON}
            if exclude_dev
            else set()
        )
        previous: dict[str, str | None] = {start: None}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for nxt in self._out.get(current, ()):
                if nxt in previous or (current, nxt) in dev_edges:
                    continue
                if exclude_dev and self._index[nxt].scope is DependencyScope.DEV:
                    continue
                previous[nxt] = current
                queue.append(nxt)
        return previous

    def shortest_path(self, target: str, exclude_dev: bool = False) -> tuple[str, ...] | None:
        """Shortest root-to-target path of node IDs, or None if unreachable.

        ``exclude_dev`` searches only runtime nodes and edges, so the path shown for a
        production package is one that exists in a production install.
        """
        if target not in self._index:
            raise KeyError(target)
        previous = self._bfs(self.root, exclude_dev)
        if target not in previous:
            return None
        path: list[str] = []
        step: str | None = target
        while step is not None:
            path.append(step)
            step = previous[step]
        return tuple(reversed(path))

    def depths(self) -> dict[str, int]:
        """Shortest distance from the root for every reachable node (root is 0)."""
        depth = {self.root: 0}
        queue = deque([self.root])
        while queue:
            current = queue.popleft()
            for nxt in self._out.get(current, ()):
                if nxt not in depth:
                    depth[nxt] = depth[current] + 1
                    queue.append(nxt)
        return depth

    def introduced_by(self, target: str) -> tuple[str, ...]:
        """Direct dependencies of the root from which ``target`` is reachable.

        Answers the PDF's core path question: which top-level dependency pulls this in?
        A direct dependency returns itself.
        """
        if target not in self._index:
            raise KeyError(target)
        direct = set(self._out.get(self.root, ()))
        seen = {target}
        queue = deque([target])
        found: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in direct:
                found.add(current)
            for parent in self._in.get(current, ()):
                if parent not in seen and parent != self.root:
                    seen.add(parent)
                    queue.append(parent)
        return tuple(sorted(found))

    def label(self, bom_ref: str) -> str:
        c = self.node(bom_ref).component
        return f"{c.name}@{c.version}" if c.version else c.name

    def path_labels(self, path: tuple[str, ...]) -> tuple[str, ...]:
        """Turn node IDs into 'name@version' labels for Finding.dependency_path."""
        return tuple(self.label(p) for p in path)
