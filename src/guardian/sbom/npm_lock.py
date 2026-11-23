"""Deterministic npm lockfile (v2/v3) parser and dependency-graph builder.

The graph follows npm's resolution rule. A dependency ``n`` of the package installed at path
``P`` resolves to the nearest ``<ancestor>/node_modules/n``, searching ``P`` first and then
each enclosing install path up to the root. Every node keeps its lockfile line number, so a
finding can cite ``package-lock.json:<line>``.

Lockfile content is untrusted data. It is parsed as JSON only and nothing in it is executed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from guardian.schemas.common import Ecosystem
from guardian.schemas.graph import DependencyGraph, EdgeKind, GraphEdge
from guardian.schemas.sbom import Component, DependencyScope, SbomComponent, SourceLocation

ROOT_ID = "."
_KEY_LINE = re.compile(r'^\s*"((?:node_modules/[^"\\]*)|)":\s*\{')


class LockfileError(ValueError):
    pass


@dataclass(frozen=True)
class LockEntry:
    path: str  # lockfile key; "" is the root project
    name: str
    version: str | None
    dev: bool = False
    optional: bool = False
    dev_optional: bool = False
    resolved: str | None = None
    integrity: str | None = None
    link: bool = False
    has_install_script: bool = False
    in_bundle: bool = False  # shipped inside a parent's tarball; covered by its integrity
    line: int | None = None
    dependencies: dict[str, str] = field(default_factory=dict)
    optional_dependencies: dict[str, str] = field(default_factory=dict)
    peer_dependencies: dict[str, str] = field(default_factory=dict)
    dev_dependencies: dict[str, str] = field(default_factory=dict)  # root only


@dataclass(frozen=True)
class Unresolved:
    source: str
    name: str
    kind: EdgeKind


@dataclass(frozen=True)
class NpmLock:
    file: str  # workspace-relative path of the lockfile
    lockfile_version: int
    entries: dict[str, LockEntry]
    unresolved: tuple[Unresolved, ...] = ()

    @property
    def root(self) -> LockEntry:
        return self.entries[""]


def _name_from_path(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def _ancestors(path: str):
    """Yield ``path`` and each enclosing install path, ending with the root ("")."""
    yield path
    while path:
        idx = path.rfind("/node_modules/")
        path = path[:idx] if idx != -1 else ""
        yield path


def _candidate(base: str, name: str) -> str:
    return f"{base}/node_modules/{name}" if base else f"node_modules/{name}"


def _key_lines(text: str) -> dict[str, int]:
    """Map each 'packages' key to its 1-based line number (first occurrence)."""
    lines: dict[str, int] = {}
    in_packages = False
    for number, line in enumerate(text.splitlines(), start=1):
        if not in_packages:
            if re.match(r'^\s*"packages":\s*\{', line):
                in_packages = True
            continue
        match = _KEY_LINE.match(line)
        if match and match.group(1) not in lines:
            lines[match.group(1)] = number
        if re.match(r"^  \}", line):  # end of the top-level "packages" object
            break
    return lines


def parse_lockfile(path: Path, workspace_relative_file: str) -> NpmLock:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockfileError(f"{workspace_relative_file}: invalid JSON: {exc}") from exc
    version = data.get("lockfileVersion")
    packages = data.get("packages")
    if version not in (2, 3) or not isinstance(packages, dict) or "" not in packages:
        raise LockfileError(
            f"{workspace_relative_file}: need lockfileVersion 2 or 3 with a 'packages' map "
            f"(got lockfileVersion={version!r})"
        )
    lines = _key_lines(text)

    def as_map(value: object) -> dict[str, str]:
        return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}

    entries: dict[str, LockEntry] = {}
    for key, raw in packages.items():
        if not isinstance(raw, dict):
            raise LockfileError(f"{workspace_relative_file}: entry {key!r} is not an object")
        entries[key] = LockEntry(
            path=key,
            name=str(raw.get("name") or (_name_from_path(key) if key else "app")),
            version=str(raw["version"]) if "version" in raw else None,
            dev=bool(raw.get("dev")),
            optional=bool(raw.get("optional")),
            dev_optional=bool(raw.get("devOptional")),
            resolved=raw.get("resolved"),
            integrity=raw.get("integrity"),
            link=bool(raw.get("link")),
            has_install_script=bool(raw.get("hasInstallScript")),
            in_bundle=bool(raw.get("inBundle")),
            line=lines.get(key),
            dependencies=as_map(raw.get("dependencies")),
            optional_dependencies=as_map(raw.get("optionalDependencies")),
            peer_dependencies=as_map(raw.get("peerDependencies")),
            dev_dependencies=as_map(raw.get("devDependencies")) if key == "" else {},
        )
    return NpmLock(file=workspace_relative_file, lockfile_version=version, entries=entries)


def resolve(lock: NpmLock, source: str, name: str) -> str | None:
    """Install path that ``name`` resolves to when required from ``source``, or None."""
    for base in _ancestors(source):
        target = _candidate(base, name)
        entry = lock.entries.get(target)
        if entry is not None:
            if entry.link and entry.resolved in lock.entries:
                return entry.resolved
            return target
    return None


def purl(name: str, version: str | None) -> str:
    if name.startswith("@") and "/" in name:
        scope, _, pkg = name.partition("/")
        base = f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}"
    else:
        base = f"pkg:npm/{quote(name, safe='')}"
    return f"{base}@{quote(version, safe='.-_~')}" if version else base


def build_graph(lock: NpmLock) -> tuple[DependencyGraph, tuple[Unresolved, ...]]:
    """Build the full graph (runtime and dev). Returns the graph and any unresolved deps."""
    root = lock.root
    direct_names = (
        set(root.dependencies)
        | set(root.dev_dependencies)
        | set(root.optional_dependencies)
        | set(root.peer_dependencies)
    )

    def node_id(path: str) -> str:
        return ROOT_ID if path == "" else path

    nodes: list[SbomComponent] = []
    for path, entry in lock.entries.items():
        if entry.link:
            continue  # links are aliases; edges go to their resolved target
        is_root = path == ""
        location = SourceLocation(file=lock.file, line=entry.line)
        nodes.append(
            SbomComponent(
                bom_ref=node_id(path),
                component=Component(
                    name=entry.name,
                    version=entry.version,
                    purl=purl(entry.name, entry.version),
                    ecosystem=Ecosystem.NPM,
                ),
                scope=(
                    DependencyScope.RUNTIME
                    if is_root
                    else DependencyScope.DEV
                    if entry.dev
                    else DependencyScope.RUNTIME
                ),
                direct=None
                if is_root
                else (path == f"node_modules/{entry.name}" and entry.name in direct_names),
                optional=entry.optional or entry.dev_optional,
                locations=(location,),
            )
        )

    edges: list[GraphEdge] = []
    unresolved: list[Unresolved] = []
    seen: set[tuple[str, str]] = set()
    for path, entry in lock.entries.items():
        if entry.link:
            continue
        groups: list[tuple[dict[str, str], EdgeKind]] = [
            (entry.dependencies, EdgeKind.DEPENDS_ON),
            (entry.optional_dependencies, EdgeKind.OPTIONAL_DEPENDS_ON),
            (entry.peer_dependencies, EdgeKind.PEER_DEPENDS_ON),
        ]
        if path == "":
            groups.insert(1, (entry.dev_dependencies, EdgeKind.DEV_DEPENDS_ON))
        for deps, kind in groups:
            for name in deps:
                target = resolve(lock, path, name)
                if target is None:
                    unresolved.append(Unresolved(node_id(path), name, kind))
                    continue
                pair = (node_id(path), node_id(target))
                if pair in seen:
                    continue  # e.g. listed as both a dependency and a peer
                seen.add(pair)
                edges.append(GraphEdge(source=pair[0], target=pair[1], kind=kind))

    graph = DependencyGraph(root=ROOT_ID, nodes=tuple(nodes), edges=tuple(edges))
    return graph, tuple(unresolved)
