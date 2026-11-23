"""CLI:  uv run --locked python -m guardian.sbom build --target nodegoat --out runs/<name>
uv run --locked python -m guardian.sbom path --graph runs/<name>/graph.json --package qs
"""

from __future__ import annotations

import argparse
import json
import sys

from guardian.sbom.build import build
from guardian.schemas.graph import DependencyGraph
from guardian.schemas.sbom import DependencyScope
from guardian.tools.runner import jail


def cmd_build(args: argparse.Namespace) -> int:
    summary = build(args.target, args.out)
    g, x = summary["graph"], summary["cross_check_vs_sbom"]
    print(
        f"SBOM   {summary['artifacts']['sbom']['file']}  ({summary['sbom']['components']} "
        f"components, {summary['artifacts']['sbom']['format']})"
    )
    print(f"Graph  {g['nodes']} nodes, {g['edges']} edges, max depth {g['max_depth']}")
    print(
        f"       runtime {g['unique_runtime_packages']} unique / dev "
        f"{g['unique_dev_packages']} unique; direct runtime {len(g['direct']['runtime'])}, "
        f"direct dev {len(g['direct']['dev'])}"
    )
    print(
        f"Check  lockfile graph vs SBOM agree: {x['agrees']} "
        f"({x['graph_runtime_unique']} vs {x['sbom_npm_unique']})"
    )
    return 0 if x["agrees"] and not g["unresolved_required"] else 1


def cmd_path(args: argparse.Namespace) -> int:
    graph = DependencyGraph.model_validate_json(jail(args.graph).read_text())
    matches = [
        n
        for n in graph.nodes
        if n.component.name == args.package
        and (args.version is None or n.component.version == args.version)
    ]
    if not matches:
        print(f"{args.package} not found", file=sys.stderr)
        return 1
    for n in matches:
        runtime = n.scope is not DependencyScope.DEV
        path = (runtime and graph.shortest_path(n.bom_ref, exclude_dev=True)) or (
            graph.shortest_path(n.bom_ref)
        )
        loc = n.locations[0] if n.locations else None
        print(
            json.dumps(
                {
                    "package": graph.label(n.bom_ref),
                    "install_path": n.bom_ref,
                    "scope": n.scope.value,
                    "dependency_path": list(graph.path_labels(path)) if path else None,
                    "introduced_by": [graph.label(d) for d in graph.introduced_by(n.bom_ref)],
                    "evidence": f"{loc.file}:{loc.line}" if loc else None,
                }
            )
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian.sbom")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="generate SBOM and dependency graph for a target")
    b.add_argument("--target", required=True)
    b.add_argument("--out", required=True)
    b.set_defaults(func=cmd_build)
    p = sub.add_parser("path", help="show dependency paths for a package")
    p.add_argument("--graph", required=True)
    p.add_argument("--package", required=True)
    p.add_argument("--version")
    p.set_defaults(func=cmd_path)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
