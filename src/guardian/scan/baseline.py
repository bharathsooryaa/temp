"""D1.S4: scanner-only baseline (PDF phase 1 exit test).

The baseline lists components, CVEs, severity and fix versions with dependency paths. Every
value comes from tool output or the offline feeds. Scanners run in an empty network namespace.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from guardian.sbom.build import build as build_sbom
from guardian.sbom.build import load_target
from guardian.sbom.npm_lock import parse_lockfile
from guardian.scan.anomaly import (
    TopList,
    anomaly_drafts,
    diff_rules,
    single_commit_rules,
)
from guardian.scan.common import (
    Draft,
    EvidenceStore,
    assemble,
    excerpt,
    exploit_refs,
    fixed_by_tool,
    group_summary,
    pointer_excerpt,
    ref_of,
    sort_key,
)
from guardian.scan.context import enrich, resolve_top_level, scan_app
from guardian.scan.feeds import EpssFeed, KevFeed, load_epss, load_kev
from guardian.scan.parsers import (
    VulnGroup,
    correlate,
    parse_grype,
    parse_osv,
    parse_trivy,
)
from guardian.scan.posture import (
    config_drafts,
    dockerfile_rules,
    eosl_hit,
    image_drafts,
    load_image,
    parse_from_lines,
    parse_hadolint,
    parse_trivy_config,
    parse_zizmor,
    run_posture_tools,
    workflow_rules,
)
from guardian.schemas.evidence import EvidenceKind, EvidenceRef
from guardian.schemas.finding import FindingSet, FindingType
from guardian.schemas.graph import DependencyGraph
from guardian.schemas.risk import Exposure, RiskFactors
from guardian.schemas.sbom import DependencyScope
from guardian.store import DEFAULT_DB, connect, save_run
from guardian.tools.runner import WORKSPACE, jail, run_tool, tool_version, workspace_relative

CACHE = WORKSPACE / "cache"
SCANNERS = ("grype", "trivy", "osv-scanner")
DEPENDENCY_TYPES = frozenset(
    {
        FindingType.VULNERABLE_DIRECT,
        FindingType.VULNERABLE_TRANSITIVE,
        FindingType.MALICIOUS_PACKAGE,
    }
)
CONTEXT_TOOLS = frozenset({"dependency-graph", "epss", "cisa-kev", "oci-layout"})


def image_line(stats: dict | None) -> str:
    if not stats:
        return "none"
    return (
        f"{stats['image']}@{stats['manifest_digest'][:19]}… "
        f"({stats['groups']} advisory groups; Grype CPE-only matches excluded: "
        f"{stats['grype_cpe_only_excluded']})"
    )


# --- running the scanners (offline) --------------------------------------------------------


def run_scanners(target_root: Path, lockfile: Path, out: Path) -> dict[str, str]:
    """Run Grype, Trivy and OSV-Scanner with no network. Returns output files by tool."""
    full_sbom = out / "sbom-full.cdx.json"
    run_tool(
        "syft",
        ["scan", f"dir:{jail(target_root)}", "-q", "-o", f"cyclonedx-json@1.5={jail(full_sbom)}"],
        env={"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"},
        offline=True,
    )
    files = {t: out / f"{t.split('-')[0]}.json" for t in SCANNERS}
    run_tool(
        "grype",
        ["sbom:" + str(jail(full_sbom)), "-q", "-o", "json", "--file", str(jail(files["grype"]))],
        env={"GRYPE_DB_CACHE_DIR": str(CACHE / "grype"), "GRYPE_DB_AUTO_UPDATE": "false"},
        offline=True,
    )
    run_tool(
        "trivy",
        ["fs", "--scanners", "vuln", "--include-dev-deps", "--skip-db-update",
         "--skip-java-db-update", "--offline-scan", "--cache-dir", str(CACHE / "trivy"),
         "--quiet", "-f", "json", "-o", str(jail(files["trivy"])), str(jail(target_root))],
        offline=True,
    )  # fmt: skip
    run_tool(
        "osv-scanner",
        ["scan", "source", "--offline", "--format", "json",
         "--output-file", str(jail(files["osv-scanner"])), "-L", str(jail(lockfile))],
        env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(CACHE / "osv")},
        offline=True,
        ok_codes=frozenset({0, 1}),  # 1 = vulnerabilities found
    )  # fmt: skip
    return {t: workspace_relative(p) for t, p in files.items()}


# --- mapping scanner results to the graph -------------------------------------------------------


@dataclass(frozen=True)
class Placement:
    node: str  # representative install path
    path: tuple[str, ...]  # node IDs, root first
    install_paths: tuple[str, ...]
    all_dev: bool


def place(graph: DependencyGraph, nodes_by_label: dict[str, list[str]], label: str):
    """Pick the representative install path: runtime before dev, direct first, then shortest."""
    candidates = nodes_by_label.get(label, [])
    if not candidates:
        return None
    scored = []
    for node_id in candidates:
        node = graph.node(node_id)
        runtime = node.scope is not DependencyScope.DEV
        path = (runtime and graph.shortest_path(node_id, exclude_dev=True)) or graph.shortest_path(
            node_id
        )
        if path is None:
            continue
        scored.append((not runtime, not bool(node.direct), len(path), node_id, path))
    if not scored:
        return None
    scored.sort()
    _, _, _, node_id, path = scored[0]
    all_dev = all(graph.node(n).scope is DependencyScope.DEV for n in candidates)
    return Placement(node_id, path, tuple(sorted(candidates)), all_dev)


# --- building findings ---------------------------------------------------------------------


def make_findings(
    groups: list[VulnGroup],
    graph: DependencyGraph,
    lockfile: str,
    outputs: dict[str, str],
    versions: dict[str, str],
    epss: EpssFeed,
    kev: KevFeed,
) -> tuple[FindingSet, list[str]]:
    store = EvidenceStore()
    drafts, unmapped = vuln_drafts(store, groups, graph, lockfile, outputs, versions, epss, kev)
    return assemble(store, drafts), unmapped


def vuln_drafts(
    store: EvidenceStore,
    groups: list[VulnGroup],
    graph: DependencyGraph,
    lockfile: str,
    outputs: dict[str, str],
    versions: dict[str, str],
    epss: EpssFeed,
    kev: KevFeed,
) -> tuple[list[Draft], list[str]]:
    """Drafts for dependency vulnerabilities, placed on the lockfile graph."""
    nodes_by_label: dict[str, list[str]] = {}
    for n in graph.nodes:
        if n.bom_ref != graph.root:
            nodes_by_label.setdefault(graph.label(n.bom_ref), []).append(n.bom_ref)

    drafts: list[Draft] = []
    unmapped: list[str] = []

    for group in groups:
        label = f"{group.name}@{group.version}"
        placement = place(graph, nodes_by_label, label)
        if placement is None:
            unmapped.append(f"{label} ({', '.join(sorted(group.ids))})")
            continue
        node = graph.node(placement.node)
        line = node.locations[0].line if node.locations else None
        refs: list[EvidenceRef] = []

        for m in sorted(group.matches, key=lambda x: (x.tool, x.advisory_id, x.pointer)):
            rec = store.add(
                ("scan", m.tool, m.pointer),
                kind=EvidenceKind.SCANNER_RESULT,
                tool=m.tool,
                tool_version=versions.get(m.tool),
                ref=m.advisory_id,
                file=lockfile,
                line=line,
                excerpt=pointer_excerpt(outputs[m.tool], m.pointer, m.summary),
            )
            refs.append(ref_of(rec))

        labels = graph.path_labels(placement.path)
        rec = store.add(
            ("graph", placement.node),
            kind=EvidenceKind.GRAPH_NODE,
            tool="dependency-graph",
            graph_node=placement.node,
            excerpt=excerpt(
                " > ".join(labels) + f" | install paths: {len(placement.install_paths)}"
            ),
        )
        refs.append(ref_of(rec))

        exploit, epss_value, kev_flag, in_kev = exploit_refs(store, group, epss, kev)
        refs.extend(exploit)
        malicious = group.malicious
        if malicious:
            ftype = FindingType.MALICIOUS_PACKAGE
        elif node.direct and len(placement.path) == 2:
            ftype = FindingType.VULNERABLE_DIRECT
        else:
            ftype = FindingType.VULNERABLE_TRANSITIVE

        draft = {
            "type": ftype,
            "title": excerpt(f"{label}: {group_summary(group)}", 200),
            "component": node.component,
            "dependency_path": labels,
            "introduced_by": tuple(graph.label(d) for d in graph.introduced_by(placement.node)),
            "advisory_ids": tuple(sorted(group.ids)),
            "severity": group.severity,
            "fixed_in": fixed_by_tool(group),
            "evidence": tuple(refs),
            "factors": RiskFactors(
                cvss=group.cvss,
                epss=epss_value,
                kev=kev_flag,
                exposure=Exposure.BUILD_OR_DEV if placement.all_dev else Exposure.UNKNOWN,
                confirmed_malicious=malicious,
            ),
        }
        drafts.append((sort_key(malicious, in_kev, group.severity, group.cvss, label, group),
                       draft))  # fmt: skip
    return drafts, unmapped


# --- orchestration ------------------------------------------------------------------------


def db_metadata(grype_out: Path) -> dict:
    grype = json.loads(grype_out.read_text()).get("descriptor", {}).get("db", {}).get("status", {})
    trivy = json.loads((CACHE / "trivy" / "db" / "metadata.json").read_text())
    osv_zip = CACHE / "osv" / "osv-scalibr" / "npm" / "all.zip"
    feeds = json.loads((CACHE / "feeds" / "feeds.json").read_text())
    return {
        "grype_db": {"schema": grype.get("schemaVersion"), "built": grype.get("built")},
        "trivy_db": {"version": trivy.get("Version"), "updated_at": trivy.get("UpdatedAt")},
        "osv_npm_db": {
            "file": workspace_relative(osv_zip),
            "downloaded_at": datetime.fromtimestamp(osv_zip.stat().st_mtime, UTC).isoformat(
                timespec="seconds"
            ),
        },
        "feeds": feeds,
    }


def baseline(target_name: str, out_dir: str | Path, db: str | Path | None = DEFAULT_DB) -> dict:
    target = load_target(target_name)
    out = jail(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sbom_summary = build_sbom(target_name, out)

    root = jail(target["path"])
    lockfile = jail(Path(target["path"]) / target["lockfile"])
    outputs = run_scanners(root, lockfile, out)
    versions = {t: tool_version(t) for t in ("syft", *SCANNERS)}

    raw = [
        *parse_grype(jail(outputs["grype"])),
        *parse_trivy(jail(outputs["trivy"])),
        *parse_osv(jail(outputs["osv-scanner"])),
    ]
    groups = correlate(raw)
    graph = DependencyGraph.model_validate_json((out / "graph.json").read_text())

    # D1.S5: container image and CI/CD posture.
    dockerfile = root / "Dockerfile"
    froms = parse_from_lines(dockerfile) if dockerfile.exists() else []
    image = load_image(froms[-1].ref) if froms else None
    outputs.update(run_posture_tools(root, out, image))
    versions.update({t: tool_version(t) for t in ("hadolint", "zizmor")})
    workflows = [jail(p) for p in sbom_summary["discovered_files"]["ci"]]
    hits = [
        *(dockerfile_rules(dockerfile) if dockerfile.exists() else []),
        *(h for w in workflows for h in workflow_rules(w)),
        *parse_hadolint(jail(outputs["hadolint"])),
        *parse_trivy_config(jail(outputs["trivy-config"]), root),
        *parse_zizmor(jail(outputs["zizmor"])),
    ]
    dockerfile_rel = workspace_relative(dockerfile)
    if image is not None:
        eosl = eosl_hit(outputs, dockerfile_rel, froms[-1])
        hits.extend([eosl] if eosl else [])
        image_raw = [*parse_trivy(jail(outputs["trivy-image"])),
                     *parse_grype(jail(outputs["grype-image"]))]  # fmt: skip
    else:
        image_raw = []

    wanted = {c for g in groups for c in g.cves} | {
        i for m in image_raw for i in m.ids if i.startswith("CVE-")
    }
    epss = load_epss(CACHE / "feeds" / "epss_scores-current.csv.gz", wanted)
    kev = load_kev(CACHE / "feeds" / "known_exploited_vulnerabilities.json")

    store = EvidenceStore()
    drafts, unmapped = vuln_drafts(
        store, groups, graph, workspace_relative(lockfile), outputs, versions, epss, kev
    )
    drafts += config_drafts(store, hits, outputs, versions)

    # D1.S6: supply-chain anomaly rules (and diff rules against the base commit, if any).
    lock = parse_lockfile(lockfile, workspace_relative(lockfile))
    anomalies = single_commit_rules(lock, TopList.load())
    if target.get("base_target"):
        base = load_target(target["base_target"])
        base_lockfile = jail(Path(base["path"]) / base["lockfile"])
        base_lock = parse_lockfile(base_lockfile, workspace_relative(base_lockfile))
        anomalies += diff_rules(base_lock, lock, graph)
    drafts += anomaly_drafts(store, anomalies, graph)
    image_stats = None
    if image is not None:
        image_part, image_stats = image_drafts(
            store, image, froms[-1], dockerfile_rel, outputs, versions, epss, kev
        )
        drafts += image_part

    # D1.S7: reachability, exposure, provenance and risk score v1, then rank by risk.
    app = scan_app(root, dockerfile if dockerfile.exists() else None)
    resolve_top_level(app, lock)
    drafts = enrich(store, drafts, app)
    finding_set = assemble(store, drafts)
    (out / "findings.json").write_text(finding_set.model_dump_json(indent=1))

    f = finding_set.findings
    deps = [x for x in f if x.type in DEPENDENCY_TYPES]
    tool_count = Counter(len(g.tools) for g in groups)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "target": sbom_summary["target"],
        "tools": versions,
        "databases": db_metadata(jail(outputs["grype"])),
        "outputs": outputs,
        "raw_matches": dict(Counter(m.tool for m in raw)),
        "groups": len(groups),
        "groups_by_tool_count": {f"{k}_tools": v for k, v in sorted(tool_count.items())},
        "findings": len(f),
        "evidence_records": len(finding_set.evidence),
        "unmapped": unmapped,
        "by_type": dict(Counter(x.type.value for x in f)),
        "by_severity": dict(Counter(x.severity.value for x in f)),
        "dependency_findings": len(deps),
        "runtime_findings": sum(1 for x in deps if x.factors.exposure is not Exposure.BUILD_OR_DEV),
        "dev_only_findings": sum(1 for x in deps if x.factors.exposure is Exposure.BUILD_OR_DEV),
        "kev_findings": sum(1 for x in f if x.factors.kev),
        "with_fix": sum(1 for x in f if x.fixed_in),
        "vulnerable_packages": len({x.component.purl for x in deps}),
        "image": image_stats,
        "posture_hits": dict(Counter(f"{h.tool}:{h.rule}" for h in hits)),
        "anomaly_hits": dict(Counter(h.rule for h in anomalies)),
        "base_target": target.get("base_target"),
        "synthetic": bool(target.get("synthetic")),
        "by_risk_level": dict(Counter(x.risk.level.value for x in f if x.risk)),
        "by_reachability": dict(Counter(x.factors.reachability.value for x in f)),
        "by_exposure": dict(Counter(x.factors.exposure.value for x in f)),
        "app_context": {
            "runtime_imports": sorted(app.runtime_imports),
            "dev_imports": sorted(app.dev_imports),
            "network_facts": [f"{s.file}:{s.line}" for s in app.network_facts],
            "dynamic_requires": app.dynamic_requires,
        },
    }
    if db is not None:
        run_id = workspace_relative(out)
        summary["store"] = {"db": workspace_relative(jail(db)), "run_id": run_id}
    (out / "baseline.json").write_text(json.dumps(summary, indent=2))
    (out / "baseline.md").write_text(render_markdown(summary, finding_set))
    if db is not None:
        conn = connect(db)
        try:
            save_run(conn, run_id, summary, finding_set, graph)
        finally:
            conn.close()
    return summary


def render_markdown(summary: dict, fs: FindingSet) -> str:
    t = summary["target"]
    lines = [
        f"# Scanner-only baseline: {t['name']} @ {t['commit'][:12]}"
        + (" (SYNTHETIC seeded fork)" if summary.get("synthetic") else ""),
        "",
        f"Generated {summary['generated_at']}. Scanners ran offline (empty network namespace).",
        "Every value below comes from tool output or the cached EPSS and KEV feeds.",
        "Findings are ranked by risk score v1 (PDF formula; unknown factors are left out and the",
        "rest re-weighted, shown as coverage). Dependency counts cover the app's npm packages.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Findings | {summary['findings']} total |",
        f"| Dependency findings | {summary['dependency_findings']} "
        f"({summary['runtime_findings']} runtime, {summary['dev_only_findings']} dev-only) |",
        f"| Vulnerable packages | {summary['vulnerable_packages']} |",
        f"| By type | {summary['by_type']} |",
        f"| By severity | {summary['by_severity']} |",
        f"| In CISA KEV | {summary['kev_findings']} |",
        f"| Fix version available | {summary['with_fix']} |",
        f"| Raw matches per tool | {summary['raw_matches']} |",
        f"| Advisory groups found by 1/2/3 tools | {summary['groups_by_tool_count']} |",
        f"| Unmapped to graph | {len(summary['unmapped'])} |",
        f"| Image inspected | {image_line(summary.get('image'))} |",
        f"| CI/Dockerfile rule hits | {summary.get('posture_hits')} |",
        f"| Anomaly rule hits | {summary.get('anomaly_hits')} |",
        f"| By risk level | {summary.get('by_risk_level')} |",
        f"| Reachability | {summary.get('by_reachability')} |",
        f"| Exposure | {summary.get('by_exposure')} |",
        "",
        "| ID | Risk | Coverage | Type | Severity | CVSS | EPSS | KEV | Reach | Exposure | "
        "Provenance | Package | Dependency path | Fixed in | Tools | Evidence |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for x in fs.findings:
        f = x.factors
        path = " > ".join(x.dependency_path)
        if len(x.dependency_path) > 5:
            path = " > ".join((*x.dependency_path[:2], "…", *x.dependency_path[-2:]))
        fixed = "; ".join(f"{fi.tool}: {', '.join(fi.versions)}" for fi in x.fixed_in) or "none"
        tools = sorted({e.tool for e in x.evidence if e.tool not in CONTEXT_TOOLS})
        r = x.risk
        risk = "" if r is None else f"{'' if r.score is None else r.score} {r.level.value}"
        lines.append(
            f"| {x.id} | {risk} | {'' if r is None else r.weight_coverage} | "
            f"{x.type.value} | {x.severity.value} | "
            f"{'' if f.cvss is None else f.cvss} | {'' if f.epss is None else f.epss} | "
            f"{'unknown' if f.kev is None else 'yes' if f.kev else 'no'} | "
            f"{f.reachability.value} | {f.exposure.value} | "
            f"{'' if f.provenance is None else f.provenance} | "
            f"{x.component.name}@{x.component.version} | {path} | {fixed} | "
            f"{', '.join(tools)} | {', '.join(e.evidence_id for e in x.evidence)} |"
        )
    return "\n".join(lines) + "\n"
