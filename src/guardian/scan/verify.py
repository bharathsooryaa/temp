"""Independent check that every cited fact in a FindingSet resolves to raw tool output.

This is the deterministic core of the PDF's hallucination check ("percent of cited IDs,
versions and paths that resolve to tool output; target 100 percent"). It re-reads the raw
files and source files and does not trust the parsers. Each raw record's format is detected
from its content, not from the evidence's claimed tool.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from guardian.scan.anomaly import max_distance, osa_distance
from guardian.scan.context import (
    IMPORT_RE,
    PACKAGE_TYPES,
    entry_key_above,
    expected_provenance,
    package_of,
)
from guardian.schemas.evidence import EvidenceKind
from guardian.schemas.finding import FindingSet
from guardian.schemas.graph import DependencyGraph
from guardian.schemas.risk import Exposure, Reachability
from guardian.scoring import score_risk
from guardian.tools.runner import jail

POINTER_RE = re.compile(r"^(\S+?)#(/\S*)")


def _pointer(doc: object, pointer: str) -> object:
    node = doc
    for part in pointer.strip("/").split("/"):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def detect(rec: object) -> str:
    if not isinstance(rec, dict):
        return "unknown"
    if "vulnerability" in rec and "artifact" in rec:
        return "grype"
    if "VulnerabilityID" in rec:
        return "trivy-vuln"
    if "affected" in rec or ("id" in rec and "aliases" in rec):
        return "osv"
    if "code" in rec and "level" in rec:
        return "hadolint"
    if "ident" in rec and "locations" in rec:
        return "zizmor"
    if "ID" in rec and "Title" in rec:
        return "trivy-misconfig"
    if "EOSL" in rec and "Family" in rec:
        return "trivy-eosl"
    return "unknown"


def _vuln_facts(fmt: str, rec: dict, doc: object, ptr: str):
    """IDs, package name, version and fix versions in one raw vulnerability record."""
    if fmt == "grype":
        v, a = rec["vulnerability"], rec["artifact"]
        ids = {v["id"], *(r["id"] for r in rec.get("relatedVulnerabilities", []))}
        return ids, a["name"], a["version"], set((v.get("fix") or {}).get("versions") or ())
    if fmt == "trivy-vuln":
        ids = {rec["VulnerabilityID"], *(rec.get("VendorIDs") or ())}
        fixed = {x.strip() for x in (rec.get("FixedVersion") or "").split(",") if x.strip()}
        return ids, rec["PkgName"], rec["InstalledVersion"], fixed
    fixed = {
        ev["fixed"]
        for aff in rec.get("affected", [])
        for rng in aff.get("ranges", [])
        for ev in rng.get("events", [])
        if "fixed" in ev
    }
    pkg = _pointer(doc, ptr.rsplit("/vulnerabilities/", 1)[0])["package"]
    return {rec["id"], *(rec.get("aliases") or ())}, pkg["name"], pkg["version"], fixed


@dataclass
class Verification:
    checked: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def resolved(self) -> int:
        return self.checked - len(self.failures)

    @property
    def rate(self) -> float:
        return 1.0 if self.checked == 0 else self.resolved / self.checked

    def check(self, ok: bool, message: str) -> None:
        self.checked += 1
        if not ok:
            self.failures.append(message)


class _Files:
    def __init__(self) -> None:
        self._json: dict[str, object] = {}
        self._lines: dict[str, list[str]] = {}

    def json(self, path: str) -> object:
        if path not in self._json:
            self._json[path] = json.loads(jail(path).read_text())
        return self._json[path]

    def lines(self, path: str) -> list[str]:
        if path not in self._lines:
            self._lines[path] = jail(path).read_text(errors="replace").splitlines()
        return self._lines[path]

    def line(self, path: str, number: int) -> str:
        if path not in self._lines:
            self._lines[path] = jail(path).read_text(errors="replace").splitlines()
        lines = self._lines[path]
        return lines[number - 1] if 1 <= number <= len(lines) else ""


def verify(fs: FindingSet, graph: DependencyGraph, outputs: dict[str, str]) -> Verification:
    files = _Files()
    output_paths = set(outputs.values())
    store = {r.id: r for r in fs.evidence}
    labels = {n.bom_ref: graph.label(n.bom_ref) for n in graph.nodes}
    v = Verification()

    for f in fs.findings:
        cited_ids: set[str] = set()
        cited_fixes: dict[str, set[str]] = {}
        advisory_refs: list[str] = []
        has_graph = False
        image_digest: str | None = None
        comp_label = f"{f.component.name}@{f.component.version}"

        for ref in f.evidence:
            rec = store[ref.evidence_id]
            where = f"{f.id}/{rec.id}"
            if rec.kind is EvidenceKind.SCANNER_RESULT:
                m = POINTER_RE.match(rec.excerpt or "")
                file_part, ptr = (m.group(1), m.group(2)) if m else ("", "")
                v.check(file_part in output_paths, f"{where}: output file {file_part!r} unknown")
                if file_part not in output_paths:
                    continue
                doc = files.json(file_part)
                try:
                    raw = _pointer(doc, ptr)
                except (KeyError, IndexError, ValueError, TypeError):
                    v.check(False, f"{where}: pointer {ptr} does not resolve")
                    continue
                fmt = detect(raw)
                if fmt in {"grype", "trivy-vuln", "osv"}:
                    ids, name, version, fixed = _vuln_facts(fmt, raw, doc, ptr)
                    cited_ids |= ids
                    cited_fixes.setdefault(rec.tool, set()).update(fixed)
                    v.check(rec.ref in ids, f"{where}: {rec.ref} not in raw record")
                    v.check(
                        (name, version) == (f.component.name, f.component.version),
                        f"{where}: raw package {name}@{version} != {comp_label}",
                    )
                    if rec.file and rec.line:
                        text = files.line(rec.file, rec.line).strip()
                        if rec.file.endswith("package-lock.json"):
                            key = text.rstrip("{ ").rstrip(":").strip('"')
                            ok = key.startswith("node_modules/") and key.endswith(
                                f"node_modules/{f.component.name}"
                            )
                        else:
                            ok = text.upper().startswith("FROM ")
                        v.check(ok, f"{where}: {rec.file}:{rec.line} does not locate {comp_label}")
                elif fmt == "hadolint":
                    cited_ids.add(raw["code"])
                    v.check(raw["code"] == rec.ref, f"{where}: hadolint code != {rec.ref}")
                    v.check(raw.get("line") == rec.line, f"{where}: hadolint line mismatch")
                    v.check(str(raw.get("file", "")).endswith(rec.file or "\0"),
                            f"{where}: hadolint file mismatch")  # fmt: skip
                elif fmt == "zizmor":
                    cited_ids.add(raw["ident"])
                    locs = raw["locations"]
                    loc = next((x for x in locs if x["symbolic"].get("kind") == "Primary"), locs[0])
                    key = loc["symbolic"]["key"].get("Local", {})
                    path = key.get("given_path") or key.get("verbatim_path") or ""
                    v.check(raw["ident"] == rec.ref, f"{where}: zizmor ident != {rec.ref}")
                    v.check(loc["concrete"]["location"]["start_point"]["row"] + 1 == rec.line,
                            f"{where}: zizmor line mismatch")  # fmt: skip
                    v.check(path.endswith(rec.file or "\0"), f"{where}: zizmor file mismatch")
                elif fmt == "trivy-misconfig":
                    cited_ids.add(raw["ID"])
                    v.check(raw["ID"] == rec.ref, f"{where}: trivy config ID != {rec.ref}")
                    start = (raw.get("CauseMetadata") or {}).get("StartLine") or None
                    v.check(start == rec.line, f"{where}: trivy config line mismatch")
                elif fmt == "trivy-eosl":
                    cited_ids.add("EOSL")
                    v.check(rec.ref == "EOSL" and raw.get("EOSL") is True,
                            f"{where}: Trivy does not report EOSL")  # fmt: skip
                else:
                    v.check(False, f"{where}: unrecognized raw record at {ptr}")
            elif rec.kind is EvidenceKind.FILE_LOCATION:
                if rec.tool == "guardian-rules":
                    cited_ids.add(rec.ref or "")
                    actual = files.line(rec.file, rec.line).strip() if rec.file and rec.line else ""
                    v.check(actual == rec.excerpt, f"{where}: {rec.file}:{rec.line} text differs")
                elif rec.tool == "oci-layout":
                    index = json.dumps(files.json(rec.file)) if rec.file else ""
                    v.check(bool(rec.ref) and rec.ref in index,
                            f"{where}: digest {rec.ref} not in {rec.file}")  # fmt: skip
                    image_digest = rec.ref
                else:
                    v.check(False, f"{where}: unknown file-location tool {rec.tool}")
            elif rec.kind is EvidenceKind.GRAPH_NODE:
                has_graph = True
                node = rec.graph_node
                v.check(node in labels, f"{where}: graph node {node} missing")
                if node in labels:
                    path = graph.shortest_path(node, exclude_dev=True) or graph.shortest_path(node)
                    v.check(
                        path is not None and graph.path_labels(path) == f.dependency_path,
                        f"{where}: dependency_path does not match the graph",
                    )
            elif rec.kind is EvidenceKind.ADVISORY:
                advisory_refs.append(rec.ref or "")
            elif rec.kind is EvidenceKind.REGISTRY_METADATA:
                _check_registry(v, files, rec, f.component.name, where)

        for aid in f.advisory_ids:
            v.check(aid in cited_ids, f"{f.id}: {aid} not in any cited raw record")
        for aref in advisory_refs:
            v.check(aref in cited_ids, f"{f.id}: EPSS/KEV cites {aref}, not an alias here")
        for fixed in f.fixed_in:
            for version in fixed.versions:
                v.check(
                    version in cited_fixes.get(fixed.tool, set()),
                    f"{f.id}: fix {version} ({fixed.tool}) not in cited raw records",
                )
        if has_graph:
            for label in f.introduced_by:
                v.check(label in labels.values(), f"{f.id}: introduced_by {label} not in graph")
        if image_digest is not None:
            v.check(
                len(f.dependency_path) == 2
                and f.dependency_path[0].endswith(f"@{image_digest}")
                and f.dependency_path[1] == comp_label
                and f.introduced_by == (f.dependency_path[0],),
                f"{f.id}: image path does not match digest {image_digest} and component",
            )
        if f.risk is not None:  # enrichment claims exist only on scored findings (D1.S7)
            _check_risk(v, f, store, files)
    return v


def _check_risk(v: Verification, f, store: dict, files: _Files) -> None:
    """Recompute reachability, exposure, provenance and the score from the cited evidence."""
    fx = f.factors
    cited = [store[r.evidence_id] for r in f.evidence]
    rules = {r.ref for r in f.evidence if r.ref}
    v.check(f.risk == score_risk(fx), f"{f.id}: risk does not match score_risk(factors)")
    v.check(
        fx.provenance
        == expected_provenance(f.type, f.component.ecosystem, fx.confirmed_malicious, rules),
        f"{f.id}: provenance {fx.provenance} not derivable from cited rules",
    )
    if fx.reachability is Reachability.IMPORTED:
        sites = [r for r in cited if r.ref == "GR-REACH-001"]
        imported = {
            package_of(m.group(2)) for r in sites for m in IMPORT_RE.finditer(r.excerpt or "")
        }
        v.check(f.component.name in imported, f"{f.id}: no cited import of {f.component.name}")
        resolved = [
            r for r in cited
            if r.ref == "GR-REACH-002" and r.file and r.line
            and entry_key_above(files.lines(r.file), r.line) == f"node_modules/{f.component.name}"
            and (r.excerpt or "").strip().rstrip(",") == f'"version": "{f.component.version}"'
        ]  # fmt: skip
        v.check(bool(resolved), f"{f.id}: import does not resolve to {f.component.name}@"
                f"{f.component.version}")  # fmt: skip
    if fx.exposure is Exposure.RUNTIME_NETWORK:
        v.check(
            fx.reachability is Reachability.IMPORTED and any(r.ref == "GR-EXPO-001" for r in cited),
            f"{f.id}: network exposure needs an import and a cited listen/EXPOSE fact",
        )
    if f.type in PACKAGE_TYPES:
        v.check(
            (fx.reachability is Reachability.DEV_ONLY_UNUSED)
            == (fx.exposure is Exposure.BUILD_OR_DEV),
            f"{f.id}: dev-only reachability and build/dev exposure disagree",
        )


TOP_RE = re.compile(r"^rank=(\d+) name=(\S+); '(.+)' not in list; distance=(\d+)")
MOCK_RE = re.compile(r"^created=(\S+); weekly_downloads=(\d+)$")


def _check_registry(v: Verification, files: _Files, rec, component: str, where: str) -> None:
    doc = files.json(rec.file) if rec.file else {}
    if rec.tool == "npm-high-impact":
        m = TOP_RE.match(rec.excerpt or "")
        if not m:
            v.check(False, f"{where}: unparseable top-list citation")
            return
        rank, popular, candidate, dist = int(m[1]), m[2], m[3], int(m[4])
        names = doc.get("names", [])
        v.check(1 <= rank <= len(names) and names[rank - 1] == popular == rec.ref,
                f"{where}: {popular} is not rank {rank} in {rec.file}")  # fmt: skip
        v.check(candidate == component and candidate not in names,
                f"{where}: {candidate} is the component and must not be high-impact")  # fmt: skip
        v.check(osa_distance(candidate, popular) == dist
                <= min(max_distance(candidate), max_distance(popular)),
                f"{where}: distance {candidate}~{popular} is not {dist}")  # fmt: skip
    elif rec.tool == "mock-registry":
        m = MOCK_RE.match(rec.excerpt or "")
        meta = doc.get("packages", {}).get(rec.ref or "", {})
        v.check(bool(m) and rec.ref == component and m[1] == meta.get("created")
                and int(m[2]) == meta.get("weekly_downloads"),
                f"{where}: registry metadata for {rec.ref} does not match {rec.file}")  # fmt: skip
    else:
        v.check(False, f"{where}: unknown registry-metadata tool {rec.tool}")


def verify_run(run_dir: str | Path) -> Verification:
    out = jail(run_dir)
    summary = json.loads((out / "baseline.json").read_text())
    fs = FindingSet.model_validate_json((out / "findings.json").read_text())
    graph = DependencyGraph.model_validate_json((out / "graph.json").read_text())
    return verify(fs, graph, summary["outputs"])
