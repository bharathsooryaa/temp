"""D1.S7: risk-factor context and risk score v1 for every finding (PDF section 6).

Every factor value comes from a cited fact. The verifier recomputes reachability, exposure,
provenance and the score from those citations (DECISIONS D7-01 to D7-04).

* Reachability: static `require('x')` / `import ... 'x'` lines in the app's server code mean
  IMPORTED (60). A package whose every install is dev-only is DEV_ONLY_UNUSED (0). Anything else
  is PRESENT_ONLY (30). CALLED (100) is never claimed, because there is no call graph yet.
* Exposure: imported by server code in an app with a cited listen/EXPOSE fact means
  RUNTIME_NETWORK (100). Other runtime packages, image and Dockerfile findings are
  RUNTIME_INTERNAL (50). Dev-only packages and CI findings are BUILD_OR_DEV (20).
* Provenance: a fixed table over the anomaly-rule IDs cited for the same component. Confirmed
  malicious is 100. npm packages with no hit score 0, meaning "no signal from the implemented
  checks", not "verified trusted". Other findings with no hit are unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from guardian import __version__
from guardian.sbom.npm_lock import NpmLock
from guardian.scan.anomaly import entry_field_line
from guardian.scan.common import Draft, EvidenceStore, ref_of
from guardian.schemas.common import Ecosystem
from guardian.schemas.evidence import EvidenceKind, EvidenceRef
from guardian.schemas.finding import FindingType
from guardian.schemas.risk import Exposure, Reachability, RiskFactors
from guardian.scoring import score_risk
from guardian.tools.runner import jail, workspace_relative

IMPORT_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|^\s*import\s+)(['"])([^'"\s]+)\1"""
)
LISTEN_RE = re.compile(r"\.listen\s*\(")
EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+\d+", re.IGNORECASE)
NODE_BUILTINS = frozenset(
    [
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    ]
)
DEV_DIRS = frozenset({"test", "tests", "__tests__", "cypress", "spec", "artifacts", "scripts"})
DEV_FILES = frozenset({"gruntfile.js", "gulpfile.js", "karma.conf.js", "webpack.config.js"})
CLIENT_DIRS = frozenset({"assets", "public", "static", "vendor"})

PACKAGE_TYPES = frozenset(
    {
        FindingType.VULNERABLE_DIRECT,
        FindingType.VULNERABLE_TRANSITIVE,
        FindingType.MALICIOUS_PACKAGE,
        FindingType.TYPOSQUAT,
        FindingType.INSTALL_SCRIPT,
        FindingType.LOCKFILE_CHANGE,
        FindingType.UNEXPECTED_DEPENDENCY,
    }
)
# Provenance points (0 trusted .. 100 highly suspicious) per rule; documented in D7-03.
PROVENANCE_POINTS = {
    "GR-TYPO-001": 60,
    "GR-INST-001": 30,
    "GR-INST-002": 80,
    "GR-LOCK-001": 60,
    "GR-LOCK-002": 50,
    "GR-LOCK-004": 80,
    "GR-LOCK-005": 50,
    "GR-DEP-001": 40,
    "GR-DEP-002": 60,
    "GR-CI-001": 50,
    "unpinned-uses": 50,
    "GR-CI-003": 50,
    "GR-IMG-001": 40,
    "GR-IMG-002": 60,
}


def package_of(spec: str) -> str | None:
    """npm package name for a module specifier, or None for local paths and builtins."""
    if spec.startswith((".", "/")) or spec.startswith("node:"):
        return None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]
    return None if name in NODE_BUILTINS else name


def file_role(rel: Path) -> str:
    """'runtime' (server code), 'dev' (tests/tooling) or 'client' (browser assets)."""
    parts = [p.lower() for p in rel.parts]
    if set(parts[:-1]) & CLIENT_DIRS:
        return "client"
    if (
        set(parts[:-1]) & DEV_DIRS
        or parts[-1] in DEV_FILES
        or re.search(r"\.(test|spec)\.[cm]?js$", parts[-1])
    ):
        return "dev"
    return "runtime"


@dataclass(frozen=True)
class Site:
    file: str  # workspace-relative
    line: int
    text: str  # exact stripped line


@dataclass
class AppContext:
    runtime_imports: dict[str, Site] = field(default_factory=dict)  # package -> first site
    dev_imports: dict[str, Site] = field(default_factory=dict)
    network_facts: list[Site] = field(default_factory=list)
    dynamic_requires: int = 0
    # name -> (version, lockfile 'version' line) of node_modules/<name>, the copy that a bare
    # require('<name>') from the app root resolves to.
    top_level: dict[str, tuple[str | None, Site | None]] = field(default_factory=dict)

    @property
    def network_facing(self) -> bool:
        return bool(self.network_facts)


def scan_app(target_root: Path, dockerfile: Path | None) -> AppContext:
    ctx = AppContext()
    files = sorted(
        p
        for p in target_root.rglob("*")
        if p.is_file()
        and p.suffix in {".js", ".mjs", ".cjs"}
        and not {"node_modules", ".git"} & set(p.relative_to(target_root).parts)
    )
    for path in files:
        role = file_role(path.relative_to(target_root))
        if role == "client":
            continue
        rel = workspace_relative(path)
        for number, text in enumerate(path.read_text(errors="replace").splitlines(), start=1):
            stripped = text.strip()
            if stripped.startswith("//"):
                continue
            for m in IMPORT_RE.finditer(text):
                pkg = package_of(m.group(2))
                if pkg:
                    bucket = ctx.runtime_imports if role == "runtime" else ctx.dev_imports
                    bucket.setdefault(pkg, Site(rel, number, stripped))
            if re.search(r"\brequire\s*\(\s*[^'\"\s)]", text):
                ctx.dynamic_requires += 1
            if role == "runtime" and LISTEN_RE.search(text):
                ctx.network_facts.append(Site(rel, number, stripped))
    if dockerfile is not None and dockerfile.exists():
        for number, text in enumerate(dockerfile.read_text().splitlines(), start=1):
            if EXPOSE_RE.match(text):
                ctx.network_facts.append(Site(workspace_relative(dockerfile), number, text.strip()))
    return ctx


def resolve_top_level(ctx: AppContext, lock: NpmLock) -> None:
    """Record which installed copy each runtime import resolves to (npm resolution from root)."""
    lines = jail(lock.file).read_text().splitlines()
    for name in ctx.runtime_imports:
        entry = lock.entries.get(f"node_modules/{name}")
        if entry is None:
            ctx.top_level[name] = (None, None)
            continue
        n = entry_field_line(lines, entry.line, "version")
        ctx.top_level[name] = (
            entry.version,
            Site(lock.file, n, lines[n - 1].strip()) if n else None,
        )


def entry_key_above(lines: list[str], number: int) -> str | None:
    """The lockfile 'packages' key whose entry contains line ``number``."""
    for i in range(number, 0, -1):
        m = re.match(r'^    "((?:node_modules/[^"]*)|)": \{', lines[i - 1])
        if m:
            return m.group(1)
    return None


def expected_provenance(
    ftype: FindingType, ecosystem: Ecosystem | None, malicious: bool, cited_rules: set[str]
) -> float | None:
    """Shared by the enrichment and the verifier, so the value is recomputable from evidence."""
    if malicious:
        return 100.0
    points = [PROVENANCE_POINTS[r] for r in cited_rules if r in PROVENANCE_POINTS]
    if points:
        return float(max(points))
    if ftype in PACKAGE_TYPES and ecosystem is Ecosystem.NPM:
        return 0.0
    return None


def _cite(store: EvidenceStore, rule: str, site: Site) -> EvidenceRef:
    rec = store.add(
        ("ctx", rule, site.file, site.line),
        kind=EvidenceKind.FILE_LOCATION,
        tool="guardian-rules",
        tool_version=f"guardian {__version__}",
        ref=rule,
        file=site.file,
        line=site.line,
        excerpt=site.text,
    )
    return ref_of(rec)


def enrich(store: EvidenceStore, drafts: list[Draft], ctx: AppContext) -> list[Draft]:
    """Fill reachability, exposure, provenance and the risk score. Re-sort by risk."""
    by_ref = {r.id: r for r in store.records}

    # Anomaly-rule citations per component, shared with every finding on that component.
    rule_refs: dict[tuple[str, str | None], list[EvidenceRef]] = {}
    for _, d in drafts:
        c = d["component"]
        for ref in d["evidence"]:
            rec = by_ref[ref.evidence_id]
            if rec.tool == "guardian-rules" and rec.ref in PROVENANCE_POINTS:
                rule_refs.setdefault((c.name, c.version), []).append(ref)

    out: list[Draft] = []
    for key, d in drafts:
        ftype, c, f0 = d["type"], d["component"], d.get("factors", RiskFactors())
        refs = list(d["evidence"])
        have = {r.evidence_id for r in refs}

        def add(ref: EvidenceRef, refs=refs, have=have) -> None:
            if ref.evidence_id not in have:
                refs.append(ref)
                have.add(ref.evidence_id)

        reach, exposure = Reachability.UNKNOWN, f0.exposure
        if ftype in PACKAGE_TYPES:
            version, version_site = ctx.top_level.get(c.name, (None, None))
            if c.name in ctx.runtime_imports and version == c.version and version_site:
                reach = Reachability.IMPORTED
                add(_cite(store, "GR-REACH-001", ctx.runtime_imports[c.name]))
                add(_cite(store, "GR-REACH-002", version_site))
            elif f0.exposure is Exposure.BUILD_OR_DEV:
                reach = Reachability.DEV_ONLY_UNUSED
            else:
                reach = Reachability.PRESENT_ONLY
            if f0.exposure is not Exposure.BUILD_OR_DEV:
                if reach is Reachability.IMPORTED and ctx.network_facing:
                    exposure = Exposure.RUNTIME_NETWORK
                    for site in ctx.network_facts:
                        add(_cite(store, "GR-EXPO-001", site))
                else:
                    exposure = Exposure.RUNTIME_INTERNAL
        elif ftype in {
            FindingType.VULNERABLE_IMAGE_PACKAGE,
            FindingType.UNTRUSTED_IMAGE,
            FindingType.MISCONFIGURATION,
        }:
            exposure = Exposure.RUNTIME_INTERNAL
        elif ftype is FindingType.UNPINNED_CI:
            exposure = Exposure.BUILD_OR_DEV

        for ref in rule_refs.get((c.name, c.version), []) if ftype in PACKAGE_TYPES else []:
            add(ref)
        cited_rules = {r.ref for r in refs if r.ref}
        provenance = expected_provenance(ftype, c.ecosystem, f0.confirmed_malicious, cited_rules)

        factors = f0.model_copy(
            update={"reachability": reach, "exposure": exposure, "provenance": provenance}
        )
        risk = score_risk(factors)
        new = {**d, "evidence": tuple(refs), "factors": factors, "risk": risk}
        out.append(
            ((risk.override is None, -(risk.score if risk.score is not None else -1), *key), new)
        )
    return out
