"""Parse Grype, Trivy and OSV-Scanner JSON into uniform raw matches, then correlate them.

Every value here is copied from tool output. Nothing is inferred, and each match keeps a
JSON pointer back into the raw file it came from.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from guardian.schemas.finding import Severity

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.LOW,
}
SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}


def norm_severity(label: object) -> Severity:
    return _SEVERITY_MAP.get(str(label or "").strip().lower(), Severity.UNKNOWN)


@dataclass(frozen=True)
class RawMatch:
    tool: str
    advisory_id: str
    aliases: frozenset[str]
    name: str
    version: str
    severity: Severity
    cvss: float | None  # highest CVSS v3/v4 base score in this tool's record
    fixed: tuple[str, ...]
    summary: str | None
    url: str | None
    pointer: str  # JSON pointer into the tool's output file
    malicious: bool = False
    purl: str | None = None
    match_types: frozenset[str] = frozenset()  # Grype matchDetails types, e.g. cpe-match

    @property
    def ids(self) -> frozenset[str]:
        return self.aliases | {self.advisory_id}


def _max_score(scores: list[float]) -> float | None:
    valid = [s for s in scores if isinstance(s, int | float) and 0 <= s <= 10]
    return max(valid) if valid else None


def parse_grype(path: Path) -> list[RawMatch]:
    data = json.loads(path.read_text())
    out = []
    for i, m in enumerate(data.get("matches", [])):
        v, a = m["vulnerability"], m["artifact"]
        related = m.get("relatedVulnerabilities", [])
        scores = [
            c.get("metrics", {}).get("baseScore")
            for rec in (v, *related)
            for c in rec.get("cvss") or []
            if str(c.get("version", "")).startswith(("3", "4"))
        ]
        fix = v.get("fix") or {}
        out.append(
            RawMatch(
                tool="grype",
                advisory_id=v["id"],
                aliases=frozenset(r["id"] for r in related if r.get("id")),
                name=a["name"],
                version=a["version"],
                severity=norm_severity(v.get("severity")),
                cvss=_max_score(scores),
                fixed=tuple(fix.get("versions") or ()) if fix.get("state") == "fixed" else (),
                summary=v.get("description")
                or next((r.get("description") for r in related if r.get("description")), None),
                url=v.get("dataSource"),
                pointer=f"/matches/{i}",
                malicious=v["id"].startswith("MAL-"),
                purl=a.get("purl"),
                match_types=frozenset(d.get("type", "") for d in m.get("matchDetails", [])),
            )
        )
    return out


def parse_trivy(path: Path) -> list[RawMatch]:
    data = json.loads(path.read_text())
    out = []
    for ri, result in enumerate(data.get("Results") or []):
        for vi, v in enumerate(result.get("Vulnerabilities") or []):
            scores = [
                s
                for src in (v.get("CVSS") or {}).values()
                for s in (src.get("V3Score"), src.get("V40Score"))
                if s is not None
            ]
            fixed = tuple(x.strip() for x in (v.get("FixedVersion") or "").split(",") if x.strip())
            out.append(
                RawMatch(
                    tool="trivy",
                    advisory_id=v["VulnerabilityID"],
                    aliases=frozenset(v.get("VendorIDs") or ()),
                    name=v["PkgName"],
                    version=v["InstalledVersion"],
                    severity=norm_severity(v.get("Severity")),
                    cvss=_max_score(scores),
                    fixed=fixed,
                    summary=v.get("Title"),
                    url=v.get("PrimaryURL"),
                    pointer=f"/Results/{ri}/Vulnerabilities/{vi}",
                    malicious=v["VulnerabilityID"].startswith("MAL-"),
                    purl=(v.get("PkgIdentifier") or {}).get("PURL"),
                )
            )
    return out


def parse_osv(path: Path) -> list[RawMatch]:
    data = json.loads(path.read_text())
    out = []
    for ri, result in enumerate(data.get("results") or []):
        for pi, pkg in enumerate(result.get("packages") or []):
            p = pkg["package"]
            group_score: dict[str, float] = {}
            for g in pkg.get("groups") or []:
                try:
                    score = float(g.get("max_severity") or "")
                except ValueError:
                    continue
                for gid in g.get("ids", []):
                    group_score[gid] = score
            for vi, v in enumerate(pkg.get("vulnerabilities") or []):
                fixed = tuple(
                    sorted(
                        {
                            ev["fixed"]
                            for aff in v.get("affected", [])
                            if (aff.get("package") or {}).get("name") == p["name"]
                            for rng in aff.get("ranges", [])
                            for ev in rng.get("events", [])
                            if "fixed" in ev
                        }
                    )
                )
                out.append(
                    RawMatch(
                        tool="osv-scanner",
                        advisory_id=v["id"],
                        aliases=frozenset(v.get("aliases") or ()),
                        name=p["name"],
                        version=p["version"],
                        severity=norm_severity((v.get("database_specific") or {}).get("severity")),
                        cvss=_max_score([group_score[v["id"]]] if v["id"] in group_score else []),
                        fixed=fixed,
                        summary=v.get("summary"),
                        url=f"https://osv.dev/vulnerability/{v['id']}",
                        pointer=f"/results/{ri}/packages/{pi}/vulnerabilities/{vi}",
                        malicious=v["id"].startswith("MAL-"),
                        purl=(p.get("purl") or "").split("?", 1)[0] or None,
                    )
                )
    return out


@dataclass
class VulnGroup:
    """All matches on one name@version that share an advisory ID or alias."""

    name: str
    version: str
    matches: list[RawMatch] = field(default_factory=list)

    @property
    def ids(self) -> frozenset[str]:
        return frozenset().union(*(m.ids for m in self.matches))

    @property
    def tools(self) -> frozenset[str]:
        return frozenset(m.tool for m in self.matches)

    @property
    def cves(self) -> tuple[str, ...]:
        return tuple(sorted(i for i in self.ids if i.startswith("CVE-")))

    @property
    def malicious(self) -> bool:
        return any(m.malicious for m in self.matches)

    @property
    def severity(self) -> Severity:
        return max((m.severity for m in self.matches), key=SEVERITY_RANK.__getitem__)

    @property
    def cvss(self) -> float | None:
        return _max_score([m.cvss for m in self.matches if m.cvss is not None])


def correlate(matches: list[RawMatch]) -> list[VulnGroup]:
    """Union-find over advisory IDs and aliases, separately for each name@version.

    A tool that reports the same advisory once per install path of one name@version (Grype
    does) adds no new facts, so only its first match per (tool, advisory, package) is kept.
    """
    by_pkg: dict[tuple[str, str], list[RawMatch]] = defaultdict(list)
    seen: set[tuple[str, str, str, str]] = set()
    for m in matches:
        key = (m.tool, m.advisory_id, m.name, m.version)
        if key in seen:
            continue
        seen.add(key)
        by_pkg[(m.name, m.version)].append(m)

    groups: list[VulnGroup] = []
    for (name, version), pkg_matches in sorted(by_pkg.items()):
        parent: dict[str, str] = {}
        for m in pkg_matches:
            ids = sorted(m.ids)
            for other in ids[1:]:
                parent[_find(parent, other)] = _find(parent, ids[0])
            _find(parent, ids[0])

        buckets: dict[str, VulnGroup] = {}
        for m in pkg_matches:
            root = _find(parent, m.advisory_id)
            buckets.setdefault(root, VulnGroup(name, version)).matches.append(m)
        groups.extend(buckets[k] for k in sorted(buckets))
    return groups


def _find(parent: dict[str, str], x: str) -> str:
    """Union-find root lookup with path halving."""
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
