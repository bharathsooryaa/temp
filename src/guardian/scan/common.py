"""Shared finding-construction helpers: evidence store, EPSS/KEV enrichment, ordering."""

from __future__ import annotations

from guardian.scan.feeds import EpssFeed, KevFeed
from guardian.scan.parsers import SEVERITY_RANK, VulnGroup
from guardian.schemas.evidence import EvidenceKind, EvidenceRecord, EvidenceRef
from guardian.schemas.finding import Finding, FindingSet, FixedIn, Severity

Draft = tuple[tuple, dict]  # (sort key, Finding fields without id)


class EvidenceStore:
    """Assigns stable E-#### IDs and de-duplicates identical facts."""

    def __init__(self) -> None:
        self.records: list[EvidenceRecord] = []
        self._by_key: dict[tuple, str] = {}

    def add(self, key: tuple, **fields) -> EvidenceRecord:
        if key in self._by_key:
            return self.records[int(self._by_key[key][2:]) - 1]
        eid = f"E-{len(self.records) + 1:04d}"
        record = EvidenceRecord(id=eid, **fields)
        self.records.append(record)
        self._by_key[key] = eid
        return record


def ref_of(record: EvidenceRecord) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=record.id, tool=record.tool, ref=record.ref, file=record.file, line=record.line
    )


def excerpt(text: str | None, limit: int = 300) -> str | None:
    if not text:
        return None
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def pointer_excerpt(output_file: str, pointer: str, text: str | None) -> str | None:
    """'<output file>#<JSON pointer>[ :: <text>]'. The verifier parses the prefix back."""
    head = f"{output_file}#{pointer}"
    return excerpt(f"{head} :: {text}" if text and text.strip() else head)


def exploit_refs(
    store: EvidenceStore, group: VulnGroup, epss: EpssFeed, kev: KevFeed
) -> tuple[list[EvidenceRef], float | None, bool | None, bool]:
    """EPSS and KEV evidence for a group. Returns refs, epss, kev flag, and whether in KEV."""
    refs: list[EvidenceRef] = []
    epss_scores = [epss.scores[c] for c in group.cves if c in epss.scores]
    best = max(epss_scores, key=lambda s: s.epss) if epss_scores else None
    if best:
        rec = store.add(
            ("epss", best.cve),
            kind=EvidenceKind.ADVISORY,
            tool="epss",
            tool_version=epss.model_version,
            ref=best.cve,
            excerpt=f"epss={best.epss} percentile={best.percentile} score_date={epss.score_date}",
        )
        refs.append(ref_of(rec))
    kev_hits = [kev.entries[c] for c in group.cves if c in kev.entries]
    for entry in kev_hits:
        rec = store.add(
            ("kev", entry.cve),
            kind=EvidenceKind.ADVISORY,
            tool="cisa-kev",
            tool_version=kev.catalog_version,
            ref=entry.cve,
            excerpt=f"in KEV since {entry.date_added}; ransomware use: {entry.known_ransomware}",
        )
        refs.append(ref_of(rec))
    # KEV is keyed by CVE: with no CVE alias, KEV membership is unknown, not "no".
    kev_flag = True if kev_hits else (False if group.cves else None)
    return refs, best.epss if best else None, kev_flag, bool(kev_hits)


def fixed_by_tool(group: VulnGroup) -> tuple[FixedIn, ...]:
    fixed: dict[str, set[str]] = {}
    for m in group.matches:
        if m.fixed:
            fixed.setdefault(m.tool, set()).update(m.fixed)
    return tuple(FixedIn(tool=t, versions=tuple(sorted(v))) for t, v in sorted(fixed.items()))


def group_summary(group: VulnGroup) -> str:
    return next(
        (m.summary for m in group.matches if m.malicious and m.summary),
        next((m.summary for m in group.matches if m.summary), sorted(group.ids)[0]),
    )


def sort_key(
    malicious: bool,
    in_kev: bool,
    severity: Severity,
    cvss: float | None,
    label: str,
    tie: VulnGroup | str,
) -> tuple:
    """Malicious first, then KEV, then severity and CVSS. Ties are broken deterministically."""
    tie_value = sorted(tie.ids)[0] if isinstance(tie, VulnGroup) else tie
    return (not malicious, not in_kev, -SEVERITY_RANK[severity], -(cvss or 0), label, tie_value)


def assemble(store: EvidenceStore, drafts: list[Draft]) -> FindingSet:
    ordered = sorted(drafts, key=lambda d: d[0])
    findings = tuple(Finding(id=f"F-{i:03d}", **d) for i, (_, d) in enumerate(ordered, start=1))
    return FindingSet(evidence=tuple(store.records), findings=findings)
