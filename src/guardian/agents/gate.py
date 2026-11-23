"""Deterministic gate for model-written explanations (PDF: 'Verify' step of the reasoning loop).

A model may only *explain* a finding. It cannot add facts. An explanation is accepted only
if every identifier, version and evidence citation in it already belongs to that finding, and
it states the reachability the deterministic pipeline computed. Rejected explanations are
returned to the model with reasons (so it can retry), recorded as rejected, and never shown.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, ValidationError

from guardian.schemas.common import EVIDENCE_ID_RE, EvidenceId, FindingId, GuardianModel
from guardian.schemas.finding import Finding
from guardian.schemas.risk import Reachability

# Broad shapes on purpose: an invented ID outside GitHub's real alphabet must still be caught.
ADVISORY_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+)\b", re.IGNORECASE
)
VERSION_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?![\w.])")
PKG_VERSION_RE = re.compile(r"(?<![\w/@.-])(@?[a-z0-9][a-z0-9._/-]*)@(v?\d[\w.+-]*)", re.IGNORECASE)

# The phrase each computed reachability must be stated with (D8-03).
REACH_WORDS = {
    Reachability.CALLED: "called",
    Reachability.IMPORTED: "imported",
    Reachability.PRESENT_ONLY: "present",
    Reachability.DEV_ONLY_UNUSED: "dev",
    Reachability.UNKNOWN: "unknown",
}


class Explanation(GuardianModel):
    """The PDF evidence card's 'AI explanation': why it matters, reachability, confidence."""

    finding_id: FindingId
    why_it_matters: str = Field(min_length=20, max_length=500)
    reachability: str = Field(min_length=5, max_length=300)
    confidence: Literal["high", "medium", "low"]
    confidence_reason: str = Field(min_length=5, max_length=300)
    cited_evidence: tuple[EvidenceId, ...] = Field(min_length=1, max_length=20)

    def text(self) -> str:
        return " ".join((self.why_it_matters, self.reachability, self.confidence_reason))

    def rationale(self) -> str:
        """Three sentences for Finding.rationale, ending with the citations."""
        cites = " ".join(f"[{e}]" for e in self.cited_evidence)
        return (
            f"{self.why_it_matters.rstrip('.')}. {self.reachability.rstrip('.')}. "
            f"Confidence {self.confidence}: {self.confidence_reason.rstrip('.')}. {cites}"
        )


def _known_versions(f: Finding) -> set[str]:
    versions = {f.component.version or ""}
    for label in (*f.dependency_path, *f.introduced_by):
        versions.add(label.rsplit("@", 1)[-1])
    for fixed in f.fixed_in:
        for v in fixed.versions:
            versions.update(VERSION_RE.findall(v) or [v])
    return {v.lstrip("v") for v in versions if v}


def _known_labels(f: Finding) -> set[str]:
    labels = {f"{f.component.name}@{f.component.version}", *f.dependency_path, *f.introduced_by}
    return {x.lower() for x in labels}


def gate(raw: dict, findings: dict[str, Finding]) -> tuple[Explanation | None, list[str]]:
    """Validate one explanation dict. Returns (explanation, []) or (None, reasons)."""
    try:
        exp = Explanation.model_validate(raw)
    except ValidationError as exc:
        return None, [f"schema: {e['loc']}: {e['msg']}" for e in exc.errors()][:10]
    f = findings.get(exp.finding_id)
    if f is None:
        return None, [f"unknown finding {exp.finding_id}"]

    reasons: list[str] = []
    own = {e.evidence_id for e in f.evidence}
    text = exp.text()
    for eid in sorted(set(exp.cited_evidence) | set(EVIDENCE_ID_RE.findall(text))):
        if eid not in own:
            reasons.append(f"cites {eid}, which is not evidence of {f.id}")
    advisories = {a.upper() for a in f.advisory_ids}
    for aid in sorted({a.upper() for a in ADVISORY_RE.findall(text)}):
        if aid not in advisories:
            reasons.append(f"mentions {aid}, which is not an advisory of {f.id}")
    labels = _known_labels(f)
    for name, version in PKG_VERSION_RE.findall(text):
        if f"{name}@{version}".lower() not in labels:
            reasons.append(f"mentions {name}@{version}, which is not on {f.id}'s path")
    versions = _known_versions(f)
    for v in sorted(set(VERSION_RE.findall(text))):
        if v.lstrip("v") not in versions:
            reasons.append(f"mentions version {v}, which no tool reported for {f.id}")
    word = REACH_WORDS[f.factors.reachability]
    if word not in exp.reachability.lower():
        reasons.append(
            f"reachability must state the computed value '{word}' ({f.factors.reachability.value})"
        )
    return (None, reasons) if reasons else (exp, [])
