"""Finding (evidence record) contract from PDF section 5.

Mapping to the PDF example: ``cvss``/``epss``/``kev``/``reachable``/``exposure`` live in
``factors``; ``risk_level``/``risk_score`` live in ``risk`` (computed by
``guardian.scoring.score_risk``, never supplied by a model).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from guardian.schemas.common import FindingId, GuardianModel, cited_evidence_ids
from guardian.schemas.evidence import EvidenceRecord, EvidenceRef
from guardian.schemas.risk import RiskAssessment, RiskFactors
from guardian.schemas.sbom import Component


class FindingType(StrEnum):
    """Slide risk types plus the PDF schema's type names."""

    VULNERABLE_DIRECT = "vulnerable_direct"
    VULNERABLE_TRANSITIVE = "vulnerable_transitive"
    TYPOSQUAT = "typosquat"  # heuristic suspicion, not confirmation
    MALICIOUS_PACKAGE = "malicious_package"  # confirmed by evidence
    INSTALL_SCRIPT = "install_script"
    SUSPICIOUS_UPDATE = "suspicious_update"
    LOCKFILE_CHANGE = "lockfile_change"
    UNEXPECTED_DEPENDENCY = "unexpected_dependency"
    UNTRUSTED_IMAGE = "untrusted_image"
    UNPINNED_CI = "unpinned_ci"  # the slide's "unpinned or unsafe CI/CD component"
    VULNERABLE_IMAGE_PACKAGE = "vulnerable_image_package"  # OS or bundled package in an image
    MISCONFIGURATION = "misconfiguration"  # Dockerfile/CI hygiene outside the slide types


class FixAction(StrEnum):
    UPGRADE = "upgrade"
    REPLACE = "replace"
    PIN = "pin"
    REMOVE = "remove"
    MITIGATE = "mitigate"
    BLOCK = "block"
    REVIEW = "review"


class Fix(GuardianModel):
    """Recommended action (Day 2). ``target`` must come from registry/advisory data."""

    action: FixAction
    target: str | None = None
    breaking: bool | None = None


class Severity(StrEnum):
    """Scanner-reported severity label, normalized across tools (not the risk band)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class FixedIn(GuardianModel):
    """Fix versions as one tool reported them. Facts from advisory data, not a recommendation."""

    tool: str = Field(min_length=1)
    versions: tuple[str, ...]


class Finding(GuardianModel):
    id: FindingId
    type: FindingType
    title: str = Field(min_length=1, max_length=200, description="One-line finding.")
    component: Component
    dependency_path: tuple[str, ...] = Field(
        default=(), description="Root first, e.g. ('app', 'express-validator@6.x', 'lodash@...')."
    )
    introduced_by: tuple[str, ...] = Field(
        default=(), description="Direct dependencies (name@version) that pull this component in."
    )
    advisory_ids: tuple[str, ...] = Field(
        default=(),
        description="Advisory IDs and aliases, or rule IDs for configuration findings, "
        "exactly as tools reported them.",
    )
    severity: Severity = Severity.UNKNOWN
    fixed_in: tuple[FixedIn, ...] = ()
    evidence: tuple[EvidenceRef, ...] = Field(min_length=1)
    factors: RiskFactors = RiskFactors()
    risk: RiskAssessment | None = None
    rationale: str | None = Field(
        default=None, max_length=2000, description="Grounded explanation citing E-### IDs only."
    )
    fix: Fix | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Finding:
        ids = [e.evidence_id for e in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate evidence_id on finding")

        path_len = len(self.dependency_path)
        if self.type is FindingType.VULNERABLE_DIRECT and path_len != 2:
            raise ValueError("vulnerable_direct requires dependency_path of [root, package]")
        if self.type is FindingType.VULNERABLE_TRANSITIVE and path_len < 3:
            raise ValueError("vulnerable_transitive requires dependency_path of length >= 3")

        if self.rationale is not None:
            cited = cited_evidence_ids(self.rationale)
            if not cited:
                raise ValueError("rationale must cite at least one evidence ID")
            unknown = cited - set(ids)
            if unknown:
                raise ValueError(f"rationale cites evidence not on this finding: {sorted(unknown)}")

        if self.risk is not None and (self.risk.override is not None) != (
            self.factors.confirmed_malicious
        ):
            raise ValueError("risk override must match factors.confirmed_malicious")
        if self.factors.confirmed_malicious and self.type is not FindingType.MALICIOUS_PACKAGE:
            raise ValueError("confirmed_malicious is only valid on malicious_package findings")
        return self


class FindingSet(GuardianModel):
    """A run's findings plus the evidence store they cite; every citation must resolve."""

    evidence: tuple[EvidenceRecord, ...]
    findings: tuple[Finding, ...]

    @model_validator(mode="after")
    def _resolved(self) -> FindingSet:
        store = {r.id: r for r in self.evidence}
        if len(store) != len(self.evidence):
            raise ValueError("duplicate evidence record id")
        finding_ids = [f.id for f in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("duplicate finding id")
        for finding in self.findings:
            for ref in finding.evidence:
                record = store.get(ref.evidence_id)
                if record is None:
                    raise ValueError(f"{finding.id} cites unresolved {ref.evidence_id}")
                if record.tool != ref.tool:
                    raise ValueError(
                        f"{finding.id}: {ref.evidence_id} tool {ref.tool!r} != {record.tool!r}"
                    )
        return self
