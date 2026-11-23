"""Risk-factor inputs and the scored assessment (PDF section 6, 'Risk scoring model')."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from guardian.schemas.common import GuardianModel


class RiskLevel(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"  # no factor is known and no override applies


class Reachability(StrEnum):
    """Scale from the PDF: 100 called, 60 imported, 30 present only, 0 dev-only unused."""

    CALLED = "called"
    IMPORTED = "imported"
    PRESENT_ONLY = "present_only"
    DEV_ONLY_UNUSED = "dev_only_unused"
    UNKNOWN = "unknown"


class Exposure(StrEnum):
    """Scale from the PDF: 100 runtime network-facing, 50 runtime internal, 20 build or dev."""

    RUNTIME_NETWORK = "runtime_network"
    RUNTIME_INTERNAL = "runtime_internal"
    BUILD_OR_DEV = "build_or_dev"  # includes test scope
    UNKNOWN = "unknown"


class RiskFactor(StrEnum):
    CVSS = "cvss"
    EPSS_KEV = "epss_kev"
    REACHABILITY = "reachability"
    EXPOSURE = "exposure"
    PROVENANCE = "provenance"


class RiskFactors(GuardianModel):
    """Raw factor inputs. ``None`` / ``UNKNOWN`` mean unknown, never zero."""

    cvss: float | None = Field(default=None, ge=0.0, le=10.0, description="CVSS base score.")
    epss: float | None = Field(default=None, ge=0.0, le=1.0, description="EPSS probability.")
    kev: bool | None = Field(default=None, description="Listed in CISA KEV; None=not checked.")
    reachability: Reachability = Reachability.UNKNOWN
    exposure: Exposure = Exposure.UNKNOWN
    provenance: float | None = Field(
        default=None, ge=0.0, le=100.0, description="0 trusted to 100 highly suspicious."
    )
    confirmed_malicious: bool = Field(
        default=False,
        description=(
            "Set only from confirmed evidence (e.g. a malicious-package advisory). "
            "A typosquat heuristic match alone must NOT set this; it raises provenance instead."
        ),
    )


class FactorContribution(GuardianModel):
    factor: RiskFactor
    weight: float = Field(ge=0.0, le=1.0, description="Weight from the PDF formula.")
    value: float | None = Field(default=None, ge=0.0, le=100.0, description="Normalized 0-100.")
    effective_weight: float = Field(
        ge=0.0, le=1.0, description="Weight after renormalizing over known factors."
    )
    contribution: float | None = Field(default=None, description="effective_weight * value.")


class RiskAssessment(GuardianModel):
    score: float | None = Field(default=None, ge=0.0, le=100.0)
    level: RiskLevel
    contributions: tuple[FactorContribution, ...]
    unknown_factors: tuple[RiskFactor, ...]
    weight_coverage: float = Field(
        ge=0.0, le=1.0, description="Sum of PDF weights for known factors (1.0 = all known)."
    )
    override: str | None = Field(default=None, description="e.g. 'confirmed_malicious'.")
