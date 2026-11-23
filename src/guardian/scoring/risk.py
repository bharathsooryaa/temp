"""Transparent weighted risk score (PDF section 6).

Risk = 0.30*S_cvss + 0.20*S_epss/kev + 0.20*S_reach + 0.15*S_exposure + 0.15*S_prov

Documented decisions (DECISIONS.md D1-02, D1-03):
* Unknown factors are excluded and the remaining weights are renormalized to sum to 1.
  They are reported in ``unknown_factors`` with ``weight_coverage``; never treated as zero.
* The score is rounded to 2 decimals *before* banding, so the displayed score and band agree.
  Bands: Critical >= 85, High >= 65, Medium >= 40, Low < 40.
* ``confirmed_malicious`` forces Critical regardless of score; heuristics cannot set it.
"""

from __future__ import annotations

from types import MappingProxyType

from guardian.schemas.risk import (
    Exposure,
    FactorContribution,
    Reachability,
    RiskAssessment,
    RiskFactor,
    RiskFactors,
    RiskLevel,
)

WEIGHTS = MappingProxyType(
    {
        RiskFactor.CVSS: 0.30,
        RiskFactor.EPSS_KEV: 0.20,
        RiskFactor.REACHABILITY: 0.20,
        RiskFactor.EXPOSURE: 0.15,
        RiskFactor.PROVENANCE: 0.15,
    }
)

REACHABILITY_SCALE = MappingProxyType(
    {
        Reachability.CALLED: 100.0,
        Reachability.IMPORTED: 60.0,
        Reachability.PRESENT_ONLY: 30.0,
        Reachability.DEV_ONLY_UNUSED: 0.0,
    }
)

EXPOSURE_SCALE = MappingProxyType(
    {
        Exposure.RUNTIME_NETWORK: 100.0,
        Exposure.RUNTIME_INTERNAL: 50.0,
        Exposure.BUILD_OR_DEV: 20.0,
    }
)

# (lower bound inclusive, level), checked in order.
BANDS: tuple[tuple[float, RiskLevel], ...] = (
    (85.0, RiskLevel.CRITICAL),
    (65.0, RiskLevel.HIGH),
    (40.0, RiskLevel.MEDIUM),
    (0.0, RiskLevel.LOW),
)

CONFIRMED_MALICIOUS = "confirmed_malicious"


def normalize(factors: RiskFactors) -> dict[RiskFactor, float | None]:
    """Map raw inputs onto the PDF's 0-100 scales. ``None`` = unknown."""
    if factors.kev is True:
        epss_kev: float | None = 100.0  # KEV forces 100
    elif factors.epss is not None:
        epss_kev = factors.epss * 100.0
    else:
        epss_kev = None  # kev False/None with no EPSS: exploit likelihood still unknown
    return {
        RiskFactor.CVSS: None if factors.cvss is None else factors.cvss * 10.0,
        RiskFactor.EPSS_KEV: epss_kev,
        RiskFactor.REACHABILITY: REACHABILITY_SCALE.get(factors.reachability),
        RiskFactor.EXPOSURE: EXPOSURE_SCALE.get(factors.exposure),
        RiskFactor.PROVENANCE: factors.provenance,
    }


def band(score: float) -> RiskLevel:
    for lower, level in BANDS:
        if score >= lower:
            return level
    return RiskLevel.LOW


def score_risk(factors: RiskFactors) -> RiskAssessment:
    values = normalize(factors)
    known = {f: v for f, v in values.items() if v is not None}
    coverage = round(sum(WEIGHTS[f] for f in known), 10)

    contributions: list[FactorContribution] = []
    total = 0.0
    for factor, weight in WEIGHTS.items():
        value = values[factor]
        effective = weight / coverage if value is not None and coverage > 0 else 0.0
        contribution = None if value is None else effective * value
        if contribution is not None:
            total += contribution
        contributions.append(
            FactorContribution(
                factor=factor,
                weight=weight,
                value=value,
                effective_weight=round(effective, 6),
                contribution=None if contribution is None else round(contribution, 2),
            )
        )

    score = round(min(max(total, 0.0), 100.0), 2) if known else None
    level = band(score) if score is not None else RiskLevel.UNKNOWN
    override = None
    if factors.confirmed_malicious:
        level, override = RiskLevel.CRITICAL, CONFIRMED_MALICIOUS

    return RiskAssessment(
        score=score,
        level=level,
        contributions=tuple(contributions),
        unknown_factors=tuple(f for f, v in values.items() if v is None),
        weight_coverage=coverage,
        override=override,
    )
