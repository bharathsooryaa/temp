"""Risk scoring against PDF section 6 weights, scales, bands and override."""

import math

import pytest

from guardian.schemas.risk import Exposure, Reachability, RiskFactor, RiskFactors, RiskLevel
from guardian.scoring import WEIGHTS, band, normalize, score_risk


def test_weights_match_pdf_and_sum_to_one():
    assert dict(WEIGHTS) == {
        RiskFactor.CVSS: 0.30,
        RiskFactor.EPSS_KEV: 0.20,
        RiskFactor.REACHABILITY: 0.20,
        RiskFactor.EXPOSURE: 0.15,
        RiskFactor.PROVENANCE: 0.15,
    }
    assert math.isclose(sum(WEIGHTS.values()), 1.0)


@pytest.mark.parametrize(
    ("reach", "expected"),
    [
        (Reachability.CALLED, 100.0),
        (Reachability.IMPORTED, 60.0),
        (Reachability.PRESENT_ONLY, 30.0),
        (Reachability.DEV_ONLY_UNUSED, 0.0),
        (Reachability.UNKNOWN, None),
    ],
)
def test_reachability_scale(reach, expected):
    assert normalize(RiskFactors(reachability=reach))[RiskFactor.REACHABILITY] == expected


@pytest.mark.parametrize(
    ("exposure", "expected"),
    [
        (Exposure.RUNTIME_NETWORK, 100.0),
        (Exposure.RUNTIME_INTERNAL, 50.0),
        (Exposure.BUILD_OR_DEV, 20.0),
        (Exposure.UNKNOWN, None),
    ],
)
def test_exposure_scale(exposure, expected):
    assert normalize(RiskFactors(exposure=exposure))[RiskFactor.EXPOSURE] == expected


@pytest.mark.parametrize(
    ("epss", "kev", "expected"),
    [
        (0.12, None, 12.0),
        (0.12, False, 12.0),
        (0.12, True, 100.0),  # KEV forces 100
        (None, True, 100.0),
        (None, False, None),  # not in KEV but EPSS unknown -> still unknown, not zero
        (None, None, None),
    ],
)
def test_epss_kev_scale(epss, kev, expected):
    assert normalize(RiskFactors(epss=epss, kev=kev))[RiskFactor.EPSS_KEV] == expected


def test_cvss_times_ten():
    assert normalize(RiskFactors(cvss=7.4))[RiskFactor.CVSS] == pytest.approx(74.0)


def test_all_known_weighted_sum():
    # 0.30*74 + 0.20*12 + 0.20*60 + 0.15*50 + 0.15*10 = 45.6
    result = score_risk(
        RiskFactors(
            cvss=7.4,
            epss=0.12,
            kev=False,
            reachability=Reachability.IMPORTED,
            exposure=Exposure.RUNTIME_INTERNAL,
            provenance=10,
        )
    )
    assert result.score == 45.6
    assert result.level is RiskLevel.MEDIUM
    assert result.unknown_factors == ()
    assert result.weight_coverage == 1.0
    assert result.override is None
    assert sum(c.contribution for c in result.contributions) == pytest.approx(45.6)


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (100.0, RiskLevel.CRITICAL),
        (85.0, RiskLevel.CRITICAL),
        (84.99, RiskLevel.HIGH),
        (65.0, RiskLevel.HIGH),
        (64.99, RiskLevel.MEDIUM),
        (40.0, RiskLevel.MEDIUM),
        (39.99, RiskLevel.LOW),
        (0.0, RiskLevel.LOW),
    ],
)
def test_band_boundaries(score, level):
    assert band(score) is level


def test_exact_85_from_factors_is_critical():
    # 0.30*100 + 0.20*100 + 0.20*100 + 0.15*100 + 0.15*0 = 85
    result = score_risk(
        RiskFactors(
            cvss=10.0,
            kev=True,
            reachability=Reachability.CALLED,
            exposure=Exposure.RUNTIME_NETWORK,
            provenance=0,
        )
    )
    assert result.score == 85.0
    assert result.level is RiskLevel.CRITICAL


def test_exact_65_from_factors_is_high():
    result = score_risk(
        RiskFactors(
            cvss=10.0,
            kev=True,
            reachability=Reachability.DEV_ONLY_UNUSED,
            exposure=Exposure.RUNTIME_NETWORK,
            provenance=0,
        )
    )
    assert result.score == 65.0
    assert result.level is RiskLevel.HIGH


def test_fractional_just_below_critical_is_high():
    # 0.30*98 + 20 + 20 + 15 + 0 = 84.4
    result = score_risk(
        RiskFactors(
            cvss=9.8,
            kev=True,
            reachability=Reachability.CALLED,
            exposure=Exposure.RUNTIME_NETWORK,
            provenance=0,
        )
    )
    assert result.score == 84.4
    assert result.level is RiskLevel.HIGH


def test_rounding_happens_before_banding():
    result = score_risk(RiskFactors(cvss=8.4996))  # 84.996 -> displayed 85.0
    assert result.score == 85.0
    assert result.level is RiskLevel.CRITICAL


def test_unknown_factors_renormalized_not_zero():
    # (0.30*50 + 0.20*100) / 0.50 = 70; treating unknown as zero would give 35.
    result = score_risk(RiskFactors(cvss=5.0, reachability=Reachability.CALLED))
    assert result.score == 70.0
    assert result.level is RiskLevel.HIGH
    assert result.weight_coverage == 0.5
    assert set(result.unknown_factors) == {
        RiskFactor.EPSS_KEV,
        RiskFactor.EXPOSURE,
        RiskFactor.PROVENANCE,
    }
    unknown = [c for c in result.contributions if c.value is None]
    assert all(c.contribution is None and c.effective_weight == 0 for c in unknown)


def test_nothing_known_is_unknown_level():
    result = score_risk(RiskFactors())
    assert result.score is None
    assert result.level is RiskLevel.UNKNOWN
    assert result.weight_coverage == 0.0
    assert len(result.unknown_factors) == 5


def test_confirmed_malicious_forces_critical():
    result = score_risk(
        RiskFactors(
            cvss=0.0,
            reachability=Reachability.DEV_ONLY_UNUSED,
            exposure=Exposure.BUILD_OR_DEV,
            provenance=0,
            confirmed_malicious=True,
        )
    )
    assert result.score is not None and result.score < 40
    assert result.level is RiskLevel.CRITICAL
    assert result.override == "confirmed_malicious"


def test_confirmed_malicious_with_no_factors_still_critical():
    result = score_risk(RiskFactors(confirmed_malicious=True))
    assert result.score is None
    assert result.level is RiskLevel.CRITICAL


def test_typosquat_heuristic_is_not_forced_critical():
    # Suspicion raises provenance only: (0.15*90 + 0.20*30 + 0.15*20) / 0.50 = 45
    result = score_risk(
        RiskFactors(
            provenance=90,
            reachability=Reachability.PRESENT_ONLY,
            exposure=Exposure.BUILD_OR_DEV,
        )
    )
    assert result.score == 45.0
    assert result.level is RiskLevel.MEDIUM
    assert result.override is None


@pytest.mark.parametrize(
    "bad",
    [{"cvss": 10.1}, {"cvss": -1}, {"epss": 1.5}, {"provenance": 101}, {"provenance": -0.1}],
)
def test_out_of_range_inputs_rejected(bad):
    with pytest.raises(ValueError):
        RiskFactors(**bad)
