"""Scanner parsing, correlation, feeds, finding construction and the citation verifier.

Uses hand-written outputs in each tool's real format, so no scanners are needed. The fixture
files go in runs/pytest-scan, inside the workspace, because the verifier path-jails them.
"""

import gzip
import json
import shutil

import pytest

from guardian.sbom.npm_lock import build_graph, parse_lockfile
from guardian.scan.baseline import make_findings
from guardian.scan.feeds import EpssFeed, EpssScore, KevEntry, KevFeed, load_epss, load_kev
from guardian.scan.parsers import correlate, norm_severity, parse_grype, parse_osv, parse_trivy
from guardian.scan.verify import verify
from guardian.schemas import Exposure, FindingType, Severity
from guardian.tools.runner import WORKSPACE

FIX = WORKSPACE / "runs" / "pytest-scan"
REL = "runs/pytest-scan"

LOCK = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo", "version": "1.0.0", "dependencies": {"a": "1", "b": "1"},
             "devDependencies": {"t": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "2"}},
        "node_modules/c": {"version": "2.0.0"},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"evil": "1"}},
        "node_modules/evil": {"version": "1.0.0"},
        "node_modules/t": {"version": "1.0.0", "dev": True},
    },
}  # fmt: skip


def grype_match(vid, name, version, related=(), sev="High", fix=(), score=None):
    return {
        "vulnerability": {
            "id": vid, "severity": sev, "dataSource": f"https://example.test/{vid}",
            "description": f"{vid} summary",
            "cvss": [{"version": "3.1", "metrics": {"baseScore": score}}] if score else [],
            "fix": {"versions": list(fix), "state": "fixed" if fix else "not-fixed"},
        },
        "relatedVulnerabilities": [{"id": r, "cvss": []} for r in related],
        "artifact": {"name": name, "version": version},
        "matchDetails": [{"type": "exact-direct-match"}],
    }  # fmt: skip


GRYPE = {
    "matches": [
        grype_match("GHSA-aaaa", "c", "2.0.0", ["CVE-2020-0001"], "Critical", ["2.0.1"], 9.8),
        grype_match("GHSA-aaaa", "c", "2.0.0", ["CVE-2020-0001"], "Critical", ["2.0.1"], 9.8),
        grype_match("GHSA-bbbb", "a", "1.0.0", sev="Medium"),
        grype_match("MAL-2023-1", "evil", "1.0.0", ["GHSA-mmmm"], "Critical", ["1.0.1"]),
    ]
}
TRIVY = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2020-0001", "PkgName": "c", "InstalledVersion": "2.0.0",
                 "FixedVersion": "2.0.1", "Severity": "CRITICAL", "Title": "c is bad",
                 "CVSS": {"nvd": {"V3Score": 9.1}, "ghsa": {"V3Score": 9.8}}},
                {"VulnerabilityID": "NSWG-ECO-1", "PkgName": "t", "InstalledVersion": "1.0.0",
                 "FixedVersion": "", "Severity": "LOW", "Title": "t is old"},
            ],
        }
    ]
}  # fmt: skip
OSV = {
    "results": [
        {
            "source": {"path": "package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "c", "version": "2.0.0", "ecosystem": "npm"},
                    "groups": [{"ids": ["GHSA-aaaa"], "max_severity": "9.8"}],
                    "vulnerabilities": [
                        {"id": "GHSA-aaaa", "aliases": ["CVE-2020-0001"], "summary": "c is bad",
                         "database_specific": {"severity": "CRITICAL"},
                         "affected": [{"package": {"name": "c"},
                                       "ranges": [{"events": [{"introduced": "0"},
                                                              {"fixed": "2.0.1"}]}]}]}
                    ],
                }
            ],
        }
    ]
}  # fmt: skip
EPSS = EpssFeed("v-test", "2026-11-22", {"CVE-2020-0001": EpssScore("CVE-2020-0001", 0.5, 0.9)})
KEV = KevFeed("test", "2026-11-20", {"CVE-2020-0001": KevEntry("CVE-2020-0001", "2024-01-01",
                                                               "x", "c", "Unknown")})  # fmt: skip
OUTPUTS = {"grype": f"{REL}/grype.json", "trivy": f"{REL}/trivy.json",
           "osv-scanner": f"{REL}/osv.json"}  # fmt: skip


@pytest.fixture(scope="module")
def scenario():
    shutil.rmtree(FIX, ignore_errors=True)
    FIX.mkdir(parents=True)
    (FIX / "package-lock.json").write_text(json.dumps(LOCK, indent=2))
    for name, data in (("grype", GRYPE), ("trivy", TRIVY), ("osv", OSV)):
        (FIX / f"{name}.json").write_text(json.dumps(data))
    lock = parse_lockfile(FIX / "package-lock.json", f"{REL}/package-lock.json")
    graph, _ = build_graph(lock)
    raw = [*parse_grype(FIX / "grype.json"), *parse_trivy(FIX / "trivy.json"),
           *parse_osv(FIX / "osv.json")]  # fmt: skip
    groups = correlate(raw)
    versions = {"grype": "grype 0", "trivy": "trivy 0", "osv-scanner": "osv 0"}
    fs, unmapped = make_findings(groups, graph, f"{REL}/package-lock.json", OUTPUTS, versions,
                                 EPSS, KEV)  # fmt: skip
    yield {"raw": raw, "groups": groups, "graph": graph, "fs": fs, "unmapped": unmapped}
    shutil.rmtree(FIX, ignore_errors=True)


def by_name(fs, name):
    return next(f for f in fs.findings if f.component.name == name)


# --- parsers -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "expected"),
    [("High", Severity.HIGH), ("MODERATE", Severity.MEDIUM), ("negligible", Severity.LOW),
     ("", Severity.UNKNOWN), (None, Severity.UNKNOWN), ("weird", Severity.UNKNOWN)],
)  # fmt: skip
def test_severity_normalization(label, expected):
    assert norm_severity(label) is expected


def test_parsers_keep_pointers_and_values(scenario):
    raw = scenario["raw"]
    g = [m for m in raw if m.tool == "grype"]
    assert [m.pointer for m in g] == ["/matches/0", "/matches/1", "/matches/2", "/matches/3"]
    assert g[0].aliases == {"CVE-2020-0001"} and g[0].cvss == 9.8 and g[0].fixed == ("2.0.1",)
    assert g[2].fixed == ()  # not-fixed state carries no versions
    assert g[3].malicious
    t = [m for m in raw if m.tool == "trivy"]
    assert t[0].cvss == 9.8  # highest v3 score across the record's sources
    assert t[1].fixed == () and t[1].pointer == "/Results/0/Vulnerabilities/1"
    o = [m for m in raw if m.tool == "osv-scanner"]
    assert o[0].cvss == 9.8 and o[0].fixed == ("2.0.1",)
    assert o[0].pointer == "/results/0/packages/0/vulnerabilities/0"


def test_correlation_merges_aliases_across_tools_and_drops_repeats(scenario):
    groups = {(g.name, g.version): g for g in scenario["groups"]}
    c = groups[("c", "2.0.0")]
    assert c.tools == {"grype", "trivy", "osv-scanner"}
    assert c.ids == {"GHSA-aaaa", "CVE-2020-0001"}
    assert len(c.matches) == 3  # grype's second identical match was dropped
    assert groups[("evil", "1.0.0")].malicious
    assert groups[("t", "1.0.0")].tools == {"trivy"}
    assert len(scenario["groups"]) == 4


def test_unrelated_ids_on_one_package_stay_separate():
    raw = parse_grype_from(
        [grype_match("GHSA-1", "x", "1", ["CVE-1"]), grype_match("GHSA-2", "x", "1", ["CVE-2"])]
    )
    assert len(correlate(raw)) == 2


def parse_grype_from(matches):
    FIX.mkdir(parents=True, exist_ok=True)
    path = FIX / "grype-extra.json"
    path.write_text(json.dumps({"matches": matches}))
    return parse_grype(path)


# --- feeds -----------------------------------------------------------------------------------


def test_load_epss_and_kev(tmp_path):
    epss = tmp_path / "epss.csv.gz"
    with gzip.open(epss, "wt") as f:
        f.write("#model_version:v1,score_date:2026-11-22T00:00:00Z\ncve,epss,percentile\n")
        f.write("CVE-1,0.1,0.5\nCVE-2,0.9,0.99\nCVE-3,bad,0.1\n")
    feed = load_epss(epss, wanted={"CVE-2", "CVE-3"})
    assert feed.model_version == "v1" and feed.score_date == "2026-11-22T00:00:00Z"
    assert set(feed.scores) == {"CVE-2"}  # CVE-1 not wanted; CVE-3 malformed and skipped
    kev = tmp_path / "kev.json"
    entry = {"cveID": "CVE-2", "dateAdded": "x"}
    kev.write_text(
        json.dumps({"catalogVersion": "1", "dateReleased": "d", "vulnerabilities": [entry]})
    )
    k = load_kev(kev)
    assert k.catalog_version == "1" and set(k.entries) == {"CVE-2"}


# --- findings ------------------------------------------------------------------------------


def test_findings_types_order_and_facts(scenario):
    fs = scenario["fs"]
    assert scenario["unmapped"] == []
    assert [f.id for f in fs.findings] == ["F-001", "F-002", "F-003", "F-004"]
    assert fs.findings[0].component.name == "evil"  # malicious sorts first
    assert fs.findings[1].component.name == "c"  # then KEV

    evil = by_name(fs, "evil")
    assert evil.type is FindingType.MALICIOUS_PACKAGE
    assert evil.factors.confirmed_malicious is True
    assert evil.dependency_path == ("demo@1.0.0", "b@1.0.0", "evil@1.0.0")

    c = by_name(fs, "c")
    assert c.type is FindingType.VULNERABLE_TRANSITIVE
    assert c.dependency_path == ("demo@1.0.0", "a@1.0.0", "c@2.0.0")
    assert c.introduced_by == ("a@1.0.0",)
    assert c.factors.kev is True and c.factors.epss == 0.5 and c.factors.cvss == 9.8
    assert {fi.tool for fi in c.fixed_in} == {"grype", "trivy", "osv-scanner"}
    assert {e.tool for e in c.evidence} == {
        "grype", "trivy", "osv-scanner", "dependency-graph", "epss", "cisa-kev"
    }  # fmt: skip

    a = by_name(fs, "a")
    assert a.type is FindingType.VULNERABLE_DIRECT
    assert a.factors.kev is None  # no CVE alias: KEV membership unknown, not "no"
    assert a.factors.epss is None
    assert a.fixed_in == ()

    t = by_name(fs, "t")
    assert t.factors.exposure is Exposure.BUILD_OR_DEV
    assert a.factors.exposure is Exposure.UNKNOWN


def test_scanner_evidence_cites_lockfile_line(scenario):
    fs = scenario["fs"]
    store = {r.id: r for r in fs.evidence}
    c = by_name(fs, "c")
    lines = (FIX / "package-lock.json").read_text().splitlines()
    for ref in c.evidence:
        rec = store[ref.evidence_id]
        if rec.tool in OUTPUTS:
            assert lines[rec.line - 1].strip() == '"node_modules/c": {'
            assert rec.excerpt.startswith(OUTPUTS[rec.tool] + "#/")


def test_shared_evidence_is_deduplicated(scenario):
    fs = scenario["fs"]
    ids = [r.id for r in fs.evidence]
    assert len(ids) == len(set(ids))
    graph_nodes = [r.graph_node for r in fs.evidence if r.graph_node]
    assert len(graph_nodes) == len(set(graph_nodes))


# --- verifier ------------------------------------------------------------------------------


def test_verifier_resolves_everything(scenario):
    v = verify(scenario["fs"], scenario["graph"], OUTPUTS)
    assert v.failures == []
    assert v.rate == 1.0 and v.checked > 20


def tampered(fs, finding_id, **update):
    findings = tuple(f.model_copy(update=update) if f.id == finding_id else f for f in fs.findings)
    return fs.model_copy(update={"findings": findings})


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"advisory_ids": ("GHSA-aaaa", "CVE-2020-0001", "CVE-2099-9999")}, "CVE-2099-9999"),
        ({"dependency_path": ("demo@1.0.0", "b@1.0.0", "c@2.0.0")}, "dependency_path"),
        ({"introduced_by": ("ghost@1.0.0",)}, "ghost@1.0.0"),
    ],
)
def test_verifier_catches_invented_facts(scenario, update, message):
    bad = tampered(scenario["fs"], "F-002", **update)
    v = verify(bad, scenario["graph"], OUTPUTS)
    assert v.rate < 1.0
    assert any(message in f for f in v.failures)


def test_verifier_catches_wrong_version_and_fix(scenario):
    fs = scenario["fs"]
    c = by_name(fs, "c")
    wrong = c.component.model_copy(update={"version": "9.9.9"})
    v = verify(tampered(fs, c.id, component=wrong), scenario["graph"], OUTPUTS)
    assert any("raw package c@2.0.0 != c@9.9.9" in f for f in v.failures)
    bad_fix = (c.fixed_in[0].model_copy(update={"versions": ("3.0.0",)}),)
    v = verify(tampered(fs, c.id, fixed_in=bad_fix), scenario["graph"], OUTPUTS)
    assert any("fix 3.0.0" in f for f in v.failures)
