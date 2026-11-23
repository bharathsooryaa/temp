"""Contract tests for evidence, SBOM, graph and finding schemas."""

import pytest
from pydantic import ValidationError

from guardian.schemas import (
    Component,
    DependencyGraph,
    Ecosystem,
    EvidenceKind,
    EvidenceRecord,
    EvidenceRef,
    Exposure,
    Finding,
    FindingSet,
    FindingType,
    Fix,
    FixAction,
    GraphEdge,
    Reachability,
    RiskFactors,
    RiskLevel,
    SbomComponent,
    cited_evidence_ids,
)
from guardian.scoring import score_risk

LODASH = Component(
    name="lodash", version="4.17.15", purl="pkg:npm/lodash@4.17.15", ecosystem=Ecosystem.NPM
)


def grype_evidence(eid="E-001"):
    return EvidenceRecord(
        id=eid,
        kind=EvidenceKind.SCANNER_RESULT,
        tool="grype",
        ref="GHSA-xxxx",
        file="package-lock.json",
        line=1243,
    )


def grype_ref(eid="E-001"):
    return EvidenceRef(
        evidence_id=eid, tool="grype", ref="GHSA-xxxx", file="package-lock.json", line=1243
    )


def transitive_finding(**overrides):
    factors = RiskFactors(
        cvss=7.4,
        epss=0.12,
        kev=False,
        reachability=Reachability.IMPORTED,
        exposure=Exposure.RUNTIME_INTERNAL,
        provenance=10,
    )
    data = {
        "id": "F-014",
        "type": FindingType.VULNERABLE_TRANSITIVE,
        "title": "lodash 4.17.15 has a known vulnerability",
        "component": LODASH,
        "dependency_path": ("app", "express-validator@6.x", "lodash@4.17.15"),
        "evidence": (grype_ref(),),
        "factors": factors,
        "risk": score_risk(factors),
        "rationale": "Grype reports the advisory for this version [E-001].",
        "fix": Fix(action=FixAction.UPGRADE, target="4.17.21", breaking=False),
    }
    data.update(overrides)
    return Finding(**data)


# --- workspace path jail -------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "../secrets.txt", "a/../../b", "C:/Windows/x", "dir\\file", "", "a\x00b"],
)
def test_evidence_rejects_paths_outside_workspace(path):
    with pytest.raises(ValidationError):
        EvidenceRecord(id="E-001", kind=EvidenceKind.FILE_LOCATION, tool="rg", file=path)


def test_evidence_normalizes_relative_path():
    rec = EvidenceRecord(
        id="E-001", kind=EvidenceKind.FILE_LOCATION, tool="rg", file="./src/./app.js"
    )
    assert rec.file == "src/app.js"


# --- evidence records ------------------------------------------------------------------


def test_evidence_must_be_locatable():
    with pytest.raises(ValidationError, match="at least one of"):
        EvidenceRecord(id="E-001", kind=EvidenceKind.ADVISORY, tool="osv")


def test_line_requires_file():
    with pytest.raises(ValidationError, match="'line' requires 'file'"):
        EvidenceRecord(id="E-001", kind=EvidenceKind.ADVISORY, tool="osv", ref="GHSA-1", line=3)


def test_graph_node_evidence_requires_node():
    with pytest.raises(ValidationError):
        EvidenceRecord(id="E-001", kind=EvidenceKind.GRAPH_NODE, tool="graph", ref="x")


@pytest.mark.parametrize("bad_id", ["E-1", "F-001", "e-001", "E-00a"])
def test_evidence_id_format(bad_id):
    with pytest.raises(ValidationError):
        EvidenceRecord(id=bad_id, kind=EvidenceKind.ADVISORY, tool="osv", ref="GHSA-1")


def test_contracts_are_frozen_and_reject_extra_fields():
    rec = grype_evidence()
    with pytest.raises(ValidationError):
        rec.tool = "other"
    with pytest.raises(ValidationError):
        EvidenceRecord(
            id="E-001", kind=EvidenceKind.ADVISORY, tool="osv", ref="GHSA-1", severity="high"
        )


# --- components ------------------------------------------------------------------------


def test_unknown_version_stays_none():
    assert Component(name="left-pad").version is None


@pytest.mark.parametrize("purl", ["lodash@4.17.15", "pkg:/lodash", "npm:lodash"])
def test_bad_purl_rejected(purl):
    with pytest.raises(ValidationError):
        Component(name="lodash", purl=purl)


# --- graph -----------------------------------------------------------------------------


def node(ref, name=None):
    return SbomComponent(bom_ref=ref, component=Component(name=name or ref))


def sample_graph():
    return DependencyGraph(
        root="app",
        nodes=(node("app"), node("ev"), node("lodash"), node("orphan")),
        edges=(GraphEdge(source="app", target="ev"), GraphEdge(source="ev", target="lodash")),
    )


def test_graph_shortest_path():
    graph = sample_graph()
    assert graph.shortest_path("lodash") == ("app", "ev", "lodash")
    assert graph.shortest_path("app") == ("app",)
    assert graph.shortest_path("orphan") is None
    with pytest.raises(KeyError):
        graph.shortest_path("missing")


def test_graph_rejects_dangling_edge():
    with pytest.raises(ValidationError, match="unknown node"):
        DependencyGraph(
            root="app", nodes=(node("app"),), edges=(GraphEdge(source="app", target="ghost"),)
        )


def test_graph_rejects_duplicate_nodes_and_missing_root():
    with pytest.raises(ValidationError, match="duplicate"):
        DependencyGraph(root="app", nodes=(node("app"), node("app")))
    with pytest.raises(ValidationError, match="root"):
        DependencyGraph(root="app", nodes=(node("other"),))


def test_graph_handles_cycles():
    graph = DependencyGraph(
        root="app",
        nodes=(node("app"), node("a"), node("b")),
        edges=(
            GraphEdge(source="app", target="a"),
            GraphEdge(source="a", target="b"),
            GraphEdge(source="b", target="a"),
        ),
    )
    assert graph.shortest_path("b") == ("app", "a", "b")


# --- findings --------------------------------------------------------------------------


def test_pdf_example_finding_validates_and_round_trips():
    finding = transitive_finding()
    assert finding.risk.level is RiskLevel.MEDIUM
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_finding_requires_evidence():
    with pytest.raises(ValidationError):
        transitive_finding(evidence=())


def test_direct_vs_transitive_path_lengths():
    with pytest.raises(ValidationError, match="vulnerable_direct"):
        transitive_finding(type=FindingType.VULNERABLE_DIRECT)
    with pytest.raises(ValidationError, match="vulnerable_transitive"):
        transitive_finding(dependency_path=("app", "lodash@4.17.15"))
    direct = transitive_finding(
        type=FindingType.VULNERABLE_DIRECT, dependency_path=("app", "lodash@4.17.15")
    )
    assert direct.type is FindingType.VULNERABLE_DIRECT


def test_rationale_must_cite_only_attached_evidence():
    with pytest.raises(ValidationError, match="must cite"):
        transitive_finding(rationale="This looks bad.")
    with pytest.raises(ValidationError, match="E-999"):
        transitive_finding(rationale="See [E-001] and [E-999].")


def test_cited_evidence_ids_extraction():
    assert cited_evidence_ids("[E-001], E-0042; not XE-001 or E-01") == {"E-001", "E-0042"}


def test_confirmed_malicious_only_on_malicious_package_with_override():
    factors = RiskFactors(confirmed_malicious=True)
    with pytest.raises(ValidationError, match="malicious_package"):
        transitive_finding(factors=factors, risk=score_risk(factors))
    with pytest.raises(ValidationError, match="override"):
        transitive_finding(
            type=FindingType.MALICIOUS_PACKAGE, factors=factors, risk=score_risk(RiskFactors())
        )
    ok = transitive_finding(
        type=FindingType.MALICIOUS_PACKAGE, factors=factors, risk=score_risk(factors)
    )
    assert ok.risk.level is RiskLevel.CRITICAL


def test_typosquat_finding_is_not_confirmed_malicious():
    factors = RiskFactors(provenance=90)
    finding = transitive_finding(
        type=FindingType.TYPOSQUAT, dependency_path=(), factors=factors, risk=score_risk(factors)
    )
    assert finding.risk.override is None


# --- finding set: every citation resolves ----------------------------------------------


def test_finding_set_resolves_all_citations():
    FindingSet(evidence=(grype_evidence(),), findings=(transitive_finding(),))


def test_finding_set_rejects_unresolved_citation():
    with pytest.raises(ValidationError, match="unresolved E-001"):
        FindingSet(evidence=(), findings=(transitive_finding(),))


def test_finding_set_rejects_tool_mismatch():
    osv = EvidenceRecord(id="E-001", kind=EvidenceKind.ADVISORY, tool="osv", ref="GHSA-xxxx")
    with pytest.raises(ValidationError, match="tool"):
        FindingSet(evidence=(osv,), findings=(transitive_finding(),))


def test_finding_set_rejects_duplicates():
    with pytest.raises(ValidationError, match="duplicate evidence"):
        FindingSet(evidence=(grype_evidence(), grype_evidence()), findings=())
    with pytest.raises(ValidationError, match="duplicate finding"):
        FindingSet(
            evidence=(grype_evidence(),), findings=(transitive_finding(), transitive_finding())
        )
