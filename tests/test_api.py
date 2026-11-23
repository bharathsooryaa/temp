"""Read-only API: endpoints, filters, graph elements, UI serving and security properties."""

import shutil
import sqlite3

import pytest
from fastapi.testclient import TestClient

from guardian.api.__main__ import main as api_main
from guardian.api.app import create_app
from guardian.schemas import (
    Component,
    DependencyGraph,
    EvidenceKind,
    EvidenceRecord,
    EvidenceRef,
    Finding,
    FindingSet,
    FindingType,
    GraphEdge,
    RiskFactors,
    SbomComponent,
)
from guardian.scoring import score_risk
from guardian.store import connect, save_explanation, save_run
from guardian.tools.runner import WORKSPACE

DIR = WORKSPACE / "runs" / "pytest-api"
DB = "runs/pytest-api/guardian.db"
RUN = "runs/pytest-api/run"


def sample():
    evidence = (
        EvidenceRecord(
            id="E-001",
            kind=EvidenceKind.SCANNER_RESULT,
            tool="grype",
            ref="GHSA-aaaa-bbbb-cccc",
            excerpt="<script>alert(1)</script>",
        ),
        EvidenceRecord(
            id="E-002",
            kind=EvidenceKind.GRAPH_NODE,
            tool="dependency-graph",
            graph_node="node_modules/b",
        ),
        EvidenceRecord(
            id="E-003", kind=EvidenceKind.SCANNER_RESULT, tool="trivy", ref="CVE-2020-1"
        ),
    )
    hi, lo = RiskFactors(cvss=9.0), RiskFactors(cvss=3.0)
    findings = (
        Finding(
            id="F-001",
            type=FindingType.VULNERABLE_TRANSITIVE,
            title="b@1.0.0: proto_%",
            component=Component(name="b", version="1.0.0"),
            dependency_path=("app@1.0.0", "a@1.0.0", "b@1.0.0"),
            introduced_by=("a@1.0.0",),
            advisory_ids=("GHSA-aaaa-bbbb-cccc",),
            evidence=(
                EvidenceRef(evidence_id="E-001", tool="grype"),
                EvidenceRef(evidence_id="E-002", tool="dependency-graph"),
            ),
            factors=hi,
            risk=score_risk(hi),
        ),
        Finding(
            id="F-002",
            type=FindingType.VULNERABLE_IMAGE_PACKAGE,
            title="zlib@1.2: bug",
            component=Component(name="zlib", version="1.2"),
            dependency_path=("node:20@sha256:" + "a" * 64, "zlib@1.2"),
            advisory_ids=("CVE-2020-1",),
            evidence=(EvidenceRef(evidence_id="E-003", tool="trivy"),),
            factors=lo,
            risk=score_risk(lo),
        ),
    )
    graph = DependencyGraph(
        root=".",
        nodes=tuple(
            SbomComponent(bom_ref=r, component=Component(name=n, version=v))
            for r, n, v in (
                (".", "app", "1.0.0"),
                ("node_modules/a", "a", "1.0.0"),
                ("node_modules/b", "b", "1.0.0"),
                ("node_modules/c", "c", "1.0.0"),
            )
        ),
        edges=(
            GraphEdge(source=".", target="node_modules/a"),
            GraphEdge(source=".", target="node_modules/c"),
            GraphEdge(source="node_modules/a", target="node_modules/b"),
            GraphEdge(source="node_modules/c", target="node_modules/b"),
        ),
    )
    return FindingSet(evidence=evidence, findings=findings), graph


@pytest.fixture(scope="module")
def client():
    shutil.rmtree(DIR, ignore_errors=True)
    DIR.mkdir(parents=True)
    ui = DIR / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text("<!doctype html><div id=root></div>")
    (ui / "assets" / "app.js").write_text("console.log(1)")
    fs, graph = sample()
    conn = connect(DB)
    save_run(
        conn,
        RUN,
        {
            "target": {"name": "t", "commit": "c" * 40},
            "generated_at": "2026-11-23T00:00:00",
            "findings": 2,
        },
        fs,
        graph,
    )
    save_explanation(conn, RUN, "F-001", "rejected", "scripted", "s", {"x": 1}, ["bad"])
    save_explanation(conn, RUN, "F-001", "accepted", "scripted", "s", {"why_it_matters": "w"}, [])
    conn.close()
    yield TestClient(create_app(DB, ui))
    shutil.rmtree(DIR, ignore_errors=True)


def test_runs_and_summary(client):
    runs = client.get("/api/runs").json()
    assert [r["run_id"] for r in runs] == [RUN]
    assert client.get("/api/summary", params={"run": RUN}).json()["findings"] == 2


def test_findings_list_filters_and_search_escaping(client):
    j = client.get("/api/findings", params={"run": RUN}).json()
    assert j["total"] == 2 and [x["id"] for x in j["items"]] == ["F-001", "F-002"]
    assert j["items"][0]["explained"] is True and j["items"][1]["explained"] is False
    typed = client.get("/api/findings", params={"run": RUN, "type": "vulnerable_image_package"})
    assert [x["id"] for x in typed.json()["items"]] == ["F-002"]
    level = j["items"][1]["risk_level"]
    assert client.get("/api/findings", params={"run": RUN, "level": level}).json()["total"] >= 1
    assert (
        client.get("/api/findings", params={"run": RUN, "q": "%"}).json()["total"] == 1
    )  # literal %
    assert client.get("/api/findings", params={"run": RUN, "q": "_"}).json()["total"] == 1
    assert client.get("/api/findings", params={"run": RUN, "q": "zlib"}).json()["total"] == 1
    assert client.get("/api/findings", params={"run": RUN, "limit": 0}).status_code == 422


def test_finding_detail_returns_ordered_evidence_and_explanation(client):
    d = client.get("/api/findings/F-001", params={"run": RUN}).json()
    assert [e["id"] for e in d["evidence"]] == ["E-001", "E-002"]
    assert d["evidence"][0]["excerpt"] == "<script>alert(1)</script>"  # data, escaped by the UI
    assert d["explanation"]["generator"] == "offline scripted template (not an LLM)"
    assert d["rejected_explanations"] == 1


def test_graph_from_dependency_graph(client):
    g = client.get("/api/graph/F-001", params={"run": RUN}).json()
    roles = {n["data"]["id"]: n["data"]["role"] for n in g["nodes"]}
    assert roles == {
        ".": "root",
        "node_modules/a": "path",
        "node_modules/b": "target",
        "node_modules/c": "context",
    }
    on_path = {e["data"]["id"] for e in g["edges"] if e["data"]["on_path"]}
    assert on_path == {".->node_modules/a", "node_modules/a->node_modules/b"}
    assert "node_modules/c->node_modules/b" in {e["data"]["id"] for e in g["edges"]}


def test_graph_from_recorded_image_path(client):
    g = client.get("/api/graph/F-002", params={"run": RUN}).json()
    assert g["source"] == "recorded path"
    assert [n["data"]["role"] for n in g["nodes"]] == ["root", "target"]


@pytest.mark.parametrize(
    "path",
    ["/api/findings", "/api/summary", "/api/checklist", "/api/findings/F-001", "/api/graph/F-001"],
)
def test_unknown_run_is_404(client, path):
    assert client.get(path, params={"run": "../../etc"}).status_code == 404


def test_unknown_finding_is_404(client):
    assert client.get("/api/findings/F-999", params={"run": RUN}).status_code == 404


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_only_reads_are_allowed(client, method):
    assert getattr(client, method)("/api/runs").status_code == 405


def test_security_headers_and_ui(client):
    r = client.get("/")
    assert r.status_code == 200 and "id=root" in r.text
    csp = r.headers["content-security-policy"]
    assert (
        "script-src 'self'" in csp
        and "object-src 'none'" in csp
        and "frame-ancestors 'none'" in csp
    )
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/../../guardian.db").status_code == 404
    assert "access-control-allow-origin" not in client.get("/api/runs").headers


def test_store_connection_is_read_only(client):
    from guardian.store import connect_readonly

    conn = connect_readonly(DB)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM runs")
    conn.close()


def test_cli_refuses_non_loopback_host(capsys):
    assert api_main(["--host", "0.0.0.0"]) == 2  # noqa: S104 - asserting it is refused
    assert "loopback" in capsys.readouterr().err
