"""Container image and CI/CD posture: guardian rules, tool parsers, merging, image findings.

Fixture files go in runs/pytest-posture, inside the workspace, because evidence paths must
be workspace-relative and the verifier path-jails them.
"""

import json
import shutil

import pytest

from guardian.scan import posture
from guardian.scan.common import EvidenceStore, assemble
from guardian.scan.feeds import EpssFeed, KevFeed
from guardian.scan.posture import (
    config_drafts,
    dockerfile_rules,
    eosl_hit,
    image_component,
    image_drafts,
    parse_from_lines,
    parse_hadolint,
    parse_trivy_config,
    parse_zizmor,
    workflow_rules,
)
from guardian.scan.verify import verify
from guardian.schemas import Ecosystem, FindingType, Severity
from guardian.schemas.graph import DependencyGraph
from guardian.schemas.sbom import Component, SbomComponent
from guardian.tools.runner import WORKSPACE

FIX = WORKSPACE / "runs" / "pytest-posture"
REL = "runs/pytest-posture"
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64

DOCKERFILE = f"""FROM node:latest AS build
RUN echo build
FROM build
FROM python
FROM alpine@{DIGEST}
RUN echo final
"""
WORKFLOW = f"""name: ci
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@{SHA}
      - uses: ./local-action
      - uses: docker://alpine:3
      # - uses: evil/action@v1
"""
EMPTY_GRAPH = DependencyGraph(root=".", nodes=(SbomComponent(bom_ref=".",
                              component=Component(name="app")),))  # fmt: skip
NO_FEEDS = (EpssFeed(None, None, {}), KevFeed(None, None, {}))


@pytest.fixture(scope="module")
def files():
    shutil.rmtree(FIX, ignore_errors=True)
    (FIX / ".github" / "workflows").mkdir(parents=True)
    (FIX / "Dockerfile").write_text(DOCKERFILE)
    (FIX / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    yield FIX
    shutil.rmtree(FIX, ignore_errors=True)


def rules_of(hits):
    return sorted((h.rule, h.line) for h in hits)


# --- guardian rules ------------------------------------------------------------------------


def test_dockerfile_rules(files):
    hits = dockerfile_rules(files / "Dockerfile")
    assert rules_of(hits) == [
        ("GR-IMG-001", 1), ("GR-IMG-001", 4),  # not digest-pinned; 'FROM build' is a stage ref
        ("GR-IMG-002", 1), ("GR-IMG-002", 4),  # latest tag / no tag
        ("GR-IMG-003", 5),  # final stage has no USER
    ]  # fmt: skip
    assert all(h.file == f"{REL}/Dockerfile" for h in hits)
    assert next(h for h in hits if h.line == 4).line_text == "FROM python"


@pytest.mark.parametrize(("user", "flagged"), [("USER app", False), ("USER root", True),
                                                ("USER 0", True)])  # fmt: skip
def test_root_user_rule(files, user, flagged):
    path = files / f"Dockerfile.{user.split()[1]}"
    path.write_text(f"FROM alpine@{DIGEST}\n{user}\n")
    hits = dockerfile_rules(path)
    assert ("GR-IMG-003" in {h.rule for h in hits}) is flagged
    if flagged:
        assert next(h for h in hits if h.rule == "GR-IMG-003").line == 2


def test_from_line_parsing(files):
    froms = parse_from_lines(files / "Dockerfile")
    assert [(f.line, f.ref, f.alias, f.tag, f.digest_pinned) for f in froms] == [
        (1, "node:latest", "build", "latest", False),
        (3, "build", None, None, False),
        (4, "python", None, None, False),
        (5, f"alpine@{DIGEST}", None, None, True),
    ]


def test_workflow_rules(files):
    hits = workflow_rules(files / ".github" / "workflows" / "ci.yml")
    assert rules_of(hits) == [("GR-CI-001", 8), ("GR-CI-002", 3), ("GR-CI-003", 11)]
    # SHA-pinned, local and commented-out actions are not flagged


@pytest.mark.parametrize(
    ("ref", "name", "version", "purl"),
    [
        ("node:12-alpine", "node", "12-alpine", "pkg:docker/library/node@12-alpine"),
        (
            "ghcr.io/org/img:1.0@" + DIGEST,
            "ghcr.io/org/img",
            "1.0",
            "pkg:docker/ghcr.io/org/img@1.0",
        ),
        ("localhost:5000/x", "localhost:5000/x", None, "pkg:docker/localhost:5000/x"),
    ],
)
def test_image_component(ref, name, version, purl):
    c = image_component(ref)
    assert (c.name, c.version, c.purl, c.ecosystem) == (name, version, purl, Ecosystem.OCI)


# --- tool parsers --------------------------------------------------------------------------


def write(name, data):
    path = FIX / name
    path.write_text(json.dumps(data))
    return path


def test_tool_parsers(files):
    hadolint = write(
        "hadolint.json",
        [
            {
                "code": "DL3007",
                "level": "warning",
                "line": 1,
                "file": str(files / "Dockerfile"),
                "message": "latest",
            }
        ],
    )
    (h,) = parse_hadolint(hadolint)
    assert (h.rule, h.severity, h.line, h.file, h.pointer) == (
        "DL3007", Severity.MEDIUM, 1, f"{REL}/Dockerfile", "/0")  # fmt: skip

    trivy = write("trivy-config.json", {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
        {"ID": "DS-0026", "Title": "No HEALTHCHECK", "Severity": "LOW"}]}]})  # fmt: skip
    (t,) = parse_trivy_config(trivy, files)
    assert (t.rule, t.severity, t.line, t.file) == ("DS-0026", Severity.LOW, None,
                                                    f"{REL}/Dockerfile")  # fmt: skip

    zizmor = write("zizmor.json", [zizmor_finding("unpinned-uses", "High", 8)])
    (z,) = parse_zizmor(zizmor)
    assert (z.rule, z.severity, z.line, z.file, z.concern) == (
        "unpinned-uses", Severity.HIGH, 8, f"{REL}/.github/workflows/ci.yml",
        "action-not-sha-pinned")  # fmt: skip


def zizmor_finding(ident, severity, line):
    path = str(FIX / ".github" / "workflows" / "ci.yml")
    return {
        "ident": ident, "desc": f"{ident} desc", "ignored": False,
        "determinations": {"severity": severity, "confidence": "High"},
        "locations": [
            {"symbolic": {"key": {"Local": {"verbatim_path": path}}, "kind": "Hidden"},
             "concrete": {"location": {"start_point": {"row": line - 2, "column": 0}}}},
            {"symbolic": {"key": {"Local": {"verbatim_path": path}}, "kind": "Primary"},
             "concrete": {"location": {"start_point": {"row": line - 1, "column": 0}}}},
        ],
    }  # fmt: skip


# --- merged CI/Dockerfile findings and their verification ------------------------------------


@pytest.fixture(scope="module")
def config_set(files):
    write("zizmor.json", [zizmor_finding("unpinned-uses", "High", 8),
                          zizmor_finding("excessive-permissions", "Medium", 5)])  # fmt: skip
    hits = [*dockerfile_rules(files / "Dockerfile"),
            *workflow_rules(files / ".github" / "workflows" / "ci.yml"),
            *parse_zizmor(FIX / "zizmor.json")]  # fmt: skip
    outputs = {"zizmor": f"{REL}/zizmor.json"}
    store = EvidenceStore()
    fs = assemble(store, config_drafts(store, hits, outputs, {"zizmor": "zizmor 1.32.0"}))
    return fs, outputs


def test_tool_and_rule_merge_into_one_finding(config_set):
    fs, _ = config_set
    checkout = [f for f in fs.findings if f.component.name == "actions/checkout"]
    assert len(checkout) == 1
    f = checkout[0]
    assert f.type is FindingType.UNPINNED_CI
    assert f.advisory_ids == ("GR-CI-001", "unpinned-uses")
    assert {e.tool for e in f.evidence} == {"guardian-rules", "zizmor"}
    assert (f.component.version, f.component.purl) == ("v4", "pkg:github/actions/checkout@v4")
    # One finding per (file, line, concern): Dockerfile lines 1 and 4 each have 001 and 002.
    image = [f for f in fs.findings if f.type is FindingType.UNTRUSTED_IMAGE]
    assert len(image) == 4
    assert {f.type for f in fs.findings if "GR-IMG-003" in f.advisory_ids} == {
        FindingType.MISCONFIGURATION}  # fmt: skip


def test_config_findings_verify(config_set):
    fs, outputs = config_set
    v = verify(fs, EMPTY_GRAPH, outputs)
    assert v.failures == [] and v.checked > 10


def test_verifier_catches_edited_rule_evidence(config_set):
    fs, outputs = config_set
    rec = next(r for r in fs.evidence if r.ref == "GR-CI-001")
    moved = rec.model_copy(update={"line": rec.line + 1})
    bad = fs.model_copy(update={"evidence": tuple(moved if r.id == rec.id else r
                                                  for r in fs.evidence)})  # fmt: skip
    v = verify(bad, EMPTY_GRAPH, outputs)
    assert any("text differs" in f for f in v.failures)

    f = next(x for x in fs.findings if x.component.name == "actions/checkout")
    invented = f.model_copy(update={"advisory_ids": (*f.advisory_ids, "GR-CI-999")})
    bad = fs.model_copy(update={"findings": tuple(invented if x.id == f.id else x
                                                  for x in fs.findings)})  # fmt: skip
    v = verify(bad, EMPTY_GRAPH, outputs)
    assert any("GR-CI-999" in f for f in v.failures)


# --- image findings ------------------------------------------------------------------------


@pytest.fixture(scope="module")
def image_set(files):
    layout = FIX / "oci"
    layout.mkdir(exist_ok=True)
    (layout / "index.json").write_text(json.dumps({"manifests": [{"digest": DIGEST}]}))
    write("trivy-image.json", {
        "Metadata": {"OS": {"Family": "alpine", "Name": "3.15.4", "EOSL": True}},
        "Results": [{"Target": "img", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2022-1", "PkgName": "zlib", "InstalledVersion": "1.2.12-r0",
             "FixedVersion": "1.2.12-r2", "Severity": "CRITICAL", "Title": "zlib bug",
             "PkgIdentifier": {"PURL": "pkg:apk/alpine/zlib@1.2.12-r0"},
             "CVSS": {"nvd": {"V3Score": 9.8}}}]}],
    })  # fmt: skip
    write("grype-image.json", {"matches": [
        {"vulnerability": {"id": "CVE-2022-1", "severity": "Critical", "cvss": [],
                           "fix": {"versions": ["1.2.12-r2"], "state": "fixed"}},
         "relatedVulnerabilities": [], "matchDetails": [{"type": "exact-direct-match"}],
         "artifact": {"name": "zlib", "version": "1.2.12-r0",
                      "purl": "pkg:apk/alpine/zlib@1.2.12-r0"}},
        {"vulnerability": {"id": "CVE-2023-2", "severity": "High", "cvss": []},
         "relatedVulnerabilities": [], "matchDetails": [{"type": "cpe-match"}],
         "artifact": {"name": "node", "version": "12.22.12"}},
    ]})  # fmt: skip
    image = {"image": "docker.io/library/node:12-alpine", "platform": "linux/amd64",
             "manifest_digest": DIGEST, "oci_layout": f"{REL}/oci"}  # fmt: skip
    outputs = {"trivy-image": f"{REL}/trivy-image.json", "grype-image": f"{REL}/grype-image.json"}
    from_line = parse_from_lines(files / "Dockerfile")[-1]
    store = EvidenceStore()
    drafts, stats = image_drafts(store, image, from_line, f"{REL}/Dockerfile", outputs,
                                 {"trivy": "t", "grype": "g"}, *NO_FEEDS)  # fmt: skip
    eosl = eosl_hit(outputs, f"{REL}/Dockerfile", from_line)
    drafts += config_drafts(store, [eosl], outputs, {"trivy": "t"})
    return assemble(store, drafts), outputs, stats


def test_image_findings(image_set):
    fs, _, stats = image_set
    assert stats["grype_cpe_only_excluded"] == 1  # the CPE-only node match is not a finding
    assert stats["groups_by_tool_count"] == {"2_tools": 1}
    zlib = next(f for f in fs.findings if f.type is FindingType.VULNERABLE_IMAGE_PACKAGE)
    assert zlib.component.ecosystem is Ecosystem.APK
    assert zlib.dependency_path == (f"docker.io/library/node:12-alpine@{DIGEST}",
                                    "zlib@1.2.12-r0")  # fmt: skip
    assert zlib.introduced_by == (zlib.dependency_path[0],)
    eosl = next(f for f in fs.findings if f.advisory_ids == ("EOSL",))
    assert eosl.type is FindingType.UNTRUSTED_IMAGE
    assert "alpine 3.15.4" in eosl.title


def test_image_findings_verify_and_catch_wrong_digest(image_set):
    fs, outputs, _ = image_set
    assert verify(fs, EMPTY_GRAPH, outputs).failures == []
    zlib = next(f for f in fs.findings if f.type is FindingType.VULNERABLE_IMAGE_PACKAGE)
    wrong = zlib.model_copy(
        update={
            "dependency_path": (
                "docker.io/library/node:12-alpine@sha256:" + "c" * 64,
                "zlib@1.2.12-r0",
            )
        }
    )
    bad = fs.model_copy(update={"findings": tuple(wrong if x.id == zlib.id else x
                                                  for x in fs.findings)})  # fmt: skip
    assert any("image path" in f for f in verify(bad, EMPTY_GRAPH, outputs).failures)


def test_no_eosl_hit_when_trivy_does_not_flag(files):
    write(
        "trivy-ok.json", {"Metadata": {"OS": {"Family": "alpine", "Name": "3.20", "EOSL": False}}}
    )
    from_line = parse_from_lines(files / "Dockerfile")[-1]
    assert eosl_hit({"trivy-image": f"{REL}/trivy-ok.json"}, "x", from_line) is None


def test_load_image_normalizes_docker_hub_names(tmp_path, monkeypatch):
    images = tmp_path / "images.json"
    images.write_text(json.dumps({"images": [{"image": "docker.io/library/node:12-alpine"},
                                             {"image": "docker.io/org/app:1"}]}))  # fmt: skip
    monkeypatch.setattr(posture, "IMAGES_FILE", images)
    assert posture.load_image("node:12-alpine")["image"] == "docker.io/library/node:12-alpine"
    assert posture.load_image("org/app:1")["image"] == "docker.io/org/app:1"
    assert posture.load_image("ghcr.io/x/y:1") is None


@pytest.mark.parametrize(("text", "expected"), [
    ("summary", "runs/x.json#/matches/0 :: summary"),
    (None, "runs/x.json#/matches/0"),
    ("   ", "runs/x.json#/matches/0"),
])  # fmt: skip
def test_pointer_excerpt_without_summary_stays_parseable(text, expected):
    from guardian.scan.common import pointer_excerpt
    from guardian.scan.verify import POINTER_RE

    out = pointer_excerpt("runs/x.json", "/matches/0", text)
    assert out == expected
    assert POINTER_RE.match(out).groups() == ("runs/x.json", "/matches/0")
