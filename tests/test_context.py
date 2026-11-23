"""Risk context (reachability, exposure, provenance) and risk score v1 enrichment.

Fixture files go in runs/pytest-context, inside the workspace, because evidence paths are
workspace-relative and the verifier path-jails them.
"""

import json
import shutil

import pytest

from guardian.sbom.npm_lock import parse_lockfile
from guardian.scan.common import EvidenceStore, assemble
from guardian.scan.context import (
    PROVENANCE_POINTS,
    enrich,
    entry_key_above,
    expected_provenance,
    file_role,
    package_of,
    resolve_top_level,
    scan_app,
)
from guardian.scan.verify import Verification, _check_risk, _Files
from guardian.schemas import Ecosystem, EvidenceKind, Exposure, FindingType, Reachability
from guardian.schemas.risk import RiskFactors
from guardian.schemas.sbom import Component
from guardian.scoring import score_risk
from guardian.tools.runner import WORKSPACE

FIX = WORKSPACE / "runs" / "pytest-context"
REL = "runs/pytest-context/app"

SERVER = """const express = require('express');
import lodash from 'lodash';
// const ignored = require('commented-out');
const conf = require(path.resolve(__dirname + '/conf.js'));
const fs = require('fs');
app.listen(3000);
"""
LOCK = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"express": "4", "foo": "1"}},
    "node_modules/express": {"version": "4.0.0"},
    "node_modules/foo": {"version": "1.0.0", "dependencies": {"express": "3"}},
    "node_modules/foo/node_modules/express": {"version": "3.0.0"},
}}  # fmt: skip


@pytest.fixture(scope="module")
def app():
    shutil.rmtree(FIX, ignore_errors=True)
    root = FIX / "app"
    for sub in ("test", "app/assets"):
        (root / sub).mkdir(parents=True)
    (root / "server.js").write_text(SERVER)
    (root / "test" / "t.js").write_text("const mocha = require('mocha');\n")
    (root / "app" / "assets" / "x.js").write_text("const $ = require('jquery');\n")
    (root / "Dockerfile").write_text("FROM node:20\nEXPOSE 8080\n")
    (root / "package-lock.json").write_text(json.dumps(LOCK, indent=2) + "\n")
    ctx = scan_app(root, root / "Dockerfile")
    lock = parse_lockfile(root / "package-lock.json", f"{REL}/package-lock.json")
    resolve_top_level(ctx, lock)
    yield ctx
    shutil.rmtree(FIX, ignore_errors=True)


@pytest.mark.parametrize(
    ("spec", "pkg"),
    [("express", "express"), ("lodash/fp", "lodash"), ("@scope/pkg/sub", "@scope/pkg"),
     ("./local", None), ("/abs", None), ("fs", None), ("node:fs", None)],
)  # fmt: skip
def test_package_of(spec, pkg):
    assert package_of(spec) == pkg


@pytest.mark.parametrize(
    ("path", "role"),
    [("server.js", "runtime"), ("app/routes/x.js", "runtime"), ("app/assets/vendor/x.js", "client"),
     ("test/a.js", "dev"), ("Gruntfile.js", "dev"), ("src/a.test.js", "dev")],
)  # fmt: skip
def test_file_role(path, role):
    from pathlib import Path

    assert file_role(Path(path)) == role


def test_scan_app(app):
    assert set(app.runtime_imports) == {"express", "lodash"}  # commented, builtin, local skipped
    assert set(app.dev_imports) == {"mocha"}  # client asset import ignored
    assert app.dynamic_requires == 1
    assert [(s.file.rsplit("/", 1)[-1], s.line) for s in app.network_facts] == [
        ("server.js", 6), ("Dockerfile", 2)]  # fmt: skip
    assert app.runtime_imports["express"].text == "const express = require('express');"
    assert app.top_level["express"][0] == "4.0.0"  # bare require resolves to node_modules/express
    assert app.top_level["lodash"] == (None, None)  # imported but not in the lockfile


def test_entry_key_above(app):
    lines = (FIX / "app" / "package-lock.json").read_text().splitlines()
    n = app.top_level["express"][1].line
    assert entry_key_above(lines, n) == "node_modules/express"


def test_expected_provenance_table():
    npm = Ecosystem.NPM
    assert expected_provenance(FindingType.VULNERABLE_DIRECT, npm, True, set()) == 100.0
    assert expected_provenance(FindingType.VULNERABLE_DIRECT, npm, False, set()) == 0.0
    assert expected_provenance(FindingType.VULNERABLE_DIRECT, npm, False,
                               {"GR-TYPO-001", "GR-INST-001"}) == 60.0  # fmt: skip
    assert expected_provenance(FindingType.VULNERABLE_IMAGE_PACKAGE, Ecosystem.APK, False,
                               set()) is None  # fmt: skip
    assert expected_provenance(FindingType.UNPINNED_CI, Ecosystem.GITHUB_ACTIONS, False,
                               {"GR-CI-001"}) == PROVENANCE_POINTS["GR-CI-001"]  # fmt: skip


# --- enrichment ----------------------------------------------------------------------------


def comp(name, version, eco=Ecosystem.NPM):
    return Component(name=name, version=version, ecosystem=eco)


def draft(store, ftype, component, factors=None, rules=()):
    refs = []
    for rule in rules:  # cite a real line of the fixture so the evidence is valid
        rec = store.add(("t", rule, component.name), kind=EvidenceKind.FILE_LOCATION,
                        tool="guardian-rules", ref=rule, file=f"{REL}/server.js", line=1,
                        excerpt="const express = require('express');")  # fmt: skip
        from guardian.scan.common import ref_of

        refs.append(ref_of(rec))
    if not refs:
        rec = store.add(("g", component.name, component.version), kind=EvidenceKind.ADVISORY,
                        tool="test", ref=f"T-{component.name}")  # fmt: skip
        from guardian.scan.common import ref_of

        refs.append(ref_of(rec))
    d = {"type": ftype, "title": f"{component.name}: t", "component": component,
         "evidence": tuple(refs)}  # fmt: skip
    label = f"{component.name}@{component.version}"
    if ftype is FindingType.VULNERABLE_DIRECT:
        d["dependency_path"] = ("app@1.0.0", label)
    elif ftype is FindingType.VULNERABLE_TRANSITIVE:
        d["dependency_path"] = ("app@1.0.0", "foo@1.0.0", label)
    if factors is not None:
        d["factors"] = factors
    return ((False, False, 0, 0, component.name, ""), d)


@pytest.fixture(scope="module")
def enriched(app):
    store = EvidenceStore()
    drafts = [
        draft(store, FindingType.VULNERABLE_DIRECT, comp("express", "4.0.0"),
              RiskFactors(cvss=9.8, epss=0.5, kev=False)),
        draft(store, FindingType.VULNERABLE_TRANSITIVE, comp("express", "3.0.0"),
              RiskFactors(cvss=9.8)),  # nested copy: imported name, wrong version
        draft(store, FindingType.VULNERABLE_TRANSITIVE, comp("devpkg", "1.0.0"),
              RiskFactors(cvss=5.0, exposure=Exposure.BUILD_OR_DEV)),
        draft(store, FindingType.MALICIOUS_PACKAGE, comp("evil", "1.0.0"),
              RiskFactors(confirmed_malicious=True)),
        draft(store, FindingType.TYPOSQUAT, comp("expresss", "1.0.0"), rules=("GR-TYPO-001",)),
        draft(store, FindingType.VULNERABLE_TRANSITIVE, comp("expresss", "1.0.0"),
              RiskFactors(cvss=7.0)),  # shares the typosquat's rule citation
        draft(store, FindingType.UNPINNED_CI, comp("actions/checkout", "v2",
              Ecosystem.GITHUB_ACTIONS), rules=("GR-CI-001",)),
        draft(store, FindingType.VULNERABLE_IMAGE_PACKAGE, comp("zlib", "1.2", Ecosystem.APK),
              RiskFactors(cvss=9.8)),
    ]  # fmt: skip
    fs = assemble(store, enrich(store, drafts, app))
    return fs, {(f.type, f.component.name, f.component.version): f for f in fs.findings}


def test_imported_copy_is_network_facing(enriched):
    _, by = enriched
    f = by[(FindingType.VULNERABLE_DIRECT, "express", "4.0.0")].factors
    assert (f.reachability, f.exposure, f.provenance) == (
        Reachability.IMPORTED, Exposure.RUNTIME_NETWORK, 0.0)  # fmt: skip
    rules = {e.ref for e in by[(FindingType.VULNERABLE_DIRECT, "express", "4.0.0")].evidence}
    assert {"GR-REACH-001", "GR-REACH-002", "GR-EXPO-001"} <= rules


def test_nested_copy_is_not_imported(enriched):
    _, by = enriched
    f = by[(FindingType.VULNERABLE_TRANSITIVE, "express", "3.0.0")].factors
    assert (f.reachability, f.exposure) == (Reachability.PRESENT_ONLY, Exposure.RUNTIME_INTERNAL)


def test_dev_malicious_ci_and_image(enriched):
    _, by = enriched
    dev = by[(FindingType.VULNERABLE_TRANSITIVE, "devpkg", "1.0.0")].factors
    assert (dev.reachability, dev.exposure) == (Reachability.DEV_ONLY_UNUSED,
                                                Exposure.BUILD_OR_DEV)  # fmt: skip
    evil = by[(FindingType.MALICIOUS_PACKAGE, "evil", "1.0.0")]
    assert evil.factors.provenance == 100.0 and evil.risk.level.value == "Critical"
    ci = by[(FindingType.UNPINNED_CI, "actions/checkout", "v2")].factors
    assert (ci.exposure, ci.provenance) == (Exposure.BUILD_OR_DEV, 50.0)
    img = by[(FindingType.VULNERABLE_IMAGE_PACKAGE, "zlib", "1.2")].factors
    assert (img.reachability, img.exposure, img.provenance) == (
        Reachability.UNKNOWN, Exposure.RUNTIME_INTERNAL, None)  # fmt: skip


def test_anomaly_rule_raises_provenance_of_same_component(enriched):
    _, by = enriched
    vuln = by[(FindingType.VULNERABLE_TRANSITIVE, "expresss", "1.0.0")]
    assert vuln.factors.provenance == 60.0
    assert "GR-TYPO-001" in {e.ref for e in vuln.evidence}


def test_scores_match_formula_and_rank_order(enriched):
    fs, _ = enriched
    for f in fs.findings:
        assert f.risk == score_risk(f.factors)
    assert fs.findings[0].risk.override == "confirmed_malicious"
    scores = [f.risk.score if f.risk.score is not None else -1 for f in fs.findings[1:]]
    assert scores == sorted(scores, reverse=True)


# --- verifier risk checks --------------------------------------------------------------------


def check(f, fs):
    v = Verification()
    _check_risk(v, f, {r.id: r for r in fs.evidence}, _Files())
    return v


def test_verifier_accepts_enriched_findings(enriched):
    fs, _ = enriched
    for f in fs.findings:
        assert check(f, fs).failures == [], f.id


@pytest.mark.parametrize(
    ("key", "update", "message"),
    [
        ((FindingType.VULNERABLE_TRANSITIVE, "express", "3.0.0"),
         {"reachability": Reachability.IMPORTED}, "does not resolve"),
        ((FindingType.VULNERABLE_TRANSITIVE, "express", "3.0.0"),
         {"exposure": Exposure.RUNTIME_NETWORK}, "network exposure"),
        ((FindingType.VULNERABLE_DIRECT, "express", "4.0.0"),
         {"provenance": 0.0, "cvss": 1.0}, "risk does not match"),
        ((FindingType.VULNERABLE_DIRECT, "express", "4.0.0"),
         {"provenance": 90.0}, "provenance"),
    ],
)  # fmt: skip
def test_verifier_catches_tampered_factors(enriched, key, update, message):
    fs, by = enriched
    f = by[key]
    bad = f.model_copy(update={"factors": f.factors.model_copy(update=update)})
    assert any(message in x for x in check(bad, fs).failures)
