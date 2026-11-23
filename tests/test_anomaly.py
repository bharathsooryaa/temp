"""Anomaly rules (typosquat, install script, lockfile, unexpected dependency) and evaluation.

Fixture files go in runs/pytest-anomaly, inside the workspace, because evidence paths are
workspace-relative and the verifier path-jails them.
"""

import json
import shutil
from datetime import UTC, datetime, timedelta

import pytest

from guardian.sbom.npm_lock import build_graph, parse_lockfile
from guardian.scan.anomaly import (
    TopList,
    anomaly_drafts,
    classify,
    diff_rules,
    entry_field_line,
    keyboard_adjacent,
    max_distance,
    osa_distance,
    single_commit_rules,
    typosquat_matches,
)
from guardian.scan.common import EvidenceStore, assemble
from guardian.scan.evaluate import seeded_changes
from guardian.scan.verify import verify
from guardian.schemas import FindingType, Severity
from guardian.tools.runner import WORKSPACE

FIX = WORKSPACE / "runs" / "pytest-anomaly"
REL = "runs/pytest-anomaly"
REG = "https://registry.npmjs.org"
RECENT = (datetime.now(UTC) - timedelta(days=5)).strftime("%Y-%m-%dT00:00:00Z")


def entry(name, version, **extra):
    base = name.rsplit("/", 1)[-1]
    return {"version": version, "resolved": f"{REG}/{name}/-/{base}-{version}.tgz",
            "integrity": f"sha512-{name}{version}", **extra}  # fmt: skip


BASE = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"express": "4", "helper": "1"}},
    "node_modules/express": entry("express", "4.16.4", dependencies={"ms": "2", "inst": "1"}),
    "node_modules/helper": entry("helper", "1.0.0"),
    "node_modules/inst": entry("inst", "1.0.0", hasInstallScript=True),
    "node_modules/ms": entry("ms", "2.0.0"),
}}  # fmt: skip
TARGET = json.loads(json.dumps(BASE))
TP = TARGET["packages"]
TP[""]["dependencies"].update({"expresss": "4.16.4", "seedpost": "1.0.0"})
TP["node_modules/express"]["resolved"] = (
    f"{REG.replace('.org', '.co')}/express/-/express-4.16.4.tgz"
)
TP["node_modules/express"]["dependencies"]["sneaky"] = "1"  # added with no express version change
TP["node_modules/expresss"] = {
    "version": "4.16.4",
    "integrity": "sha512-x",
    "resolved": "http://127.0.0.1:4873/expresss/-/expresss-4.16.4.tgz",
}
TP["node_modules/helper"] = entry("helper", "1.1.0", dependencies={"newdep": "1"})  # minor bump
TP["node_modules/ms"]["integrity"] = "sha512-TAMPERED"
TP["node_modules/newdep"] = entry("newdep", "1.0.0")
TP["node_modules/seedpost"] = {
    "version": "1.0.0",
    "integrity": "sha512-s",
    "hasInstallScript": True,
    "resolved": "http://127.0.0.1:4873/seedpost/-/seedpost-1.0.0.tgz",
}
TP["node_modules/sneaky"] = entry("sneaky", "1.0.0")
TOP = ["express", "lodash", "helper", "debug", "chalk"]


@pytest.fixture(scope="module")
def fx():
    shutil.rmtree(FIX, ignore_errors=True)
    (FIX / "base").mkdir(parents=True)
    (FIX / "target").mkdir()
    (FIX / "base" / "package-lock.json").write_text(json.dumps(BASE, indent=2) + "\n")
    (FIX / "target" / "package-lock.json").write_text(json.dumps(TARGET, indent=2) + "\n")
    (FIX / "top.json").write_text(json.dumps({"names": TOP}))
    (FIX / "seedpost.json").write_text(
        json.dumps(
            {
                "name": "seedpost",
                "scripts": {"postinstall": "echo MARKER && curl -s http://127.0.0.1:9/x || true"},
            },
            indent=2,
        )
    )
    (FIX / "registry.json").write_text(json.dumps({"packages": {
        "expresss": {"created": RECENT, "weekly_downloads": 5},
        "seedpost": {"created": RECENT, "weekly_downloads": 1,
                     "manifests": {"1.0.0": f"{REL}/seedpost.json"}},
    }}))  # fmt: skip
    base = parse_lockfile(FIX / "base" / "package-lock.json", f"{REL}/base/package-lock.json")
    lock = parse_lockfile(FIX / "target" / "package-lock.json", f"{REL}/target/package-lock.json")
    graph, _ = build_graph(lock)
    top = TopList.load(FIX / "top.json")
    hits = single_commit_rules(lock, top, FIX / "registry.json") + diff_rules(base, lock, graph)
    store = EvidenceStore()
    fs = assemble(store, anomaly_drafts(store, hits, graph))
    yield {"hits": hits, "graph": graph, "fs": fs, "top": top, "lock": lock}
    shutil.rmtree(FIX, ignore_errors=True)


def rules_by_package(hits):
    out = {}
    for h in hits:
        out.setdefault(h.node.rsplit("node_modules/", 1)[-1], set()).add(h.rule)
    return out


# --- distance helpers ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "d"),
    [("express", "express", 0), ("expresss", "express", 1), ("exrpess", "express", 1),
     ("lodahs", "lodash", 1), ("lpdahs", "lodash", 2), ("", "abc", 3), ("ab", "ba", 1)],
)  # fmt: skip
def test_osa_distance(a, b, d):
    assert osa_distance(a, b) == d


@pytest.mark.parametrize(
    ("candidate", "popular", "kind"),
    [("expresss", "express", "insertion"), ("expres", "express", "deletion"),
     ("lodahs", "lodash", "transposition"), ("lodaah", "lodash", "keyboard-adjacent substitution"),
     ("lodazh", "lodash", "keyboard-adjacent substitution"), ("lodpsh", "lodash", "substitution"),
     ("body_parser", "body-parser", "separator change"), ("lpdahs", "lodash", "multiple edits")],
)  # fmt: skip
def test_classify(candidate, popular, kind):
    assert classify(candidate, popular) == kind


def test_keyboard_adjacency_and_thresholds():
    assert keyboard_adjacent("s", "a") and keyboard_adjacent("s", "z")
    assert not keyboard_adjacent("s", "p") and not keyboard_adjacent("s", "s")
    assert (max_distance("lodash"), max_distance("express")) == (1, 2)


def test_typosquat_matches_skip_popular_and_short(fx):
    top = fx["top"]
    m = typosquat_matches({"expresss", "express", "lodahs", "dbg", "unrelated-name"}, top)
    assert m == {"expresss": ("express", 1, 1), "lodahs": ("lodash", 2, 1)}


def test_entry_field_line(fx):
    lines = (FIX / "target" / "package-lock.json").read_text().splitlines()
    key = fx["lock"].entries["node_modules/seedpost"].line
    n = entry_field_line(lines, key, "hasInstallScript")
    assert lines[n - 1].strip() == '"hasInstallScript": true,'
    assert entry_field_line(lines, key, "nope") is None


# --- rules -------------------------------------------------------------------------------------


def test_rule_coverage(fx):
    by_pkg = rules_by_package(fx["hits"])
    assert by_pkg["expresss"] == {"GR-TYPO-001", "GR-LOCK-001"}
    assert by_pkg["seedpost"] == {"GR-INST-002", "GR-LOCK-001"}
    assert by_pkg["inst"] == {"GR-INST-001"}  # no manifest available -> not inspected
    assert by_pkg["express"] == {"GR-LOCK-001", "GR-LOCK-005"}  # lookalike host, same version
    assert by_pkg["ms"] == {"GR-LOCK-004"}  # integrity changed, version unchanged
    assert by_pkg["newdep"] == {"GR-DEP-001"}  # from helper 1.0.0 -> 1.1.0
    assert by_pkg["sneaky"] == {"GR-DEP-002"}  # no direct dependency changed version
    assert "helper" not in by_pkg  # popular, and the bump itself is in the manifest diff


def test_typosquat_severity_uses_registry_metadata(fx):
    typo = next(h for h in fx["hits"] if h.rule == "GR-TYPO-001")
    assert typo.severity is Severity.HIGH  # 1 edit, created 5 days ago, 5 weekly downloads
    assert {c.tool for c in typo.cites} == {"guardian-rules", "npm-high-impact", "mock-registry"}


def test_findings_grouped_per_package_and_type(fx):
    fs = fx["fs"]
    express = [f for f in fs.findings if f.component.name == "express"]
    assert len(express) == 1 and express[0].advisory_ids == ("GR-LOCK-001", "GR-LOCK-005")
    assert express[0].type is FindingType.LOCKFILE_CHANGE
    seedpost = {f.type for f in fs.findings if f.component.name == "seedpost"}
    assert seedpost == {FindingType.INSTALL_SCRIPT, FindingType.LOCKFILE_CHANGE}
    newdep = next(f for f in fs.findings if f.component.name == "newdep")
    assert newdep.dependency_path == ("app@1.0.0", "helper@1.1.0", "newdep@1.0.0")
    assert newdep.introduced_by == ("helper@1.1.0",)


# --- verification ----------------------------------------------------------------------------


def test_anomaly_findings_verify(fx):
    v = verify(fx["fs"], fx["graph"], {})
    assert v.failures == [] and v.checked > 30


def _swap_evidence(fs, predicate, **update):
    rec = next(r for r in fs.evidence if predicate(r))
    new = rec.model_copy(update=update)
    return fs.model_copy(update={"evidence": tuple(new if r.id == rec.id else r
                                                   for r in fs.evidence)})  # fmt: skip


def test_verifier_catches_wrong_rank_and_registry_facts(fx):
    fs = fx["fs"]
    bad = _swap_evidence(fs, lambda r: r.tool == "npm-high-impact",
                         excerpt="rank=2 name=express; 'expresss' not in list; distance=1 "
                                 "(insertion)")  # fmt: skip
    assert any("not rank 2" in f for f in verify(bad, fx["graph"], {}).failures)
    bad = _swap_evidence(fs, lambda r: r.tool == "mock-registry" and r.ref == "expresss",
                         excerpt=f"created={RECENT}; weekly_downloads=999999")  # fmt: skip
    assert any("registry metadata" in f for f in verify(bad, fx["graph"], {}).failures)
    bad = _swap_evidence(fs, lambda r: r.ref == "GR-LOCK-004" and "TAMPERED" in (r.excerpt or ""),
                         excerpt='"integrity": "sha512-ms2.0.0",')  # fmt: skip
    assert any("text differs" in f for f in verify(bad, fx["graph"], {}).failures)


# --- evaluation helper -----------------------------------------------------------------------


def test_seeded_changes_lines(fx):
    changes = seeded_changes(f"{REL}/base", f"{REL}/target")
    lock_changes = changes[f"{REL}/target/package-lock.json"]
    lines = (FIX / "target" / "package-lock.json").read_text().splitlines()
    ms_integrity = entry_field_line(lines, fx["lock"].entries["node_modules/ms"].line, "integrity")
    assert ms_integrity in lock_changes
    assert fx["lock"].entries["node_modules/helper"].line not in lock_changes  # key line unchanged
