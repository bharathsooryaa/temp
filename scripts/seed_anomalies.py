"""Create the seeded-anomaly fork of NodeGoat (D1.S6). SYNTHETIC and INERT.

* Clones targets/nodegoat locally to targets/nodegoat-seeded, with Git hooks disabled, and
  commits the scenarios below on branch `seeded-anomalies`. Nothing is pushed or published.
* Nothing is installed or executed. The "mock registry" is metadata files under
  targets/mock-registry. Payloads are markers: the postinstall script only echoes a marker
  and calls a dead localhost port, and it never runs.
* Writes targets/seeded-ground-truth.json, registers the target in targets/targets.json, and
  makes the fork read-only.

Usage:  python3 -I scripts/seed_anomalies.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "targets" / "nodegoat"
FORK = ROOT / "targets" / "nodegoat-seeded"
REGISTRY = ROOT / "targets" / "mock-registry"
BRANCH = "seeded-anomalies"
MOCK = "http://127.0.0.1:4873"  # mock registry URL; nothing listens there and nothing fetches
GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=guardian-seed",
       "-c", "user.email=guardian-seed@localhost", "-c", "commit.gpgsign=false"]  # fmt: skip


def git(*args: str, cwd: Path = FORK) -> str:
    return subprocess.run([*GIT, *args], cwd=cwd, check=True, capture_output=True,  # noqa: S603
                          text=True).stdout.strip()  # fmt: skip


def fake_integrity(label: str) -> str:
    """Deterministic, obviously synthetic sha512 integrity (hash of a marker string)."""
    digest = hashlib.sha512(f"GUARDIAN-SYNTHETIC:{label}".encode()).digest()
    return "sha512-" + base64.b64encode(digest).decode()


def insert_sorted(packages: dict, key: str, value: dict) -> dict:
    """Insert a top-level node_modules/<name> key before the next top-level key in order."""
    out, placed = {}, False
    for k, v in packages.items():
        top_level = k.startswith("node_modules/") and "/node_modules/" not in k
        if not placed and top_level and k > key:
            out[key] = value
            placed = True
        out[k] = v
    if not placed:
        out[key] = value
    return out


def make_writable(path: Path) -> None:
    for p in [path, *path.rglob("*")]:
        if not p.is_symlink():
            p.chmod(p.stat().st_mode | stat.S_IWUSR)


def make_readonly(path: Path) -> None:
    for p in [path, *path.rglob("*")]:
        if not p.is_symlink():
            p.chmod(p.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def main() -> int:
    clean_commit = json.loads((ROOT / "targets" / "targets.json").read_text())["targets"][0]
    base_sha = clean_commit["commit"]
    if FORK.exists():
        make_writable(FORK)
        shutil.rmtree(FORK)
    git("clone", "--quiet", "--no-hardlinks", str(CLEAN), str(FORK), cwd=ROOT)
    git("checkout", "--quiet", "-b", BRANCH, base_sha)
    git("remote", "remove", "origin")  # no path back to anything, so nothing can be pushed

    pkg_path, lock_path = FORK / "package.json", FORK / "package-lock.json"
    pkg = json.loads(pkg_path.read_text())
    lock = json.loads(lock_path.read_text())
    packages = lock["packages"]
    root = packages[""]

    # S3 typosquat: 'expresss' (one extra 's'), served by the mock registry.
    pkg["dependencies"]["expresss"] = "4.16.4"
    root["dependencies"]["expresss"] = "4.16.4"
    packages = insert_sorted(packages, "node_modules/expresss", {
        "version": "4.16.4", "resolved": f"{MOCK}/expresss/-/expresss-4.16.4.tgz",
        "integrity": fake_integrity("expresss@4.16.4"),
    })  # fmt: skip

    # S4 suspicious install script: an inert postinstall in a local test package.
    pkg["dependencies"]["guardian-seed-postinstall"] = "1.0.0"
    root["dependencies"]["guardian-seed-postinstall"] = "1.0.0"
    packages = insert_sorted(packages, "node_modules/guardian-seed-postinstall", {
        "version": "1.0.0",
        "resolved": f"{MOCK}/guardian-seed-postinstall/-/guardian-seed-postinstall-1.0.0.tgz",
        "integrity": fake_integrity("guardian-seed-postinstall@1.0.0"),
        "hasInstallScript": True,
    })  # fmt: skip

    # S5 modified lockfile: (a) lookalike registry host for marked; (b) ms integrity changed
    # with no version change.
    packages["node_modules/marked"]["resolved"] = (
        "https://registry.npmjs.co/marked/-/marked-0.3.5.tgz"
    )
    packages["node_modules/ms"]["integrity"] = fake_integrity("ms@2.0.0-tampered")

    # S6 unexpected dependency: a minor bump of dont-sniff-mimetype adds 3 transitive packages.
    pkg["dependencies"]["dont-sniff-mimetype"] = "^1.1.0"
    root["dependencies"]["dont-sniff-mimetype"] = "^1.1.0"
    new_deps = [f"guardian-seed-dep-{c}" for c in "abc"]
    packages["node_modules/dont-sniff-mimetype"] = {
        "version": "1.1.0",
        "resolved": "https://registry.npmjs.org/dont-sniff-mimetype/-/dont-sniff-mimetype-1.1.0.tgz",
        "integrity": fake_integrity("dont-sniff-mimetype@1.1.0"),
        "dependencies": {n: "^1.0.0" for n in new_deps},
    }
    for n in new_deps:
        packages = insert_sorted(packages, f"node_modules/{n}", {
            "version": "1.0.0", "resolved": f"https://registry.npmjs.org/{n}/-/{n}-1.0.0.tgz",
            "integrity": fake_integrity(f"{n}@1.0.0"),
        })  # fmt: skip

    lock["packages"] = packages
    pkg_path.write_text(json.dumps(pkg, indent=2) + "\n")
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")

    # S7 untrusted image: final stage FROM node:latest, running as root (USER line removed).
    dockerfile = FORK / "Dockerfile"
    lines = dockerfile.read_text().splitlines()
    final_from = max(i for i, line in enumerate(lines) if line.startswith("FROM "))
    lines[final_from] = "FROM node:latest"
    lines = [line for line in lines if not line.startswith("USER ")]
    dockerfile.write_text("\n".join(lines) + "\n")

    # S8 unsafe CI: pull_request_target together with checkout of the PR head.
    (FORK / ".github" / "workflows" / "seeded-pr-target.yml").write_text(
        "# SYNTHETIC (Guardian D1.S6): inert seeded scenario, never pushed or run.\n"
        "name: seeded-pr-target\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    (FORK / "SEEDED.md").write_text(
        "# SYNTHETIC: seeded supply-chain anomalies\n\n"
        "This branch is a local, inert evaluation fixture for Software Supply Chain Guardian.\n"
        "Nothing here is published or installed. The packages `expresss`, "
        "`guardian-seed-postinstall` and `guardian-seed-dep-*` do not exist in any registry; "
        "their integrity hashes are hashes of marker strings.\n"
        "See targets/seeded-ground-truth.json for the expected detections.\n"
    )

    # Mock registry metadata. Facts for the synthetic packages only.
    REGISTRY.mkdir(parents=True, exist_ok=True)
    manifest_dir = REGISTRY / "guardian-seed-postinstall" / "1.0.0"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "package.json").write_text(json.dumps({
        "name": "guardian-seed-postinstall", "version": "1.0.0",
        "description": "SYNTHETIC inert test package (Guardian D1.S6)",
        "scripts": {"postinstall": "echo GUARDIAN-SYNTHETIC-MARKER && "
                                   "curl -s http://127.0.0.1:9/guardian-synthetic || true"},
    }, indent=2) + "\n")  # fmt: skip
    (REGISTRY / "registry.json").write_text(json.dumps({
        "note": "SYNTHETIC mock registry metadata for seeded scenarios (Guardian D1.S6)",
        "url": MOCK,
        "packages": {
            "expresss": {"created": "2026-11-20T00:00:00Z", "weekly_downloads": 12,
                         "maintainers": ["guardian-seed"]},
            "guardian-seed-postinstall": {
                "created": "2026-11-21T00:00:00Z", "weekly_downloads": 3,
                "maintainers": ["guardian-seed"],
                "manifests": {"1.0.0": "targets/mock-registry/guardian-seed-postinstall/1.0.0/"
                                       "package.json"}},
        },
    }, indent=2) + "\n")  # fmt: skip

    git("add", "-A")
    git("commit", "--quiet", "-m", "SYNTHETIC: seeded supply-chain anomalies for Guardian "
        "evaluation (inert, local only)")  # fmt: skip
    seeded_sha = git("rev-parse", "HEAD")
    git("checkout", "--quiet", "--detach", seeded_sha)  # HEAD holds the SHA, like the clean target

    truth = {
        "target": "nodegoat-seeded", "base_target": "nodegoat",
        "base_commit": base_sha, "seeded_commit": seeded_sha,
        "note": "Seeded (S3-S8) plus pre-existing real issues in the unmodified app (R1-R4).",
        "expected": [
            {"id": "S3", "scenario": "typosquat", "type": "typosquat", "component": "expresss"},
            {"id": "S4", "scenario": "suspicious install script", "type": "install_script",
             "component": "guardian-seed-postinstall"},
            {"id": "S5a", "scenario": "lockfile registry host changed", "type": "lockfile_change",
             "component": "marked", "rule": "GR-LOCK-001"},
            {"id": "S5b", "scenario": "integrity changed without version change",
             "type": "lockfile_change", "component": "ms", "rule": "GR-LOCK-004"},
            *({"id": f"S6{c}", "scenario": "transitive additions from a minor bump",
               "type": "unexpected_dependency", "component": f"guardian-seed-dep-{c}"}
              for c in "abc"),
            {"id": "S7a", "scenario": "base image uses latest", "type": "untrusted_image",
             "component": "node", "rule": "GR-IMG-002"},
            {"id": "S7b", "scenario": "final stage runs as root", "type": "misconfiguration",
             "rule": "GR-IMG-003"},
            {"id": "S8", "scenario": "pull_request_target with checkout", "type": "unpinned_ci",
             "rule": "GR-CI-002"},
            {"id": "R1", "scenario": "real direct CVE", "type": "vulnerable_direct",
             "component": "marked"},
            {"id": "R2", "scenario": "real transitive CVE", "type": "vulnerable_transitive",
             "component": "bson"},
            {"id": "R3", "scenario": "real malicious package", "type": "malicious_package",
             "component": "fsevents"},
            {"id": "R4", "scenario": "real tag-pinned action", "type": "unpinned_ci",
             "component": "actions/checkout", "rule": "GR-CI-001"},
        ],
    }  # fmt: skip
    (ROOT / "targets" / "seeded-ground-truth.json").write_text(json.dumps(truth, indent=2) + "\n")

    targets_file = ROOT / "targets" / "targets.json"
    targets = json.loads(targets_file.read_text())
    targets["targets"] = [t for t in targets["targets"] if t["name"] != "nodegoat-seeded"] + [{
        "name": "nodegoat-seeded", "repo": "local fork of targets/nodegoat (no remote)",
        "commit": seeded_sha, "base_target": "nodegoat", "base_commit": base_sha,
        "branch": BRANCH, "synthetic": True, "license": "Apache-2.0", "ecosystem": "npm",
        "lockfile": "package-lock.json", "path": "targets/nodegoat-seeded", "read_only": True,
    }]  # fmt: skip
    targets_file.write_text(json.dumps(targets, indent=2) + "\n")

    make_readonly(FORK)
    print(f"seeded {BRANCH} at {seeded_sha} (base {base_sha[:12]})")
    print(git("show", "--stat", "--oneline", "HEAD"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
