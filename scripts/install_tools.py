"""Install pinned scanner binaries into tools/bin from tools/manifest.json.

Stdlib only. Each download must match the pinned SHA-256 or it is discarded. From archives,
only the named member is extracted, and only as a regular file. Nothing is installed outside
the workspace, and nothing needs root.

Usage:  python3 -I scripts/install_tools.py [--only NAME ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tools" / "manifest.json"
BIN = ROOT / "tools" / "bin"
DOWNLOADS = ROOT / "tools" / "downloads"
ALLOWED_PREFIX = "https://github.com/"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    if not url.startswith(ALLOWED_PREFIX):
        raise SystemExit(f"refusing non-GitHub URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-tool-installer"})  # noqa: S310 - https GitHub prefix checked above
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=300) as r, tmp.open("wb") as f:  # noqa: S310
        shutil.copyfileobj(r, f)
    tmp.replace(dest)


def extract_member(archive: Path, member: str, dest: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        matches = [m for m in tar.getmembers() if m.name.lstrip("./") == member]
        if len(matches) != 1:
            raise SystemExit(
                f"{archive.name}: expected one member {member!r}, found {len(matches)}"
            )
        info = matches[0]
        if not info.isfile():
            raise SystemExit(f"{archive.name}: member {member!r} is not a regular file")
        src = tar.extractfile(info)
        if src is None:
            raise SystemExit(f"{archive.name}: cannot read {member!r}")
        with src, dest.open("wb") as out:
            shutil.copyfileobj(src, out)


def install(tool: dict) -> str:
    name, expected = tool["name"], tool["sha256"].lower()
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    artifact = DOWNLOADS / Path(tool["url"]).name
    if not artifact.exists() or sha256(artifact) != expected:
        download(tool["url"], artifact)
    actual = sha256(artifact)
    if actual != expected:
        artifact.unlink(missing_ok=True)
        raise SystemExit(f"{name}: SHA-256 mismatch (expected {expected}, got {actual}); deleted")

    BIN.mkdir(parents=True, exist_ok=True)
    target = BIN / name
    with tempfile.NamedTemporaryFile(dir=BIN, delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        if tool["kind"] == "tar.gz":
            extract_member(artifact, tool["member"], tmp_path)
        elif tool["kind"] == "binary":
            shutil.copyfile(artifact, tmp_path)
        else:
            raise SystemExit(f"{name}: unknown kind {tool['kind']!r}")
        tmp_path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        os.replace(tmp_path, target)
    finally:
        tmp_path.unlink(missing_ok=True)
    return f"{name} {tool['version']} sha256 ok -> {target.relative_to(ROOT)}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="*", default=None, help="tool names to install")
    args = parser.parse_args()
    tools = json.loads(MANIFEST.read_text())["tools"]
    if args.only:
        unknown = set(args.only) - {t["name"] for t in tools}
        if unknown:
            raise SystemExit(f"unknown tools: {sorted(unknown)}")
        tools = [t for t in tools if t["name"] in args.only]
    for tool in tools:
        print(install(tool), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
