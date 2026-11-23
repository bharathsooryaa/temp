"""Fetch the popular-npm-package list used by the typosquat rule (D6-01).

Source: npm-high-impact 1.13.0 (MIT, wooorm), the tarball from registry.npmjs.org.
It is verified against the pinned SHA-512 integrity before anything is read. Only
`package/lib/top.js` is read, parsed as text with a strict per-line pattern, and never
executed. Output: cache/toplists/npm-high-impact-1.13.0.json (names in source order).

Usage:  python3 -I scripts/fetch_toplist.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME, VERSION = "npm-high-impact", "1.13.0"
URL = f"https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"
INTEGRITY = (
    "sha512-Dngjb2fyZfj4/7aZ+9kGGGK/IWnBhb45nzHX1ECxi26vXixk"
    "KzdixCB81XTwQzyAwc4d39VbcTL+rlS+d7VETA=="
)
MEMBER = "package/lib/top.js"
# npm name characters only (legacy packages such as 'JSONStream' may use uppercase)
LINE = re.compile(r"\s*'([A-Za-z0-9@._/~-]+)',?")


def main() -> int:
    out = ROOT / "cache" / "toplists" / f"{NAME}-{VERSION}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "pkg.tgz"
        subprocess.run(  # noqa: S603 - fixed https URL, argv list
            [
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--max-time",
                "300",
                "-o",
                str(tgz),
                URL,
            ],
            check=True,
        )
        data = tgz.read_bytes()
        got = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        if got != INTEGRITY:
            raise SystemExit(f"integrity mismatch: expected {INTEGRITY}, got {got}")
        with tarfile.open(tgz, "r:gz") as tar:
            info = tar.getmember(MEMBER)
            if not info.isfile():
                raise SystemExit(f"{MEMBER} is not a regular file")
            text = tar.extractfile(info).read().decode("utf-8")

    lines = text.strip().splitlines()
    if lines[0].strip() != "export const top = [" or lines[-1].strip() != "]":
        raise SystemExit("unexpected file layout; refusing to parse")
    names = []
    for number, line in enumerate(lines[1:-1], start=2):
        m = LINE.fullmatch(line)
        if not m:
            raise SystemExit(f"line {number} is not a plain quoted name: {line!r}")
        names.append(m.group(1))
    if len(names) != len(set(names)):
        raise SystemExit("duplicate names in list")

    out.write_text(json.dumps({
        "source": {"package": NAME, "version": VERSION, "url": URL, "integrity": INTEGRITY,
                   "member": MEMBER, "license": "MIT",
                   "definition": "npm high-impact: >=1,000,000 weekly downloads or >=500 "
                                 "dependents"},
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "count": len(names),
        "names": names,
    }, indent=1) + "\n")  # fmt: skip
    print(f"{len(names)} names -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
