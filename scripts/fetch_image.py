"""Download a public Docker Hub image into a local OCI layout, verifying every digest.

Usage:  python3 -I scripts/fetch_image.py library/node 12-alpine [--platform linux/amd64]

* Only https://auth.docker.io and https://registry-1.docker.io are contacted. Blob redirects
  to Docker's CDN are followed by curl, and every byte is verified against its sha256 digest.
* Writes cache/images/<repo>_<tag>/ (OCI image layout) and records the digests in
  targets/images.json. Nothing is executed and no Docker daemon is needed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
REGISTRY = "https://registry-1.docker.io/v2/{repo}"
ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}


def curl(url: str, out: Path, headers: dict[str, str]) -> dict[str, str]:
    """Fetch url into out with curl (https only). Returns the final response headers."""
    with tempfile.NamedTemporaryFile(delete=False) as hdr:
        header_file = Path(hdr.name)
    args = [
        "/usr/bin/curl",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--max-time",
        "600",
        "--retry",
        "2",
        "-o",
        str(out),
        "-D",
        str(header_file),
    ]
    for k, v in headers.items():
        args += ["-H", f"{k}: {v}"]
    subprocess.run([*args, url], check=True)  # noqa: S603 - fixed https URL, argv list
    raw = header_file.read_text(errors="replace").split("\r\n\r\n")
    header_file.unlink()
    last = [block for block in raw if block.strip()][-1]
    return {
        k.strip().lower(): v.strip()
        for k, _, v in (line.partition(":") for line in last.splitlines()[1:])
    }


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def fetch_verified(url: str, digest: str | None, dest: Path, headers: dict[str, str]) -> dict:
    tmp = dest.with_suffix(".part")
    resp = curl(url, tmp, headers)
    actual = sha256(tmp)
    expected = digest or resp.get("docker-content-digest")
    if expected is None or actual != expected:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"digest mismatch for {url}: expected {expected}, got {actual}")
    tmp.replace(dest)
    return {"digest": actual, "content_type": resp.get("content-type", "").split(";")[0]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", help="e.g. library/node")
    parser.add_argument("tag", help="e.g. 12-alpine")
    parser.add_argument("--platform", default="linux/amd64")
    a = parser.parse_args()
    os_name, arch = a.platform.split("/")

    with tempfile.TemporaryDirectory() as td:
        token_file = Path(td) / "token.json"
        curl(AUTH.format(repo=a.repo), token_file, {})
        token = json.loads(token_file.read_text())["token"]
    auth = {"Authorization": f"Bearer {token}", "Accept": ACCEPT}
    base = REGISTRY.format(repo=a.repo)

    out = ROOT / "cache" / "images" / f"{a.repo.replace('/', '_')}_{a.tag}"
    blobs = out / "blobs" / "sha256"
    blobs.mkdir(parents=True, exist_ok=True)

    # Tag -> index (or a single manifest). Verified against Docker-Content-Digest.
    first = blobs / "tag.tmp"
    info = fetch_verified(f"{base}/manifests/{a.tag}", None, first, auth)
    index_digest = info["digest"]
    first.replace(blobs / index_digest.split(":")[1])
    doc = json.loads((blobs / index_digest.split(":")[1]).read_text())

    if info["content_type"] in INDEX_TYPES or "manifests" in doc:
        chosen = [m for m in doc["manifests"]
                  if m.get("platform", {}).get("os") == os_name
                  and m.get("platform", {}).get("architecture") == arch]  # fmt: skip
        if len(chosen) != 1:
            raise SystemExit(f"expected one {a.platform} manifest, found {len(chosen)}")
        manifest_desc = chosen[0]
        mpath = blobs / manifest_desc["digest"].split(":")[1]
        fetch_verified(f"{base}/manifests/{manifest_desc['digest']}", manifest_desc["digest"],
                       mpath, auth)  # fmt: skip
        manifest = json.loads(mpath.read_text())
    else:
        manifest = doc
        manifest_desc = {"mediaType": info["content_type"], "digest": index_digest,
                         "size": (blobs / index_digest.split(":")[1]).stat().st_size}  # fmt: skip

    for desc in [manifest["config"], *manifest["layers"]]:
        dest = blobs / desc["digest"].split(":")[1]
        if dest.exists() and sha256(dest) == desc["digest"]:
            continue
        fetch_verified(f"{base}/blobs/{desc['digest']}", desc["digest"], dest, auth)
        if dest.stat().st_size != desc["size"]:
            raise SystemExit(f"size mismatch for {desc['digest']}")

    (out / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    (out / "index.json").write_text(json.dumps({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": manifest_desc["mediaType"],
            "digest": manifest_desc["digest"],
            "size": manifest_desc["size"],
            "annotations": {"org.opencontainers.image.ref.name": a.tag},
        }],
    }, indent=2))  # fmt: skip

    record = {
        "image": f"docker.io/{a.repo}:{a.tag}",
        "platform": a.platform,
        "index_digest": index_digest,
        "manifest_digest": manifest_desc["digest"],
        "layers": [d["digest"] for d in manifest["layers"]],
        "bytes": sum(d["size"] for d in manifest["layers"]),
        "oci_layout": out.relative_to(ROOT).as_posix(),
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    images_file = ROOT / "targets" / "images.json"
    images = json.loads(images_file.read_text()) if images_file.exists() else {"images": []}
    images["images"] = [i for i in images["images"] if i["image"] != record["image"]] + [record]
    images_file.write_text(json.dumps(images, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
