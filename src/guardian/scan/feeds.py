"""Offline EPSS and CISA KEV lookups from cache/feeds (fetched by scripts/fetch_feeds.sh)."""

from __future__ import annotations

import csv
import gzip
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EpssScore:
    cve: str
    epss: float
    percentile: float


@dataclass(frozen=True)
class EpssFeed:
    model_version: str | None
    score_date: str | None
    scores: dict[str, EpssScore]


@dataclass(frozen=True)
class KevEntry:
    cve: str
    date_added: str | None
    vendor: str | None
    product: str | None
    known_ransomware: str | None


@dataclass(frozen=True)
class KevFeed:
    catalog_version: str | None
    date_released: str | None
    entries: dict[str, KevEntry]


def load_epss(path: Path, wanted: set[str] | None = None) -> EpssFeed:
    """Load EPSS scores. Pass ``wanted`` to keep only those CVEs (the full feed is ~400k rows)."""
    with gzip.open(path, "rt", encoding="utf-8") as f:
        header = f.readline().lstrip("#").strip()
        meta = dict(part.split(":", 1) for part in header.split(",") if ":" in part)
        scores = {}
        for row in csv.DictReader(f):
            cve = row.get("cve", "")
            if wanted is not None and cve not in wanted:
                continue
            try:
                scores[cve] = EpssScore(cve, float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                continue
    return EpssFeed(meta.get("model_version"), meta.get("score_date"), scores)


def load_kev(path: Path) -> KevFeed:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = {
        v["cveID"]: KevEntry(
            cve=v["cveID"],
            date_added=v.get("dateAdded"),
            vendor=v.get("vendorProject"),
            product=v.get("product"),
            known_ransomware=v.get("knownRansomwareCampaignUse"),
        )
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }
    return KevFeed(data.get("catalogVersion"), data.get("dateReleased"), entries)
