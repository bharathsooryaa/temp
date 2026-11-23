#!/usr/bin/env bash
# Download the EPSS and CISA KEV feeds into cache/feeds, then record each file's SHA-256 and date.
# The feeds change daily, so the hashes record what was used rather than pin anything.
set -euo pipefail
cd "$(dirname "$0")/.."
out=cache/feeds
mkdir -p "$out"

fetch() {  # name url file
  curl --fail --silent --show-error --location --proto '=https' --max-time 300 \
       --retry 2 -o "$out/$3.part" "$2"
  mv "$out/$3.part" "$out/$3"
  printf '  "%s": {"url": "%s", "file": "%s/%s", "sha256": "%s", "fetched_at": "%s"}' \
    "$1" "$2" "$out" "$3" "$(sha256sum "$out/$3" | cut -d' ' -f1)" "$(date -u +%FT%TZ)"
}

{
  echo "{"
  fetch epss "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz" epss_scores-current.csv.gz
  echo ","
  fetch kev "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" known_exploited_vulnerabilities.json
  echo
  echo "}"
} > "$out/feeds.json.part"
mv "$out/feeds.json.part" "$out/feeds.json"
cat "$out/feeds.json"
