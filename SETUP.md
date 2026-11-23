# Setup

## Current checkout restoration (2026-11-23)

This checkout is `/home/bharath_sooryaa/Documents/side_proj/BGSW`; older paths below
describe the previous environment. Here Python 3.12.14, uv 0.12.13, Node 22.22.2,
and npm 9.2.0 were verified. `.guardian-git` is absent. Git status/log can be read
normally; protected `.git` is not modified.

```bash
uv sync --locked --python python3.12 --no-python-downloads --no-build --cache-dir .cache/uv
```

`uv add langchain-deepseek` was approved for the real demo and resolved 1.2.0;
`uv.lock` also adds langchain-openai 1.8.0, openai 3.51.0, regex 2026.11.15, and
tiktoken 0.14.0. Existing dependency versions were preserved. Registry dependencies
were installed from wheels; only this trusted local project was built. The local
cache `.cache/` is ignored. Network downloads require the managed runtime's network
approval; sandbox DNS failures are not missing-package evidence.

UI restoration used `npm ci --ignore-scripts --cache ../.cache/npm --no-audit
--no-fund` from `ui/`. `npm run build` passed with a bundle-size warning.

See RUN.md for the real scanner → DeepSeek → local UI demo. Do not use the old
scripted CLI commands below: production provider and model selection are explicit.
For database provisioning on a slow connection, Trivy needs `--timeout 30m
--no-progress`; its default five-minute timeout interrupted a near-complete download.
The download timeout does not change the offline scan's network isolation.

## Key handling after the live demo

The user-provided `.env` was consumed only for the explicitly requested migration,
then deleted. The live child received `DEEPSEEK_API_KEY` through its environment;
no replacement key file was created. Environment variables set in that child do
not persist into new terminals or future agent processes. Use RUN.md's hidden
prompt for future authorized runs. The read-only API/UI needs no provider key.

## Requirements

- `uv` 0.13.9, installed at `~/.local/bin/uv`.
- Python 3.12. `uv` provides it (cpython 3.12.16). The system `python3` is 3.14 and is not used.

## Reproduce the environment

```bash
cd /home/suthekshan/bosch
uv sync --locked          # creates .venv with Python 3.12.16 and installs uv.lock
uv run --locked pytest    # run tests
uv run --locked ruff check .
uv run --locked ruff format --check .
```

## Resolved dependencies (uv.lock, 2026-11-23)

Since D1.S8 the lock has 64 packages, including deepagents 0.7.38, langchain 1.5.0,
langchain-core 1.8.1, langgraph 1.2.22, langchain-anthropic 1.7.10, langchain-google-genai
4.5.0 and langsmith 0.14.17, all resolved with `exclude-newer = 2026-11-16`. That cutoff moved
pydantic to 2.14.3 and ruff to 0.17.5. The table below is the original D0/D1.S1 set.

| Package | Version | Role |
|---|---|---|
| pydantic | 2.14.4 | Contract validation (runtime) |
| pydantic-core | 2.50.5 | Pydantic dependency |
| annotated-types | 0.8.0 | Pydantic dependency |
| typing-extensions | 4.16.0 | Pydantic dependency |
| typing-inspection | 0.4.5 | Pydantic dependency |
| pytest | 9.2.0 | Tests (dev) |
| iniconfig, packaging, pluggy, pygments | 2.3.1, 26.3, 1.7.0, 2.21.0 | pytest dependencies (dev) |
| ruff | 0.17.6 | Lint and format (dev) |

No Python dependencies were added in D1.S2 or D1.S3. Deep Agents, LangChain, FastAPI and model
SDKs are not installed yet; each is added in its approved step. Scanner binaries are listed
below.

## Secrets

No secrets are used. A future LLM API key goes in an environment variable outside the
workspace. `.env` files are git-ignored and must not be created in the workspace.

## Scanner binaries (D1.S2)

```bash
python3 -I scripts/install_tools.py        # downloads ~240 MB into tools/downloads and verifies SHA-256
tools/bin/syft --version                   # syft 1.57.2
```

The pins and hashes are in `tools/manifest.json`. `tools/bin/` and `tools/downloads/` are
git-ignored and reproduced from the manifest.

## Sample target (D1.S2)

```bash
git -c core.hooksPath=/dev/null clone --no-checkout https://github.com/OWASP/NodeGoat.git targets/nodegoat
git -C targets/nodegoat -c core.hooksPath=/dev/null checkout c5cb68a7084e4ae7dcc60e6a98768720a81841e8
chmod -R a-w targets/nodegoat
```

The pinned commit is recorded in `targets/targets.json`. Nothing in the target is installed or
executed.

## Build the SBOM and graph (D1.S3)

```bash
uv run --locked python -m guardian.sbom build --target nodegoat --out runs/d1s3
uv run --locked python -m guardian.sbom path --graph runs/d1s3/graph.json --package marked
```

## Vulnerability databases and feeds (D1.S2/D1.S4, about 5.3 GB in `cache/`)

```bash
W=$PWD
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home GRYPE_DB_CACHE_DIR=$W/cache/grype tools/bin/grype db update
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home tools/bin/trivy fs --download-db-only --cache-dir $W/cache/trivy
env -i PATH=/usr/bin:/bin HOME=$W/cache/tool-home OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=$W/cache/osv \
  tools/bin/osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
  -L $W/targets/nodegoat/package-lock.json --format json --output-file /dev/null || true
scripts/fetch_feeds.sh        # EPSS and CISA KEV into cache/feeds, with SHA-256 and date in feeds.json
```

Grype refuses databases older than 120 hours, so refresh the caches before a demo.

## Scanner-only baseline (D1.S4)

```bash
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s4
```

All scanners run in an empty network namespace (`unshare -rn`). The outputs in `runs/d1s4/`
are `findings.json`, `baseline.md`, `baseline.json`, and the raw `grype.json`, `trivy.json` and
`osv.json`.

## Base image for the image scan (D1.S5)

```bash
python3 -I scripts/fetch_image.py library/node 12-alpine   # Docker Hub only; every blob SHA-256-verified
```

This writes an OCI layout to `cache/images/library_node_12-alpine/` and records the digests in
`targets/images.json`. The baseline command then scans it offline. It also runs Hadolint,
`trivy config` and zizmor (`--offline --no-config`) on the Dockerfile and workflows.

## Popular-package list and seeded fork (D1.S6)

```bash
python3 -I scripts/fetch_toplist.py      # npm-high-impact 1.13.0, SHA-512 verified, read as text only
python3 -I scripts/seed_anomalies.py     # SYNTHETIC local fork targets/nodegoat-seeded (no remote)
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s6-clean
uv run --locked python -m guardian.scan baseline --target nodegoat-seeded --out runs/d1s6-seeded
uv run --locked python -m guardian.scan evaluate --seeded runs/d1s6-seeded --clean runs/d1s6-clean \
  --out runs/d1s6-seeded/evaluation.json
```

`seed_anomalies.py` rewrites the seeded fork and ground truth from scratch; the commit SHA stays
stable only while the script and base commit are unchanged. The seeded target's base image is
`node:latest`, which is not fetched, so its run has no image findings.

## Risk scoring and the evidence store (D1.S7)

The baseline command now also scores and ranks every finding, and saves the run to SQLite:

```bash
uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s7
sqlite3 runs/guardian.db "SELECT id, risk_score, risk_level, weight_coverage, component_name \
  FROM findings WHERE run_id='runs/d1s7' ORDER BY ordinal LIMIT 10"
```

`baseline(..., db=None)` skips the store (the tests use this or their own database). The store
needs only Python's stdlib `sqlite3`; the `sqlite3` command line tool is optional.

## Agents (D1.S8)

```bash
uv sync --locked     # now includes deepagents 0.7.38 and LangChain (exclude-newer 2026-11-16)
uv run --locked python -m guardian.agents analyze --run runs/d1s7 --limit 10
uv run --locked python -m guardian.agents run --target nodegoat --out runs/d1s8
```

The default provider is the offline scripted model, with no network. Real providers and the
opt-in are described in `LLM_PROVIDERS.md`.

## Not yet set up

- The Docker daemon. The CLI exists, but `/var/run/docker.sock` is missing. NodeGoat's own
  image cannot be built until it runs; the base image is scanned instead.

## Published source repository (2026-11-23)

Current source is published at https://github.com/bharathsooryaa/temp on main.
The GitHub repository contains source and instructions, not local dependency
environments, cached databases, scanner downloads, credentials, or generated runs.
The proposed setup.sh/setup.bat launchers have not been implemented or published;
follow the manual setup and RUN.md until that separate step is approved.
