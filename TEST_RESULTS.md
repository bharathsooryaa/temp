# Test results

## Current checkout: approved real DeepSeek demo preparation (2026-11-23)

Baseline revision `f46179b`, initially clean. No live provider request has been sent.
DeepSeek model selected by user: `deepseek-flash`. The five-finding paid run is approved; an optional monetary ceiling is unspecified.
Key availability is pending. This record describes this checkout, not historical runs.

| Command/check | Actual outcome |
|---|---|
| `git --git-dir=.guardian-git --work-tree=. status --short` | Failed: metadata absent. Normal read-only `git status --short` succeeds and was initially empty; no Git metadata modified |
| `rg --files` | Failed: rg unavailable; used find and direct file reads |
| Python/uv/Node/npm versions | 3.12.14 / 0.12.13 / 22.22.2 / 9.2.0 |
| `unshare -rn /usr/bin/true` | Exit 0 |
| Initial sandbox dependency/scanner/target downloads | Failed with DNS errors; rerun through managed network approval |
| `uv sync --locked --python python3.12 --no-python-downloads --no-build --cache-dir .cache/uv` | Succeeded with approved network access; 69 locked packages including project |
| `uv add langchain-deepseek --python python3.12 --no-python-downloads --no-build --cache-dir .cache/uv` | Succeeded: 74 resolved packages; five provider-related additions, existing versions unchanged |
| `npm ci --ignore-scripts --cache ../.cache/npm --no-audit --no-fund` in ui | 44 packages installed |
| `npm run build` in ui | Passed TypeScript and Vite build; warning: minified JS bundle exceeds 500 kB |
| NodeGoat checkout | Exact registered commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`; made read-only; no target scripts installed or executed |
| `scripts/fetch_feeds.sh`, `scripts/fetch_toplist.py`, `scripts/fetch_image.py library/node 12-alpine` | Passed; feed hashes recorded; popular list SHA-512 matched, 17,338 names; image blobs digest-verified, 30,083,968 bytes |
| Scanner installer | Syft, Grype, OSV-Scanner and Trivy installed after matching manifest SHA-256; posture tools still downloading at this checkpoint |
| Grype first artifact | Rejected and deleted for hash mismatch after overlapping download invocations; redundant downloader stopped; isolated retry passed unchanged pinned hash |
| `.venv/bin/python -m guardian.sbom build --target nodegoat --out runs/demo-deepseek` | Passed: CycloneDX 1.5, 422 components; graph 1,480 nodes / 2,295 edges / depth 13; runtime package sets agree 381/381 |
| Initial offline suite | Found stale missing ScriptedModel import; moved historical fixture under tests and explicitly injected it. Optional-adapter test then failed because OpenAI adapter is now installed; test now simulates adapter absence |
| Sandbox API tests | Stalled in TestClient; process stopped after a successful bounded suite outside restricted runtime |
| `timeout 120 .venv/bin/pytest -m 'not integration' -q` (approved runtime) | 239 passed, 4 deselected in 1.53s before four additional CLI validation cases |
| `timeout 120 .venv/bin/pytest tests/test_build_integration.py tests/test_runner.py -q` | 14 passed in 1.00s, including restored Syft/NodeGoat integration |
| `.venv/bin/ruff check .`, `.venv/bin/ruff format --check .`, `git diff --check` | Passed after new fixture import formatting |
| External-call refusal check | DeepSeek refused without GUARDIAN_ALLOW_EXTERNAL_MODELS=1; key availability checked as boolean only, currently not set |
| Ad hoc source-context inspection | Two helper probes failed (missing dockerfile argument; wrong field name); corrected probe returned 12 runtime import names and 3 network facts; no application changes required |

Full scanner baseline, independent citation verification, and live explanation/UI
acceptance remain pending. Historical vulnerability counts below are not results
of this new demo run. Four more offline CLI validation cases were added after the
239-test checkpoint; results are recorded when their run completes.

Further verified preparation:

- Offline suite after CLI tests: **243 passed, 4 deselected in 1.55s**.
- Final provider tests after selecting non-thinking mode: **28 passed in 1.01s**.
- Actual ChatDeepSeek client and Deep Agents graph constructed successfully in
  `unshare -rn` with a dummy key; no model invocation. Reported provider `deepseek`,
  request timeout 60, retries 0, output tokens 2,048, main tools `{read_file, task}`.
- All six scanner downloads passed SHA-256 verification and were installed.
- Database restore commands buffer output. They were restarted with the host CA
  certificate environment forwarded, before completion. On stopping the first
  Trivy process its buffered log showed 39.73/136.26 MiB downloaded; it was making
  progress, not stalled. The restart was unnecessary and is not counted as a
  successful download. Grype/OSV were also restarted; restoration is still pending.
- `grype db list -o json` with a 45-second bound succeeded and listed active
  schema v6.1.10, built 2026-11-23T06:28:32Z.
- Full available suite (`timeout 120 .venv/bin/pytest -q`): **245 passed, 2 skipped
  in 2.62s**. Explicit skips: full baseline lacks database caches; seeded integration
  lacks seeded checkout (not used for this demo). All six `--version` checks match
  the scanner manifest. Ruff and `git diff --check` pass.
- The restarted Trivy download reached 131.01/136.26 MiB, then its internal default
  five-minute timeout failed with `context deadline exceeded`. Retrying with the
  CLI's documented `--timeout 30m --no-progress`; no cache success claimed yet.
- DeepSeek adapter finalized as `langchain-deepseek==1.2.0`; offline re-resolution
  preserves all resolved versions. `uv lock --check --offline --cache-dir .cache/uv`
  passes (74 packages).

## D1.S1: contracts and risk scoring (2026-11-23)

Environment: Python 3.12.16 (uv-managed), pydantic 2.14.4, pytest 9.2.0, ruff 0.17.6.

| Command | Outcome |
|---|---|
| `uv sync` | Created `.venv` and installed 12 packages, with `uv.lock` written (13 resolved packages, counting the project itself) |
| `uv lock --check` | Lockfile up to date |
| `uv run --locked ruff check .` | All checks passed |
| `uv run --locked ruff format --check .` | 16 files already formatted |
| `uv run --locked pytest` | **75 passed**, 0 failed, 0 skipped |

### Coverage of acceptance criteria

- **PDF weights:** 0.30/0.20/0.20/0.15/0.15, which sum to 1.
- **Factor scales:** CVSS×10; EPSS×100 (KEV forces 100); reachability 100/60/30/0; exposure
  100/50/20; provenance 0 to 100.
- **Weighted sum:** a hand-computed example, the PDF's lodash finding, scores 45.6 (Medium).
- **Bands at boundaries:** 85, 84.99, 65, 64.99, 40, 39.99. Exact 85 and 65 from real factors are
  tested, as is 84.4 (High) and rounding before banding (84.996 shows as 85.0, Critical).
- **Unknown factors (D1-02):** renormalized, not zeroed. CVSS 5 plus "called" scores 70, not 35.
  No data gives `Unknown`.
- **Malicious override (D1-04):** forces Critical, even when the score is low or `None`. A
  typosquat heuristic is not forced to Critical and has no override.
- **Out-of-range inputs:** rejected.
- **Evidence paths:** absolute, `..`, Windows drive, backslash, empty and NUL paths are rejected;
  `./` is normalized.
- **Evidence records:** must be locatable; `line` requires `file`; ID format is enforced.
- **All contracts:** frozen, with unknown fields rejected.
- **Graph:** dangling edges, duplicate nodes and a missing root are rejected. Shortest path works,
  including through cycles and for unreachable nodes.
- **Findings:**
  - Direct and transitive dependency-path lengths are enforced.
  - A rationale must cite attached evidence; uncited or unknown `E-###` is rejected.
  - Override consistency is enforced.
  - JSON round-trips.
- **FindingSet:** rejects unresolved citations, tool mismatches, and duplicate evidence or finding
  IDs.

### Problems found while testing

- A test named "...despite_float_error" claimed float noise at 85. Checking showed
  0.30·100+0.20·100+0.20·100+0.15·100 is exactly 85.0, so the test was renamed. The 84.996 case is
  the one that exercises rounding.

### Limits

- Unit tests only. No scanner, SBOM, model or network behaviour exists yet.
- No coverage tool is installed, so no coverage percentage is reported.

## D1.S2: sample app and scanners (2026-11-23, partial)

| Check | Outcome |
|---|---|
| `make_manifest.py`, a one-off scratchpad script, which compared each hash from two sources | 5 tools agreed across checksum file and GitHub API digest; zizmor has the API digest only |
| `python3 -I scripts/install_tools.py` | 6/6 `sha256 ok` |
| `tools/bin/<tool> --version` | syft 1.57.2, grype 0.121.3, osv-scanner 2.7.1, trivy 0.76.2, hadolint 2.15.1, zizmor 1.32.0 |
| NodeGoat clone | HEAD `c5cb68a7…`; a test write into the clone was refused (`Permission denied`) |
| `docker version` | **Fails**: the daemon is not running (`/var/run/docker.sock` missing) |
| Database, EPSS and KEV caching | **Not done** |

## D1.S3: SBOM and dependency graph (2026-11-23)

| Command | Outcome |
|---|---|
| `uv run --locked python -m guardian.sbom build --target nodegoat --out runs/d1s3` | exit 0. SBOM: 422 components, CycloneDX 1.5. Graph: 1,480 nodes, 2,295 edges, max depth 13. Cross-check agrees (381 vs 381) |
| `... guardian.sbom path --package marked` | `owasp-nodejs-goat@1.3.0 → marked@0.3.5`, evidence `package-lock.json:6742`; that line is confirmed to be the `node_modules/marked` entry |
| `uv run --locked ruff check .` / `ruff format --check .` | All checks passed / 33 files formatted |
| `uv run --locked pytest` | **103 passed** (75 from D1.S1 plus 28 new) |
| `uv run --locked pytest -m integration` | 2 passed: syft runs in the minimal environment, and the NodeGoat end-to-end build |

### New coverage

- **npm resolution:** nested copies take precedence; resolution walks up the ancestors; scoped
  packages resolve.
- **purl encoding:** scoped names are written as `%40scope`, and `+` in versions as `%2B`.
- **Lockfile line numbers:** each one is checked against the real line.
- **Node attributes:** direct and dev flags, edge kinds (dev, peer, optional).
- **Unresolved dependencies:** reported, never invented. Optional and required ones are
  reported separately.
- **Graph queries:**
  - depths
  - `introduced_by`
  - a dev shortcut against the runtime-only path
  - an unreachable orphan
  - a JSON round trip that keeps the query indexes
- **Rejected inputs:** v1 and invalid lockfiles; the wrong CycloneDX format or version; dangling
  SBOM references.
- **Cross-check:** dev packages and duplicate install paths are handled, and differences are
  listed.
- **Runner:** non-allow-listed tools are rejected (`bash`, `curl`, `npm`, traversal, `;`). Path
  jail escapes are rejected, including through a symlink.

### Problems found and fixed

- **Count mismatch:** Syft's 413 npm components looked like a mismatch with the lockfile's 380
  unique runtime packages. Tracing showed 381 unique name@version on both sides (Syft includes
  the root). The 413 counts the same version at several install paths separately.
- **Misleading path:** the plain shortest path for a runtime package went through a dev-only
  dependency. `exclude_dev` path search was added, with a test.
- **Lint:** ruff flagged S310, E501 and RUF043. Each was fixed and documented in place.

### Limits

- The SBOM hash differs between runs, because Syft embeds a timestamp and serial number.
  Comparisons should use component sets, not file hashes.
- No vulnerability scanning yet (D1.S4).
- The graph covers npm only. Container and OS packages come in D1.S5.

## D1.S2 completion and D1.S4: scanner-only baseline (2026-11-23)

| Command | Outcome |
|---|---|
| `grype db update` (cache/grype) | Schema v6.1.10, built 2026-11-23T06:28Z, status valid (3.4 GB) |
| `trivy fs --download-db-only` | DB v2, updated 2026-11-23T07:04Z (1.7 GB) |
| `osv-scanner ... --download-offline-databases` | npm `all.zip`, 212 MB |
| `scripts/fetch_feeds.sh` | EPSS score_date 2026-11-22 (411,251 lines); KEV 2026.11.20 (1,790) |
| `unshare -rn curl https://github.com` | `Could not resolve host`: the namespace has no network |
| Offline Syft, Grype, Trivy and OSV runs in `unshare -rn` | All succeeded (OSV exit 1 means vulnerabilities found) |
| `uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s4` | exit 0. 324 findings / 133 packages; 0 unmapped; 1,263 evidence records |
| Citation verifier (run by the command above) | **7,335/7,335 cited facts resolve (100.0%)** |
| `uv run --locked ruff check .` / `ruff format --check .` | All checks passed / 42 files unchanged |
| `uv run --locked pytest` | **122 passed** (103 earlier plus 19 new) |

### Baseline facts (NodeGoat `c5cb68a`, databases as of 2026-11-23)

- **Raw matches:** Grype 340, Trivy 325, OSV 313. Grype's 340 drop to 313 unique
  (advisory, package) pairs, the same as OSV's 313. All Grype matches are exact package matches;
  none come from CPEs.
- **Advisory groups:** 310 found by 3 tools, 1 by 2 tools, 13 by 1 tool. The single-tool ones
  are all Trivy NSWG advisories with no alias.
- **Findings by type:** 1 malicious package (fsevents, MAL-2023-462), 20 vulnerable direct, 303
  vulnerable transitive. 93 runtime and 231 dev-only. 0 in KEV.
- **Missing data:** 24 findings have no CVSS, 31 no EPSS, and 31 have KEV unknown (no CVE alias).

### New coverage (test_scan.py and test_baseline_integration.py)

- **Parsers, in each tool's real format:** JSON pointers; aliases; the highest v3 CVSS; fix
  versions (Grype's not-fixed state gives no versions); malicious flags.
- **Correlation:** a GHSA and its CVE merge across all three tools; a repeated Grype match is
  dropped; unrelated IDs stay separate.
- **Feeds:** the EPSS header, the `wanted` filter, and a malformed row; KEV loading.
- **Findings:**
  - malicious first, then KEV
  - direct and transitive types and dependency paths
  - `introduced_by`
  - KEV unknown when there is no CVE
  - dev-only exposure
  - lockfile lines cited
  - deduplicated evidence
- **Verifier:** 100% on valid data. It catches an invented CVE, a wrong dependency path, an
  unknown `introduced_by`, a wrong component version and a wrong fix version.
- **Integration:** a real offline NodeGoat baseline. The fsevents malware is detected, agreement
  across all three tools is above 90%, and the verifier reaches 100%.

### Problems found and fixed

- **Duplicate Grype matches:** Grype repeats a match once per install path, which created 27
  duplicate evidence records. These are now collapsed in `correlate`.
- **Lint:** ruff flagged B023 (a closure over a loop variable in union-find) and E501. Both were
  fixed by moving `_find` to module level and wrapping lines.

### Limits

- **Possible duplicates:** the 13 Trivy NSWG advisories have no alias data, so they may duplicate
  other findings.
- **Not computed yet:** reachability, network exposure and the risk scores (D1.S7).
- **Changing counts:** the databases change daily, so counts will drift. Exact numbers here are
  for the 2026-11-23 databases.

## D1.S5: container image and CI/CD inspection (2026-11-23)

| Command | Outcome |
|---|---|
| `docker version` | Still fails (no daemon), so option (b) was used |
| `python3 -I scripts/fetch_image.py library/node 12-alpine` | Manifest `sha256:4517380049fc…`, 4 layers, 30,083,968 bytes; every digest verified |
| Offline Trivy image, Grype `oci-dir:`, Hadolint, `trivy config`, zizmor (`unshare -rn`) | All succeeded. Hadolint exit 1 and zizmor exit 14 mean "findings present" |
| `uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/d1s5` | exit 0. 407 findings, of which 324 are dependency findings. 1,437 evidence records |
| Citation verifier | **8,782/8,782 (100.0%)** |
| `uv run --locked ruff check .` / `ruff format` | All checks passed |
| `uv run --locked pytest` | **142 passed** (122 earlier plus 20 new; the integration test extended with posture checks) |

### Facts (2026-11-23 databases)

- **Trivy image:** Alpine 3.15.4 with `EOSL: true`. 23 OS-package and 49 bundled-npm-package
  vulnerabilities.
- **Grype image:** 217 matches. 144 are CPE-only and excluded; 73 exact.
- **Image groups:** 70 advisory groups; 69 found by both tools.
- **zizmor:** 6 `unpinned-uses` (High) and 2 `excessive-permissions` (Medium). Each of the 6
  matches a GR-CI-001 hit at the same line.
- **Hadolint:** DL3066 (info). **Trivy config:** DS-0026 (low). **GR-IMG-001:** Dockerfile lines
  1 and 7.

### New coverage (tests/test_posture.py)

- **Dockerfile rules:** `latest` and no tag, stage references skipped, digest-pinned images,
  root user variants, and `FROM` parsing with an alias.
- **Workflow rules:** tag vs SHA; local, `docker://` and commented-out actions; and
  `pull_request_target` combined with checkout.
- **Image references:** Docker Hub, GHCR with a digest, and a registry with a port. Also
  `load_image` name normalization.
- **Parsers:** Hadolint, Trivy config and zizmor in their real formats, including zizmor's
  Primary vs Hidden locations.
- **Merging:** zizmor and the guardian rule merge into one finding with an action purl.
- **Image findings:** the CPE-only match is excluded, the image path and `introduced_by` are
  set, and the EOSL hit is produced only when Trivy sets the flag.
- **Verifier:** 100% on config and image findings. It catches a moved rule line, an invented
  rule ID and a wrong image digest.
- **Regression:** a pointer excerpt with no summary stays parseable.

### Problems found and fixed

- **Pointer parsing:** an empty summary produced excerpts ending in `" ::"`, which broke the
  verifier's pointer parsing. The image test caught it; it was a latent Step 4 bug. Fixed with
  `pointer_excerpt` and a regex parser.
- **Outdated assertion:** the integration test required every finding to have a dependency path.
  CI and Dockerfile findings have none, so it now applies to dependency and image types only.
- **Misleading count:** the CLI and report said "407 (93 runtime, 231 dev-only)". The split now
  shows only against the 324 dependency findings.
- **Code structure:** a circular import between `baseline` and `posture` was removed by moving
  shared helpers to `scan/common.py`.

### Limits

- NodeGoat's own image was not built, because Docker is not running.
- Node 12 binary CVEs are not listed, because Grype's CPE matches are excluded (D5-03).
- **Suspected false positive:** `npm-cli-docs@0.1.0`, matched to GHSA-mwpr-cgch-q8vc, is npm's
  bundled docs folder. It is reported as the tool found it and not suppressed.
- The workflow rules are line-based. zizmor cross-checks them, but unusual YAML layouts could be
  missed by the guardian rules.

## D1.S6: anomaly rules and seeded evaluation (2026-11-23)

| Command | Outcome |
|---|---|
| Source probes | npm search 200 (query-based); ecosyste.ms 429; GitHub API rate-limited; npm-high-impact metadata 200 |
| `python3 -I scripts/fetch_toplist.py` | Integrity matched. First runs refused `'JSONStream'` and `'-'` (strict pattern), then the pattern was widened. 17,338 names |
| `python3 -I scripts/seed_anomalies.py` | `seeded-anomalies` at `bb57ba2`, base `c5cb68a`. No remote; write refused (read-only). Lockfile diff +40/−7 |
| `... baseline --target nodegoat --out runs/d1s6-clean` | 415 findings; **8,835/8,835 verified** |
| `... baseline --target nodegoat-seeded --out runs/d1s6-seeded` | 362 findings (no image: `node:latest` not fetched); **7,853/7,853 verified** |
| `... evaluate --seeded runs/d1s6-seeded --clean runs/d1s6-clean` | **Seeded recall 10/10, real recall 4/4, precision on new 20/20** |
| `uv run --locked ruff check .` | All checks passed |
| `uv run --locked pytest` | **167 passed** (142 earlier plus 24 anomaly plus 1 seeded integration) |

### Clean-app anomaly and posture findings (manual review of 21)

- **17 valid:**
  - `grunt-if` from `github.com/.../tarball/master` (GR-LOCK-001, mutable).
  - 3 GR-INST-001: cypress, nodemon and fsevents.
  - 6 tag-pinned actions and 2 excessive-permissions.
  - EOSL and 2 GR-IMG-001.
  - DS-0026 and DL3066.
- **4 false positives (GR-TYPO-001, low, distance 2):**

  | Package | Near |
  |---|---|
  | `pad-stream` | `tar-stream` |
  | `lodash.rest` | `lodash.get` |
  | `node-eta` | `node-pty` |
  | `director` | `direction` |

- **Typosquat precision on the clean app:** 0/4. Every seeded typosquat is caught, but the
  name-only heuristic is noisy at distance 2.

### New coverage (tests/test_anomaly.py)

- **Distance helpers:** optimal string alignment distance and the edit classifier (insertion,
  deletion, transposition, keyboard-adjacent, separator, multiple). Also keyboard adjacency and
  length thresholds.
- **Typosquat matching:** popular and short names are skipped. Severity is high only with recent
  and rarely-downloaded registry metadata.
- **Every rule** fires on a crafted base/target pair, and the popular, bumped `helper` is *not*
  flagged.
- **Grouping:** one finding per package and type, with paths and `introduced_by`.
- **Verifier:** 100% on anomaly findings. It catches a wrong popular-list rank, wrong registry
  downloads and an edited lockfile line.
- **Evaluation helper:** `seeded_changes` reports changed lines and not unchanged ones.

### Problems found and fixed

- **Strict list parser:** it rejected legitimate names (`JSONStream`, `-`). It was widened to the
  npm name characters, still with no quotes or backslashes.
- **Distance-2 typosquats:** 4 false positives on the real app. Severity is now evidence-based
  (D6-02), and `classify` no longer labels 2-edit matches as single edits.
- **Hardcoded date:** the package-age check used a fixed date; it now uses the current date.
- **Untestable registry path:** the mock-registry path was hardcoded, so test fixtures cited the
  real file. It is now a parameter.
- **Evaluator precision (initially 15/23):**
  - File-path components differed between targets, so unchanged findings looked new.
  - Genuine detections of seeded files by tools the ground truth didn't name were counted as
    false.
  - Fixed with prefix-normalized signatures and difflib changed-line attribution. The result is
    20/20.
- **My own test mistake:** `lodsah` vs `lodash` is one transposition, so a real 2-edit example
  replaced it.
- **Lint:** the S607 partial `curl` path was fixed by pinning `/usr/bin/curl` in both fetch
  scripts.

### Limits

- **Suspicious-update rule:** maintainer change and publish anomalies are not implemented; they
  need live registry metadata.
- **Package age:** real packages have no age or download data, so typosquat suspicion relies on
  the name and list membership.
- **The seeded fork** only edits the lockfile's `packages` section, not the legacy v1
  `dependencies` section. Its image is not fetched, so its run has no image findings.

## D1.S7: risk score v1 and the SQLite store (2026-11-23)

| Command | Outcome |
|---|---|
| First `baseline --target nodegoat --out runs/d1s7` | Verifier: **2 failures**. `underscore@1.8.3` (a nested dev copy) was claimed "imported" because imports were matched by name only. Fixed (D7-01) |
| `baseline --target nodegoat --out runs/d1s7` | exit 0. 415 findings scored. **10,127/10,127 verified** |
| `baseline --target nodegoat-seeded --out runs/d1s7-seeded` | exit 0. **9,082/9,082 verified** |
| `evaluate --seeded runs/d1s7-seeded --clean runs/d1s7` | Seeded 10/10, real 4/4, precision on new 20/20 (unchanged) |
| Store round trip | `load_findings()` equals `findings.json` for both runs. `PRAGMA foreign_key_check` is empty; `integrity_check` returns ok |
| `uv run --locked ruff check .` | All checks passed (an S608 false positive was resolved with a literal placeholder list) |
| `uv run --locked pytest` | **201 passed** (167 earlier plus 25 context plus 8 store plus 1 extended integration) |

### Results (2026-11-23 databases)

- **Clean:**
  - Risk levels: Critical 1 (fsevents, forced), High 0, Medium 97, Low 317.
  - Reachability: imported 16, present only 79, dev-only unused 237, unknown 83.
  - Exposure: network 16, internal 154, build/dev 245.
- **Top dependency findings:**

  | Finding | Score | Level | Coverage |
  |---|---|---|---|
  | `underscore@1.9.1` | 57.24 | Medium | 1.0 |
  | `y18n@3.2.1` | 56.82 | Medium | 1.0 |
  | `mongodb@2.2.36` | 54.0 | Medium | 0.5 (GHSA-only, no CVSS or EPSS) |
  | `marked@0.3.5` | 54.0 | Medium | 0.5 |

- **Seeded:** `marked` CVEs rise to High 72.0, because the tampered-host provenance (60) is shared
  onto the CVE findings.

### New coverage

- **tests/test_context.py:**
  - Package-name mapping, file roles, and app scanning (commented, builtin, local, client and
    dev imports; dynamic requires; listen and EXPOSE facts).
  - Top-level resolution, `entry_key_above`, and the provenance table.
  - Enrichment: imported vs nested copy, dev-only, malicious, CI, image, and shared anomaly
    provenance. Scores match the formula, in rank order.
  - Verifier catches a wrong "imported", fake network exposure, a score that doesn't match its
    factors, and invented provenance.
- **tests/test_store.py:** exact round trip, atomic replace, a failed save keeping the previous
  run, rank order, foreign keys, unknown run, path jail and schema-version mismatch.
- **Integration:** every finding scored, fsevents first, the store round-trips, and test runs use
  separate databases.

### Problems found and fixed

- **Import matching:** by name only, which wrongly marked a nested dev copy as imported. The
  verifier caught it, and the fix resolves to the installed copy.
- **Missing factors:** config drafts had no `factors` key, causing a KeyError. They now default
  to empty factors.
- **Old fixtures:** the new risk checks failed three earlier unit tests whose fixtures are
  unscored. Risk checks now apply to scored findings only, and pipeline runs score everything.
- **Test databases:** integration tests wrote to the main database. They now use separate or no
  databases.

### Limits

- No call graph, so no finding is "called". Two dynamic requires are not resolved (both are local
  config).
- Network-facing is inferred from import plus listen/EXPOSE, not from data-flow analysis.
- Provenance 0 means no signal from four checks, not verified trust.
- Coverage rescaling distorts cross-category ranking (D7-04). This may need a decision before the
  demo.

## D1.S8: agents and the explanation gate (2026-11-23)

| Command | Outcome |
|---|---|
| `uv lock` (deepagents 0.7.38, exclude-newer 2026-11-16) | 64 packages. pydantic 2.14.3, ruff 0.17.5 (cutoff) |
| `uv sync --locked`, then unit tests on the new versions | 197 passed before any agent code was added |
| Prototype in `unshare -rn` | Scripted model drove a tool call through `create_deep_agent`; tool node `['ping', 'read_file']` |
| `python -m guardian.agents analyze --run runs/d1s7 --limit 5` in `unshare -rn` | 5 accepted, 0 rejected, 0 blocked, 7 tool calls |
| `... analyze --run runs/d1s7-seeded --limit 3 --provider scripted-hallucinating` | **0 accepted**, 3 rejected (E-9999 not evidence; CVE-2099-0001 not an advisory), exit 1 |
| `... analyze --run runs/d1s7 --provider anthropic` (no opt-in) | Refused before building a model, exit 2 |
| `python -m guardian.agents run --target nodegoat --out runs/d1s8` | run_discovery → run_detection → list → 10× get → submit. 10 accepted. `verify_run(runs/d1s8)`: **10,127/10,127** |
| `uv run --locked ruff check .` / `ruff format --check .` | All checks passed / 75 files formatted |
| `uv run --locked pytest` | **223 passed** (201 earlier plus 22 agent tests; the integration test now also runs agents on real data) |

### New coverage (tests/test_agents.py)

- **Gate:** accepts grounded text. Rejects a foreign cited ID, a foreign mentioned ID, invented
  CVE and GHSA IDs, a foreign `pkg@version`, an unreported version, a missing reachability
  word, an unknown finding and schema errors. Ignores CVSS/EPSS decimals and allows fix
  versions.
- **Tools:** list clamped to `max_findings`; excerpts returned as `untrusted_excerpt`; unknown
  ID; accepted and rejected rows stored; 3-attempt cap.
- **Orchestrator:** the main graph exposes exactly {`task`, `read_file`}; the allow-list
  middleware blocks `write_file` without running it.
- **End-to-end runs:** scripted analyze (2/2 accepted, dev-only stated) and hallucinating (all
  rejected). Full mode calls discovery then detection and adopts the stored run.
- **Providers:** refusal without the opt-in, a missing package, an unknown provider, and the
  scripted provider key.
- **Store:** v1 → v2 migration.
- **Integration:** the scripted agents explain 8 findings of a real NodeGoat run with no blocked
  calls.

### Problems found and fixed

- **Dropped noqa:** `ruff --fix` (RUF100) removed a justified `# noqa: S603` from the runner's
  `subprocess.run`, which re-triggered S603. Restored.
- **Format-sensitive edit:** a store edit was anchored on pre-format text, so the assertion
  stopped it before writing. It was re-applied on the formatted text.

### Limits

- **No real LLM yet:** no real model has been called, so explanation quality from a real LLM is
  untested. The gate, tools and graph are tested with the scripted model only.
- **Gate scope:** the gate checks identifiers, versions, citations and the reachability word.
  It doesn't judge whether prose reasoning is sound. Claims without identifiers (for example
  "this is easy to exploit") are not machine-checked.
- **Global profile registry:** the harness-profile registry is process-global. The profile is
  registered per provider key before each build.

Database restoration completed:

- Trivy succeeded with the longer timeout: database v2, updated
  2026-11-23T07:04:04.632673631Z, about 1.7 GB expanded.
- Grype database update succeeded; about 3.4 GB expanded.
- OSV loaded the cached npm all.zip (about 212 MB). Its exit 1 means findings
  present; the database-load message confirms download completion.
- Kernel-isolated Trivy preflight over the actual NodeGoat target: 325 vulnerability
  records across 133 distinct package/version pairs; raw output saved as
  runs/demo-deepseek/trivy-preflight.json. Full correlation and verification pending.

Real baseline and local UI acceptance (this checkout):

- `.venv/bin/python -m guardian.scan baseline --target nodegoat --out runs/demo-deepseek`:
  exit 0; **415 findings**, including 324 dependency findings (93 runtime / 231 dev-only),
  70 image-package findings, and 21 anomaly/posture findings. Raw matches: Grype 340,
  Trivy 325, OSV 313. No unmapped findings; 1,471 evidence records.
- Independent verification: **10,127/10,127 cited facts resolved (100%)**.
- Risk bands: Critical 1 (confirmed-malicious override), Medium 97, Low 317.
  Scanner severity labels are distinct from computed risk bands.
- SQLite `PRAGMA integrity_check`: ok; `foreign_key_check`: no rows.
  Explanations table is empty. No live LLM explanation has been generated.
- `timeout 120 .venv/bin/pytest tests/test_baseline_integration.py::test_nodegoat_offline_baseline -q`:
  **1 passed in 25.72s**. This test uses an explicit offline model fixture in a
  separate test database; its explanations are not demo data.
- API bind initially refused inside sandbox. Approved loopback launch succeeded:
  `.venv/bin/python -m guardian.api --host 127.0.0.1 --port 8000`.
- Actual HTTP checks: UI, `/api/runs`, findings list, evidence card,
  `/api/graph/F-001`, and checklist return 200; required security headers present.
  Runs endpoint returns the real demo run with 415 findings; explanation is null.
  An initial probe used a nonexistent `/api/graph` route (404); corrected to the
  documented `/api/graph/{fid}` route without an application change.
- Checklist: **8 pass / 2 fail / 2 n/a**. Pending: live grounded explanations and
  README.md (not included in this approved scope). No complete Day 1 claim.
- No browser visual inspection performed; UI build and actual HTTP/API serving verified.
- Live five-finding DeepSeek run remains pending secure key entry. The user's
  approval covers this run; no additional implementation approval is requested.


## Live DeepSeek acceptance and requested .env cleanup (2026-11-23)

Authorization: original five-finding live demo approval, selected `deepseek-flash`,
then explicit instruction to use the credential in `.env` and remove that file.

- The source had one non-comment credential assignment with a noncanonical label.
  Canonical-name-only preflight refused it without printing or deleting anything.
  The single assignment's value was then safely parsed without shell evaluation,
  mapped to `DEEPSEEK_API_KEY` in a child environment, and `.env` removed. No key,
  fingerprint, or raw credential content was logged or written to another file.
- Live analysis against `runs/demo-deepseek` with `deepseek:deepseek-flash`, limit 5:
  **exit 0, 5 accepted, 0 rejected attempts, 0 blocked tool calls, 7 specialist-tool
  calls**. Captured output was redacted by the runner before display. The runner
  discarded its key reference after the child exited; future processes need fresh
  key entry. No production source or dependencies changed for this cleanup.
- Revalidated every exported explanation with `gate()` against the actual findings:
  **5/5 accepted**. Export explicitly records `generator: language model` and the
  requested provider/model. The SQLite store contains exactly five accepted
  explanations for this run, all `deepseek:deepseek-flash`.
- Independent raw-evidence verification: **10,127/10,127**, zero failures.
- SQLite integrity: **ok**. Filesystem check: `.env` is absent.
- HTTP `/api/findings/F-001?run=runs%2Fdemo-deepseek`: **200**, actual DeepSeek
  provider/model and language-model generator served to the existing UI.
- HTTP checklist: **200**, **9 pass / 1 fail / 2 n/a**. Item 9 (grounded AI
  recommendations) passes. Only item 12 (README.md) remains failed, outside this
  approved scope. No full Day 1 submission-completion claim.
- Relevant earlier verification remains valid: 245-test available suite, separate
  real-baseline integration, production UI build, Ruff and lockfile checks.
- Approved demo scope is complete. No repository remediation, deployment,
  publication, merge, or alternate provider was performed.

## Publication preflight: bharathsooryaa/temp (2026-11-23)

- User explicitly authorized pushing current source first; setup launchers deferred.
- Destination ls-remote succeeded and advertised no branches.
- 88 source candidates inspected; ignored generated/cache/secret paths excluded.
- Credential-pattern inspection found no flags in candidate files; no matched raw
  values printed. Dotenv files have no tracked history.
- Existing history inspected before publication; no credential-pattern flags.
- Configured Git author identity available. Existing main at f46179b is preserved.
- Ruff and Git diff whitespace checks pass. No code changed in this publication
  step; earlier implementation tests remain applicable.
- Commit and remote-push verification outcomes follow after execution.
