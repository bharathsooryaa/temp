# Real repository demo with DeepSeek

Scenario: inspect the unmodified OWASP NodeGoat repository at
`c5cb68a7084e4ae7dcc60e6a98768720a81841e8`. Scanners produce the findings, dependency
paths and risk factors. DeepSeek explains up to five findings from those facts. The
seeded target and test model fixtures are not used. This is static inspection; the
intentionally vulnerable app is never installed or started.

Run commands from this workspace root. Python must be 3.12; use `.venv/bin/python`.
Provisioning and current validation results are in SETUP.md and TEST_RESULTS.md.

Current session: step 1 completed successfully with 415 findings and 10,127/10,127
verified cited facts. The UI is already running at <http://127.0.0.1:8000>.
The approved live DeepSeek run is also complete: five explanations accepted,
zero rejected attempts and zero blocked tool calls. Refresh the UI to see them.
The user-provided `.env` was removed after the key was loaded into the live process
environment; no replacement key file was created. The key was discarded on exit.
Step 2 is for a future rerun, which needs the key entered again and may incur
additional API charges; another live rerun is not needed to view existing results.

## 1. Produce the actual scan

Once all pinned tools and database caches are restored:

```bash
.venv/bin/python -m guardian.scan baseline --target nodegoat --out runs/demo-deepseek
```

The command must exit successfully with no unmapped findings and 100% resolved
scanner citations. Inspect `runs/demo-deepseek/baseline.md`, `findings.json`, and
raw scanner JSON. Counts depend on the downloaded databases; historical counts in
PROGRESS.md are not promised results for this run. Scanners use `unshare -rn`;
do not disable this isolation if the runtime refuses it.

## 2. Generate actual DeepSeek explanations

Requires authorization for API spending and sending finding facts and repository
evidence excerpts to DeepSeek. The selected model is `deepseek-flash`. No provider
fallback is configured. External calls remain disabled unless explicitly enabled.

In a local Bash terminal, enter the key at the hidden prompt, never in a command,
chat message, `.env` file, source file, or saved log. This subshell discards it on
exit. Do not enable shell tracing (`set -x`).

```bash
(
  set +x
  read -r -s -p 'DeepSeek API key: ' DEEPSEEK_API_KEY
  printf '\n'
  export DEEPSEEK_API_KEY
  export GUARDIAN_ALLOW_EXTERNAL_MODELS=1
  export LANGSMITH_TRACING=false LANGCHAIN_TRACING_V2=false
  .venv/bin/python -m guardian.agents analyze \
    --run runs/demo-deepseek --provider deepseek --model deepseek-flash --limit 5
)
```

The model has a 60-second request timeout, no automatic request retries, and a
2,048-token output limit per request. The graph also has recursion limits. These
are execution bounds, not an enforced currency budget; use provider account
controls for a hard spending cap. A run makes multiple model requests.
DeepSeek uses its documented non-thinking tool-calling mode for this demo:
<https://api-docs.deepseek.com/guides/tool_calls/>.

Read `explanations.json`, `explanations.md`, and `agent-trace.json` in the run
directory. Accepted explanations must record `deepseek:deepseek-flash` and
`generator: language model`. Rejected explanations are recorded separately. The
gate validates identifiers, versions, evidence membership, and reachability; it
does not prove that every prose statement is sound. No live-call result has been
claimed unless it is recorded in TEST_RESULTS.md.

## 3. Show the local evidence UI

```bash
npm --prefix ui run build
.venv/bin/python -m guardian.api --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Select `runs/demo-deepseek`, inspect the ranked findings,
choose an explained finding, and follow its dependency path and evidence records.
The API docs are at <http://127.0.0.1:8000/api/docs>. Stop the server with Ctrl+C.

The UI can show scanner results before model analysis, but that is not completion
of the requested live LLM demo. The inspected container is the digest-verified
base image, not a rebuilt NodeGoat application image. Static imports do not prove
exploitability, and suspected scanner false positives must remain visible as such.
