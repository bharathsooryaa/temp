# LLM providers

## Current real-demo setup (2026-11-23)

The production model module no longer contains a scripted model. Historical scripted
results below remain historical; the fixture now lives only under `tests/`.
The CLI requires explicit `--provider` and `--model`. For the approved demo the user
selected `--provider deepseek --model deepseek-flash`, with at most five findings.

Installed: langchain-deepseek 1.2.0, langchain-openai 1.8.0, openai 3.51.0.
DeepSeek reads `DEEPSEEK_API_KEY`; a missing key fails before client construction.
`GUARDIAN_ALLOW_EXTERNAL_MODELS=1` and user authorization remain required.
The approved live run completed: **5/5 accepted explanations**, no rejected
attempts, no blocked tool calls. The user provided the key in `.env` and explicitly
requested migration/removal. A one-time runner parsed that assignment as data,
loaded `DEEPSEEK_API_KEY` into the child environment, deleted `.env`, and discarded
the in-memory credential on exit. No persistent replacement was created.
Future processes require a fresh environment variable or hidden terminal prompt
(RUN.md); they do not automatically retain the key from this completed run.

DeepSeek requests use a 60-second timeout, zero automatic retries and a 2,048-token
output limit. These do not enforce a dollar budget. The existing DeepInfra adapter
is preserved, but it is not selected or authorized as a fallback for this demo.

Status on 2026-11-23: **the real DeepSeek Flash demo has completed successfully**.
Earlier agent test runs used an explicitly injected offline fixture.

## Policy

- **One interface:** all model access goes through `guardian.agents.models.build_model(ModelConfig)`.
  Agents, tools and the gate are provider-independent.
- **External calls are off by default.** A real provider is built only when both of these hold:
  1. The user has authorized that provider, and the data it will receive (finding facts and
     evidence excerpts, which can include repository text).
  2. `GUARDIAN_ALLOW_EXTERNAL_MODELS=1` is set in the environment of that run.

  Otherwise `build_model` raises `ModelDisabledError` and the CLI exits with code 2.
- **API keys:** keys are read by each provider SDK from its usual environment variable, set
  outside the workspace. Guardian never reads, logs, stores or exports them.
- **No silent fallback:** there is no fallback to a different provider when one fails.
- **Capabilities:** a model must support tool calling. Structured output, streaming and pricing
  are not assumed. Explanations come back through a tool call and are validated by the
  deterministic gate, whatever model wrote them.
- **Tracing:** LangSmith tracing is forced off (`LANGSMITH_TRACING=false`) unless the user
  explicitly sets it.

## Providers

| `--provider` | Backed by | Package | Installed | Notes |
|---|---|---|---|---|
| `scripted` / `scripted-hallucinating` | Test-only fixture | none | tests only | Not selectable by production provider construction |
| `anthropic` | `init_chat_model(..., model_provider="anthropic")` | `langchain-anthropic` 1.7.10 | yes (pulled in by deepagents) | Needs `ANTHROPIC_API_KEY` |
| `google_genai` | `init_chat_model(..., model_provider="google_genai")` | `langchain-google-genai` 4.5.0 | yes (pulled in by deepagents) | Needs a Google API key |
| `openai` | `init_chat_model(..., model_provider="openai")` | `langchain-openai` | yes (DeepSeek transitive dependency) | Not authorized for this demo |
| `deepseek` | `init_chat_model(..., model_provider="deepseek")` | `langchain-deepseek` 1.2.0 | yes | Approved model: `deepseek-flash`; needs `DEEPSEEK_API_KEY` |
| `ollama` | `init_chat_model(..., model_provider="ollama")` | `langchain-ollama` | **no**: needs approval | Local; still requires the opt-in |
| `openai_compatible` | OpenAI client with `--base-url` | `langchain-openai` | yes (DeepSeek transitive dependency) | Custom endpoints require their own authorization |

## Example (only after authorization)

```bash
export ANTHROPIC_API_KEY=...            # set outside the workspace, never committed
GUARDIAN_ALLOW_EXTERNAL_MODELS=1 uv run --locked python -m guardian.agents analyze \
  --run runs/d1s7 --provider anthropic --model <model-id> --limit 5
```

Paid calls cost money and send finding data to the provider. Each provider and model choice
needs explicit user approval before its first use.
