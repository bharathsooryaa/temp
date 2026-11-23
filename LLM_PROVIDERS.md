# LLM providers

Status on 2026-11-23: **no external model has been called.** All agent runs used the offline
scripted model.

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
| `scripted` (default) | `ScriptedModel` in this repo | none | yes | Offline, deterministic template. **Not an LLM**; labelled as such in every output |
| `scripted-hallucinating` | `ScriptedModel(mode="hallucinate")` | none | yes | Test fixture that invents an advisory and a citation. The gate must reject all of it |
| `anthropic` | `init_chat_model(..., model_provider="anthropic")` | `langchain-anthropic` 1.7.10 | yes (pulled in by deepagents) | Needs `ANTHROPIC_API_KEY` |
| `google_genai` | `init_chat_model(..., model_provider="google_genai")` | `langchain-google-genai` 4.5.0 | yes (pulled in by deepagents) | Needs a Google API key |
| `openai` | `init_chat_model(..., model_provider="openai")` | `langchain-openai` | **no**: adding it needs approval | |
| `deepseek` | `init_chat_model(..., model_provider="deepseek")` | `langchain-deepseek` | **no**: needs approval | |
| `ollama` | `init_chat_model(..., model_provider="ollama")` | `langchain-ollama` | **no**: needs approval | Local; still requires the opt-in |
| `openai_compatible` | OpenAI client with `--base-url` | `langchain-openai` | **no**: needs approval | Custom endpoints |

## Example (only after authorization)

```bash
export ANTHROPIC_API_KEY=...            # set outside the workspace, never committed
GUARDIAN_ALLOW_EXTERNAL_MODELS=1 uv run --locked python -m guardian.agents analyze \
  --run runs/d1s7 --provider anthropic --model <model-id> --limit 10
```

Paid calls cost money and send finding data to the provider. Each provider and model choice
needs explicit user approval before its first use.
