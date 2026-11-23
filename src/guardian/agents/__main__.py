"""CLI:
  python -m guardian.agents analyze --run runs/demo-deepseek \
      --provider deepseek --model deepseek-flash --limit 5
  python -m guardian.agents run --target nodegoat --out runs/demo-deepseek \
      --provider deepseek --model deepseek-flash --limit 5
Both require an explicit live --provider/--model, and only run with
GUARDIAN_ALLOW_EXTERNAL_MODELS=1 (see LLM_PROVIDERS.md).
"""

from __future__ import annotations

import argparse
import json
import sys

from guardian.agents.gate import Explanation
from guardian.agents.models import ModelConfig, ModelDisabledError
from guardian.agents.orchestrator import run_agents
from guardian.agents.tools import AgentContext, write_trace
from guardian.store import DEFAULT_DB, accepted_explanations, connect, load_findings
from guardian.tools.runner import jail, workspace_relative


def export(ctx: AgentContext, cfg: ModelConfig, outcome: dict) -> dict:
    """Write explanations.json/.md for the run. Every rationale is re-validated on Finding."""
    out = jail(ctx.out_dir)
    conn = connect(ctx.db)
    try:
        fs = load_findings(conn, ctx.run_id)
        accepted = accepted_explanations(conn, ctx.run_id)
        rejected = conn.execute(
            "SELECT finding_id, attempt, reasons_json FROM explanations "
            "WHERE run_id = ? AND status = 'rejected' ORDER BY finding_id, attempt",
            (ctx.run_id,),
        ).fetchall()
    finally:
        conn.close()
    by_id = {f.id: f for f in fs.findings}
    items = []
    for fid in sorted(accepted, key=lambda i: [f.id for f in fs.findings].index(i)):
        exp = Explanation.model_validate(accepted[fid])
        f = by_id[fid]
        explained = type(f).model_validate({**f.model_dump(), "rationale": exp.rationale()})
        items.append(
            {
                "finding_id": fid,
                "risk": f.risk.model_dump(mode="json") if f.risk else None,
                "explanation": exp.model_dump(mode="json"),
                "rationale": explained.rationale,
            }
        )
    scripted = cfg.provider.startswith("scripted")
    doc = {
        "run_id": ctx.run_id,
        "provider": cfg.provider,
        "model": cfg.model,
        "generator": "offline scripted template (not an LLM)" if scripted else "language model",
        "accepted": items,
        "rejected": [
            {"finding_id": r[0], "attempt": r[1], "reasons": json.loads(r[2])} for r in rejected
        ],
        "blocked_tool_calls": outcome["blocked_tool_calls"],
        "final_message": outcome["final"],
    }
    (out / "explanations.json").write_text(json.dumps(doc, indent=2) + "\n")
    (out / "explanations.md").write_text(render(doc, by_id))
    write_trace(ctx, out / "agent-trace.json", {"provider": cfg.provider, "model": cfg.model})
    return doc


def render(doc: dict, by_id: dict) -> str:
    lines = [
        f"# AI explanations: {doc['run_id']}",
        "",
        f"Generator: **{doc['generator']}** ({doc['provider']}:{doc['model']}). Each "
        "explanation passed the deterministic gate; rejected ones are listed, never shown "
        "as explanations.",
        "",
    ]
    for item in doc["accepted"]:
        f, e, r = by_id[item["finding_id"]], item["explanation"], item["risk"] or {}
        lines += [
            f"## {f.id} {f.title}",
            "",
            f"- Risk: {r.get('score')} {r.get('level')} (coverage {r.get('weight_coverage')})",
            f"- Path: {' > '.join(f.dependency_path) or 'n/a'}",
            f"- Why it matters: {e['why_it_matters']}",
            f"- Reachability: {e['reachability']}",
            f"- Confidence: {e['confidence']} ({e['confidence_reason']})",
            f"- Evidence: {', '.join(e['cited_evidence'])}",
            "",
        ]
    if doc["rejected"]:
        lines += ["## Rejected by the gate", ""]
        lines += [
            f"- {r['finding_id']} attempt {r['attempt']}: {'; '.join(r['reasons'])}"
            for r in doc["rejected"]
        ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="guardian.agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("analyze", "run"):
        s = sub.add_parser(name)
        s.add_argument("--db", default=DEFAULT_DB)
        s.add_argument("--provider", required=True)
        s.add_argument("--model", required=True)
        s.add_argument("--base-url")
        s.add_argument("--limit", type=int, default=5)
        if name == "analyze":
            s.add_argument("--run", required=True, help="stored run id, e.g. runs/d1s7")
        else:
            s.add_argument("--target", required=True)
            s.add_argument("--out", required=True)
    a = p.parse_args(argv)
    if not 1 <= a.limit <= 5:
        p.error("--limit must be between 1 and 5 for the live demo")
    cfg = ModelConfig(provider=a.provider, model=a.model, base_url=a.base_url)

    if a.cmd == "analyze":
        run_id = workspace_relative(jail(a.run))
        summary = json.loads((jail(run_id) / "baseline.json").read_text())
        ctx = AgentContext(
            target=summary["target"]["name"],
            out_dir=run_id,
            db=a.db,
            provider=cfg.provider,
            model=cfg.model,
            run_id=run_id,
            max_findings=a.limit,
        )
        mode = "analyze"
    else:
        from guardian.sbom.build import build as build_sbom
        from guardian.scan.baseline import baseline

        out = workspace_relative(jail(a.out))
        jail(out).mkdir(parents=True, exist_ok=True)
        ctx = AgentContext(
            target=a.target,
            out_dir=out,
            db=a.db,
            provider=cfg.provider,
            model=cfg.model,
            max_findings=a.limit,
            discover=build_sbom,
            detect=lambda t, o, d: baseline(t, o, db=d),
        )
        mode = "full"
    try:
        outcome = run_agents(ctx, cfg, mode)
    except ModelDisabledError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if ctx.run_id is None:
        print("no stored run was produced", file=sys.stderr)
        return 1
    doc = export(ctx, cfg, outcome)
    print(f"Agents   {ctx.provider}:{ctx.model} ({doc['generator']}) on {ctx.run_id}")
    print(
        f"Accepted {len(doc['accepted'])}  rejected attempts {len(doc['rejected'])}  "
        f"blocked tool calls {len(outcome['blocked_tool_calls'])}  tool calls "
        f"{outcome['tool_calls']}"
    )
    print(f"Final    {outcome['final'][:200]}")
    print(f"Output   {ctx.out_dir}/explanations.md")
    return 0 if doc["accepted"] and not outcome["blocked_tool_calls"] else 1


if __name__ == "__main__":
    sys.exit(main())
