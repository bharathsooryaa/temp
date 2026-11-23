"""CLI:  uv run --locked python -m guardian.scan baseline --target nodegoat --out runs/<name>"""

from __future__ import annotations

import argparse
import sys

from guardian.scan.baseline import baseline
from guardian.scan.verify import verify_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian.scan")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline", help="offline scanner-only baseline for a registered target")
    b.add_argument("--target", required=True)
    b.add_argument("--out", required=True)
    e = sub.add_parser("evaluate", help="score a seeded run against ground truth")
    e.add_argument("--seeded", required=True)
    e.add_argument("--clean", required=True)
    e.add_argument("--truth", default="targets/seeded-ground-truth.json")
    e.add_argument("--out")
    args = parser.parse_args(argv)
    if args.cmd == "evaluate":
        return cmd_evaluate(args)

    s = baseline(args.target, args.out)
    print(
        f"Findings {s['findings']} total; dependency findings {s['dependency_findings']} "
        f"({s['runtime_findings']} runtime, {s['dev_only_findings']} dev-only) over "
        f"{s['vulnerable_packages']} packages"
    )
    print(f"By type  {s['by_type']}")
    print(f"Severity {s['by_severity']}  KEV {s['kev_findings']}  with fix {s['with_fix']}")
    print(f"Raw      {s['raw_matches']}  groups by tool count {s['groups_by_tool_count']}")
    print(f"Unmapped {len(s['unmapped'])}  evidence records {s['evidence_records']}")
    print(f"Report   {args.out}/baseline.md")
    v = verify_run(args.out)
    print(
        f"Verify   {v.resolved}/{v.checked} cited facts resolve to raw tool output ({v.rate:.1%})"
    )
    for failure in v.failures[:20]:
        print(f"  FAIL {failure}")
    return 1 if s["unmapped"] or v.failures else 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    import json

    from guardian.scan.evaluate import evaluate
    from guardian.tools.runner import jail

    r = evaluate(args.seeded, args.clean, args.truth)
    for item in r["items"]:
        mark = "DETECTED" if item["detected"] else "MISSED  "
        print(f"{mark} {item['id']:4} {item['scenario']:42} {', '.join(item['findings'])}")
    print(
        f"Seeded recall {r['seeded_recall']}  real recall {r['real_recall']}  "
        f"precision on new anomaly findings {r['precision_on_new']}"
    )
    for fp in r["false_positives_new"]:
        print(f"  FP {fp['id']} {fp['type']} {fp['component']} {fp['rules']}")
    print(f"Clean-run anomaly/posture findings for review: {len(r['clean_run_anomaly_findings'])}")
    if args.out:
        jail(args.out).write_text(json.dumps(r, indent=2) + "\n")
    missed = [i for i in r["items"] if not i["detected"]]
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
