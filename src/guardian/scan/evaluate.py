"""Seeded ground-truth evaluation (PDF section 6, "Validation and evaluation").

* Recall: an expected item is detected when a seeded-run finding has the same type, the same
  component name (if given) and the rule (if given) among its advisory_ids.
* Precision is over *new* anomaly/posture findings: those in the seeded run with no
  counterpart in the clean run. A new finding is a true positive when it concerns something the
  seeding changed (a seeded component, or a seeded rule).
* Anomaly/posture findings that also appear in the clean run are reported separately for
  manual review. They are real signals or false positives in the unmodified app.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path

from guardian.sbom.build import load_target
from guardian.schemas.finding import FindingSet, FindingType
from guardian.tools.runner import jail

ANOMALY_TYPES = frozenset(
    {
        FindingType.TYPOSQUAT,
        FindingType.INSTALL_SCRIPT,
        FindingType.LOCKFILE_CHANGE,
        FindingType.UNEXPECTED_DEPENDENCY,
        FindingType.UNTRUSTED_IMAGE,
        FindingType.UNPINNED_CI,
        FindingType.MISCONFIGURATION,
    }
)
# Components the seeding script changed, beyond those named in the expected list.
EXTRA_SEEDED_COMPONENTS = frozenset({"dont-sniff-mimetype"})


def _signature(f, target_path: str) -> tuple:
    """Finding identity across runs. File-path components drop the target's own prefix."""
    name = f.component.name.removeprefix(target_path.rstrip("/") + "/")
    return (f.type.value, name, f.component.version, f.advisory_ids)


def seeded_changes(clean_root: str, seeded_root: str) -> dict[str, set[int] | None]:
    """Workspace paths of seeded files mapped to the line numbers the seeding changed or added.

    ``None`` means the whole file is new. Computed with difflib, so no git command is run.
    """
    changes: dict[str, set[int] | None] = {}
    seeded = jail(seeded_root)
    for path in sorted(p for p in seeded.rglob("*") if p.is_file() and ".git" not in p.parts):
        rel = path.relative_to(seeded).as_posix()
        twin = jail(clean_root) / rel
        ws = f"{seeded_root.rstrip('/')}/{rel}"
        new_lines = path.read_text(errors="replace").splitlines()
        if not twin.exists():
            changes[ws] = None
            continue
        old_lines = twin.read_text(errors="replace").splitlines()
        lines = set()
        matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
        for tag, _, _, j1, j2 in matcher.get_opcodes():
            if tag != "equal":
                lines |= set(range(j1 + 1, j2 + 1)) or {max(j1, 1)}
        if lines:
            changes[ws] = lines
    return changes


def _touches(f, fs: FindingSet, changes: dict[str, set[int] | None]) -> bool:
    store = {r.id: r for r in fs.evidence}
    for ref in f.evidence:
        rec = store[ref.evidence_id]
        if rec.file in changes:
            lines = changes[rec.file]
            if lines is None or rec.line is None or rec.line in lines:
                return True
    return False


def _matches(f, item: dict) -> bool:
    return (
        f.type.value == item["type"]
        and ("component" not in item or f.component.name == item["component"])
        and ("rule" not in item or item["rule"] in f.advisory_ids)
    )


def evaluate(seeded_dir: str | Path, clean_dir: str | Path, truth_file: str | Path) -> dict:
    seeded = FindingSet.model_validate_json((jail(seeded_dir) / "findings.json").read_text())
    clean = FindingSet.model_validate_json((jail(clean_dir) / "findings.json").read_text())
    truth = json.loads(jail(truth_file).read_text())

    detected = []
    for item in truth["expected"]:
        hits = [f.id for f in seeded.findings if _matches(f, item)]
        detected.append({**item, "detected": bool(hits), "findings": hits})

    seeded_target, base_target = load_target(truth["target"]), load_target(truth["base_target"])
    clean_sigs = {_signature(f, base_target["path"]) for f in clean.findings}
    changes = seeded_changes(base_target["path"], seeded_target["path"])
    seeded_components = {
        i["component"] for i in truth["expected"] if "component" in i and i["id"].startswith("S")
    } | EXTRA_SEEDED_COMPONENTS
    seeded_rules = {i["rule"] for i in truth["expected"] if "rule" in i and i["id"].startswith("S")}
    new = [
        f
        for f in seeded.findings
        if f.type in ANOMALY_TYPES and _signature(f, seeded_target["path"]) not in clean_sigs
    ]
    tp = [
        f
        for f in new
        if f.component.name in seeded_components
        or seeded_rules & set(f.advisory_ids)
        or _touches(f, seeded, changes)
    ]
    fp = [f for f in new if f not in tp]
    seeded_items = [d for d in detected if d["id"].startswith("S")]
    real_items = [d for d in detected if d["id"].startswith("R")]

    def brief(f) -> dict:
        return {
            "id": f.id,
            "type": f.type.value,
            "component": f"{f.component.name}@{f.component.version}",
            "rules": list(f.advisory_ids),
            "title": f.title,
        }

    return {
        "truth": jail(truth_file).relative_to(jail(".")).as_posix(),
        "seeded_recall": f"{sum(d['detected'] for d in seeded_items)}/{len(seeded_items)}",
        "real_recall": f"{sum(d['detected'] for d in real_items)}/{len(real_items)}",
        "new_anomaly_findings": len(new),
        "seeded_files_changed": sorted(changes),
        "precision_on_new": f"{len(tp)}/{len(new)}" if new else "n/a",
        "items": detected,
        "false_positives_new": [brief(f) for f in fp],
        "clean_run_anomaly_findings": [brief(f) for f in clean.findings if f.type in ANOMALY_TYPES],
    }
