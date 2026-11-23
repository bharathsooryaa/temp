"""Persistent evidence store (SQLite, stdlib sqlite3; approved for D1.S7).

One database (default runs/guardian.db) holds many runs. A run's rows are replaced atomically
when it is saved again. Findings round-trip exactly through their JSON column. The other
columns are for querying (score, level, type, component, rule IDs, evidence links, graph).
All SQL uses bound parameters.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from guardian.schemas.finding import FindingSet
from guardian.schemas.graph import DependencyGraph
from guardian.tools.runner import jail

DEFAULT_DB = "runs/guardian.db"
SCHEMA_VERSION = 2  # v2 (D1.S8): explanations table; v1 -> v2 is additive

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, target TEXT NOT NULL, commit_sha TEXT NOT NULL,
    generated_at TEXT NOT NULL, synthetic INTEGER NOT NULL, summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    id TEXT NOT NULL, kind TEXT NOT NULL, tool TEXT NOT NULL, tool_version TEXT, ref TEXT,
    file TEXT, line INTEGER, graph_node TEXT, excerpt TEXT, record_json TEXT NOT NULL,
    PRIMARY KEY (run_id, id)
);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    id TEXT NOT NULL, ordinal INTEGER NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL,
    component_name TEXT NOT NULL, component_version TEXT, purl TEXT, ecosystem TEXT,
    severity TEXT NOT NULL, risk_score REAL, risk_level TEXT, weight_coverage REAL,
    override TEXT, advisory_ids_json TEXT NOT NULL, dependency_path_json TEXT NOT NULL,
    finding_json TEXT NOT NULL,
    PRIMARY KEY (run_id, id)
);
CREATE TABLE IF NOT EXISTS finding_evidence (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    PRIMARY KEY (run_id, finding_id, evidence_id),
    FOREIGN KEY (run_id, finding_id) REFERENCES findings(run_id, id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, evidence_id) REFERENCES evidence(run_id, id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS graph_nodes (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    node_id TEXT NOT NULL, name TEXT NOT NULL, version TEXT, scope TEXT NOT NULL,
    direct INTEGER, optional INTEGER NOT NULL, PRIMARY KEY (run_id, node_id)
);
CREATE TABLE IF NOT EXISTS graph_edges (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
    PRIMARY KEY (run_id, source, target)
);
CREATE TABLE IF NOT EXISTS explanations (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, attempt INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('accepted', 'rejected')),
    provider TEXT NOT NULL, model TEXT NOT NULL, created_at TEXT NOT NULL,
    explanation_json TEXT NOT NULL, reasons_json TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id, attempt),
    FOREIGN KEY (run_id, finding_id) REFERENCES findings(run_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS findings_by_score ON findings(run_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS findings_by_component ON findings(run_id, component_name);
"""


def connect(db: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    path = jail(db)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    if conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "1":
        with conn:  # additive migration: SCHEMA above already created the explanations table
            conn.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    found = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    if found != str(SCHEMA_VERSION):
        raise RuntimeError(f"store schema {found} != expected {SCHEMA_VERSION}")
    return conn


def connect_readonly(db: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    """Read-only connection (SQLite URI mode=ro); writes raise sqlite3.OperationalError."""
    path = jail(db)
    if not path.exists():
        raise FileNotFoundError(f"no store at {db}")
    conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def save_run(
    conn: sqlite3.Connection, run_id: str, summary: dict, fs: FindingSet, graph: DependencyGraph
) -> None:
    t = summary["target"]
    with conn:  # one transaction: the old run is replaced atomically
        conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
            (
                run_id,
                t["name"],
                t["commit"],
                summary["generated_at"],
                int(bool(summary.get("synthetic"))),
                json.dumps(summary, sort_keys=True),
            ),
        )
        conn.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    run_id,
                    r.id,
                    r.kind.value,
                    r.tool,
                    r.tool_version,
                    r.ref,
                    r.file,
                    r.line,
                    r.graph_node,
                    r.excerpt,
                    r.model_dump_json(),
                )
                for r in fs.evidence
            ],
        )
        rows, links = [], []
        for ordinal, f in enumerate(fs.findings):
            risk = f.risk
            rows.append(
                (
                    run_id,
                    f.id,
                    ordinal,
                    f.type.value,
                    f.title,
                    f.component.name,
                    f.component.version,
                    f.component.purl,
                    f.component.ecosystem.value if f.component.ecosystem else None,
                    f.severity.value,
                    risk.score if risk else None,
                    risk.level.value if risk else None,
                    risk.weight_coverage if risk else None,
                    risk.override if risk else None,
                    json.dumps(list(f.advisory_ids)),
                    json.dumps(list(f.dependency_path)),
                    f.model_dump_json(),
                )
            )
            links += [(run_id, f.id, e.evidence_id, i) for i, e in enumerate(f.evidence)]
        conn.executemany(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows
        )
        conn.executemany("INSERT INTO finding_evidence VALUES (?, ?, ?, ?)", links)
        conn.executemany(
            "INSERT INTO graph_nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    run_id,
                    n.bom_ref,
                    n.component.name,
                    n.component.version,
                    n.scope.value,
                    None if n.direct is None else int(n.direct),
                    int(n.optional),
                )
                for n in graph.nodes
            ],
        )
        conn.executemany(
            "INSERT INTO graph_edges VALUES (?, ?, ?, ?)",
            [(run_id, e.source, e.target, e.kind.value) for e in graph.edges],
        )


def load_findings(conn: sqlite3.Connection, run_id: str) -> FindingSet:
    """Rebuild the exact FindingSet of a run. It is validated again on load."""
    from guardian.schemas.evidence import EvidenceRecord
    from guardian.schemas.finding import Finding

    evidence = tuple(
        EvidenceRecord.model_validate_json(row[0])
        for row in conn.execute(
            "SELECT record_json FROM evidence WHERE run_id = ? ORDER BY id", (run_id,)
        )
    )
    findings = tuple(
        Finding.model_validate_json(row[0])
        for row in conn.execute(
            "SELECT finding_json FROM findings WHERE run_id = ? ORDER BY ordinal", (run_id,)
        )
    )
    if not findings and not evidence:
        raise KeyError(f"no run {run_id!r} in store")
    return FindingSet(evidence=evidence, findings=findings)


def top_findings(conn: sqlite3.Connection, run_id: str, limit: int = 10) -> list[tuple]:
    return conn.execute(
        "SELECT id, risk_score, risk_level, type, component_name, component_version, title "
        "FROM findings WHERE run_id = ? ORDER BY ordinal LIMIT ?",
        (run_id, limit),
    ).fetchall()


def save_explanation(
    conn: sqlite3.Connection,
    run_id: str,
    finding_id: str,
    status: str,
    provider: str,
    model: str,
    explanation: dict,
    reasons: list[str],
) -> int:
    """Record one gated explanation attempt; returns its attempt number."""
    from datetime import UTC, datetime

    with conn:
        attempt = conn.execute(
            "SELECT COALESCE(MAX(attempt), 0) + 1 FROM explanations "
            "WHERE run_id = ? AND finding_id = ?",
            (run_id, finding_id),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO explanations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                finding_id,
                attempt,
                status,
                provider,
                model,
                datetime.now(UTC).isoformat(timespec="seconds"),
                json.dumps(explanation, sort_keys=True),
                json.dumps(reasons),
            ),
        )
    return attempt


def accepted_explanations(conn: sqlite3.Connection, run_id: str) -> dict[str, dict]:
    """Latest accepted explanation per finding."""
    rows = conn.execute(
        "SELECT finding_id, explanation_json FROM explanations e WHERE run_id = ? "
        "AND status = 'accepted' AND attempt = (SELECT MAX(attempt) FROM explanations x "
        "WHERE x.run_id = e.run_id AND x.finding_id = e.finding_id AND x.status = 'accepted')",
        (run_id,),
    ).fetchall()
    return {fid: json.loads(js) for fid, js in rows}
