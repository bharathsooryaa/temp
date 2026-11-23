import { useEffect, useState } from "react";
import {
  api,
  type Checklist,
  type FindingDetail,
  type FindingRow,
  type GraphElements,
  type RunInfo,
} from "./api";
import { EvidenceCard, LevelBadge } from "./EvidenceCard";

const TYPES = [
  "", "malicious_package", "vulnerable_direct", "vulnerable_transitive", "vulnerable_image_package",
  "typosquat", "install_script", "lockfile_change", "unexpected_dependency", "untrusted_image",
  "unpinned_ci", "misconfiguration",
];
const LEVELS = ["", "Critical", "High", "Medium", "Low"];
const STATUS_STYLE: Record<string, string> = {
  pass: "bg-green-100 text-green-800",
  fail: "bg-red-100 text-red-800",
  "n/a": "bg-slate-100 text-slate-600",
};

export default function App() {
  const [runs, setRuns] = useState<RunInfo[]>([]);
  const [run, setRun] = useState("");
  const [filters, setFilters] = useState({ type: "", level: "", q: "" });
  const [rows, setRows] = useState<{ total: number; items: FindingRow[] }>({ total: 0, items: [] });
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [graph, setGraph] = useState<GraphElements | null>(null);
  const [checklist, setChecklist] = useState<Checklist | null>(null);
  const [tab, setTab] = useState<"findings" | "checklist">("findings");
  const [error, setError] = useState("");

  useEffect(() => {
    api.runs().then((r) => {
      setRuns(r);
      if (r[0]) setRun(r[0].run_id);
    }).catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!run) return;
    api.findings(run, { ...filters, limit: 200 }).then((r) => {
      setRows(r);
      setSelected((current) => (r.items.some((i) => i.id === current) ? current : (r.items[0]?.id ?? "")));
    }).catch((e: Error) => setError(e.message));
  }, [run, filters]);

  useEffect(() => {
    if (!run) return;
    setChecklist(null);
    api.checklist(run).then(setChecklist).catch((e: Error) => setError(e.message));
  }, [run]);

  useEffect(() => {
    if (!run || !selected) {
      setDetail(null);
      return;
    }
    setGraph(null);
    api.finding(run, selected).then(setDetail).catch((e: Error) => setError(e.message));
    api.graph(run, selected).then(setGraph).catch((e: Error) => setError(e.message));
  }, [run, selected]);

  const current = runs.find((r) => r.run_id === run);
  return (
    <div className="mx-auto max-w-7xl p-4">
      <header className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold">Software Supply Chain Guardian</h1>
          <p className="text-xs text-slate-500">
            Read-only evidence view. Every value comes from tool output stored in runs/guardian.db.
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <label htmlFor="run">Run</label>
          <select id="run" className="rounded border border-slate-300 bg-white px-2 py-1" value={run}
                  onChange={(e) => setRun(e.target.value)}>
            {runs.map((r) => (
              <option key={r.run_id} value={r.run_id}>
                {r.run_id} · {r.target}{r.synthetic ? " (SYNTHETIC)" : ""}
              </option>
            ))}
          </select>
        </div>
      </header>
      {error && <div className="mb-3 rounded bg-red-50 p-2 text-sm text-red-800">{error}</div>}
      {current && (
        <section className="mb-4 flex flex-wrap gap-4 text-sm">
          <div className="rounded border border-slate-200 bg-white px-3 py-2">
            <div className="text-xs text-slate-500">Commit</div>
            <code>{current.commit.slice(0, 12)}</code>
          </div>
          <div className="rounded border border-slate-200 bg-white px-3 py-2">
            <div className="text-xs text-slate-500">Findings</div>
            {current.findings}
          </div>
          <div className="rounded border border-slate-200 bg-white px-3 py-2">
            <div className="text-xs text-slate-500">By risk level</div>
            <div className="flex gap-1">
              {Object.entries(current.by_risk_level ?? {}).map(([level, n]) => (
                <span key={level}><LevelBadge level={level} /> {n}</span>
              ))}
            </div>
          </div>
          {checklist && (
            <div className="rounded border border-slate-200 bg-white px-3 py-2">
              <div className="text-xs text-slate-500">Day 1 checklist</div>
              {checklist.counts.pass} pass · {checklist.counts.fail} fail · {checklist.counts["n/a"]} n/a
            </div>
          )}
        </section>
      )}
      <nav className="mb-3 flex gap-2 text-sm">
        {(["findings", "checklist"] as const).map((t) => (
          <button key={t} type="button" onClick={() => setTab(t)}
                  className={`rounded px-3 py-1 ${tab === t ? "bg-slate-800 text-white" : "bg-white border border-slate-300"}`}>
            {t === "findings" ? "Findings" : "Day 1 checklist"}
          </button>
        ))}
      </nav>
      {tab === "checklist" ? (
        <ChecklistView checklist={checklist} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[22rem_1fr]">
          <aside>
            <div className="mb-2 grid grid-cols-2 gap-2 text-sm">
              <select aria-label="Type" className="rounded border border-slate-300 bg-white px-1 py-1"
                      value={filters.type} onChange={(e) => setFilters({ ...filters, type: e.target.value })}>
                {TYPES.map((t) => <option key={t} value={t}>{t ? t.replaceAll("_", " ") : "All types"}</option>)}
              </select>
              <select aria-label="Risk level" className="rounded border border-slate-300 bg-white px-1 py-1"
                      value={filters.level} onChange={(e) => setFilters({ ...filters, level: e.target.value })}>
                {LEVELS.map((l) => <option key={l} value={l}>{l || "All levels"}</option>)}
              </select>
              <input aria-label="Search" placeholder="Search package or title" maxLength={100}
                     className="col-span-2 rounded border border-slate-300 px-2 py-1" value={filters.q}
                     onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
            </div>
            <p className="mb-1 text-xs text-slate-500">
              {rows.total} findings, ranked by risk{rows.total > rows.items.length ? ` (first ${rows.items.length})` : ""}
            </p>
            <ol className="max-h-[70vh] overflow-y-auto rounded border border-slate-200 bg-white text-sm">
              {rows.items.map((r) => (
                <li key={r.id}>
                  <button type="button" onClick={() => setSelected(r.id)}
                          className={`w-full border-b border-slate-100 px-2 py-1.5 text-left ${selected === r.id ? "bg-blue-50" : "hover:bg-slate-50"}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-slate-500">{r.id}</span>
                      <LevelBadge level={r.risk_level} score={r.risk_score} />
                    </div>
                    <div className="truncate">{r.component}{r.version ? `@${r.version}` : ""}</div>
                    <div className="truncate text-xs text-slate-500">
                      {r.type.replaceAll("_", " ")}{r.explained ? " · explained" : ""}
                    </div>
                  </button>
                </li>
              ))}
            </ol>
          </aside>
          <main>{detail ? <EvidenceCard detail={detail} graph={graph} /> : <p className="text-sm text-slate-500">Select a finding.</p>}</main>
        </div>
      )}
    </div>
  );
}

function ChecklistView({ checklist }: { checklist: Checklist | null }) {
  if (!checklist) return <p className="text-sm text-slate-500">Evaluating checklist…</p>;
  return (
    <table className="w-full rounded border border-slate-200 bg-white text-sm">
      <tbody>
        {checklist.items.map((i) => (
          <tr key={i.n} className="border-t border-slate-100 align-top">
            <td className="w-8 p-2 text-slate-500">{i.n}</td>
            <td className="w-20 p-2">
              <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${STATUS_STYLE[i.status] ?? ""}`}>{i.status}</span>
            </td>
            <td className="p-2">
              <div className="font-medium">{i.text}</div>
              <div className="text-xs text-slate-500">{i.evidence}</div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
