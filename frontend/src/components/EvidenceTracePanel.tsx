import { useEffect, useState } from "react";
import { api } from "../../lib/api";

const labels: Record<string, string> = {
  OBSERVATION: "Observation",
  PROVIDER_RESULT: "Provider result",
  NORMALIZED_INDICATOR: "Normalized indicator",
  FINDING: "Finding",
  REPORT_REVISION: "Report revision",
  CANONICAL_COMMITMENT: "Canonical commitment",
  APPEND_ONLY_LEDGER_EVENT: "Append-only ledger event",
  BLOCKCHAIN_ANCHOR: "Optional blockchain anchor",
};

function statusClass(status: string) {
  return status === "RECORDED" ? "text-emerald-300" : status === "NOT_ANCHORED" || status === "NOT_CREATED" ? "text-slate-400" : "text-amber-300";
}

export default function EvidenceTracePanel({ scanId }: { scanId?: number }) {
  const [value, setValue] = useState(scanId ? String(scanId) : "");
  const [chain, setChain] = useState<any>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (scanId) { setValue(String(scanId)); load(scanId); } }, [scanId]);
  async function load(id = Number(value)) {
    if (!id) { setError("Enter a scan ID."); return; }
    setBusy(true); setError("");
    try { setChain(await api(`/scans/${id}/evidence-chain`)); }
    catch (err: any) { setChain(undefined); setError(err.message || "Evidence chain could not be loaded"); }
    finally { setBusy(false); }
  }

  return <section className="glass rounded-3xl border border-cyan/20 p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-xl font-semibold">Evidence and provenance chain</h2><p className="mt-1 max-w-3xl text-sm text-slate-400">Observation → provider result → normalized indicator → finding → report revision → commitment → ledger → optional blockchain anchor. Each stage is sourced from persisted records.</p></div>
      <span className="text-xs text-cyan">Evidence-first verification</span>
    </div>
    <div className="mt-4 flex flex-wrap gap-2"><input value={value} onChange={(e) => setValue(e.target.value)} inputMode="numeric" placeholder="Scan ID" className="rounded border border-line bg-black/20 px-3 py-2 text-sm" /><button type="button" onClick={() => load()} disabled={busy} className="rounded bg-cyan px-3 py-2 text-sm font-semibold text-ink">{busy ? "Loading..." : "Trace evidence"}</button></div>
    {error && <p className="mt-3 text-sm text-red-300">{error}</p>}
    {!chain ? <p className="mt-5 text-sm text-slate-500">Load a persisted scan to inspect its evidence chain. Missing later stages remain explicitly uncreated or unanchored.</p> : <>
      <div className="mt-5 rounded-xl border border-line p-4 text-xs text-slate-400"><div className="flex flex-wrap justify-between gap-2"><span>Scan #{chain.scan_id} · {chain.target}</span><span>Observed: {chain.observed_at ? new Date(chain.observed_at).toLocaleString() : "Unknown"}</span></div><div className="mt-2">Freshness: {chain.freshness?.policy}</div></div>
      <div className="mt-4 grid gap-3 md:grid-cols-2">{(chain.stages || []).map((stage: any) => <article key={stage.stage} className="rounded-xl border border-line p-4"><div className="flex items-center justify-between gap-3"><h3 className="text-sm font-semibold">{labels[stage.stage] || stage.stage}</h3><span className={`text-xs font-semibold ${statusClass(stage.status)}`}>{stage.status}</span></div><p className="mt-2 text-xs text-slate-500">{stage.explanation}</p><div className="mt-3 text-xs text-slate-400">{stage.items?.length || 0} persisted record{stage.items?.length === 1 ? "" : "s"}</div>{stage.items?.slice(0, 3).map((item: any, index: number) => <details key={item.id || index} className="mt-2 rounded border border-line/70 p-2"><summary className="cursor-pointer text-xs text-cyan">Evidence record {item.id || item.revision_id || index + 1}</summary><pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all text-[10px] text-slate-500">{JSON.stringify(item, null, 2)}</pre></details>)}</article>)}</div>
      <div className="mt-4 rounded-xl border border-line p-4 text-xs text-slate-400">Risk conclusion: <span className="text-slate-200">{chain.risk?.level || "UNKNOWN"}</span> · score {chain.risk?.score ?? "UNKNOWN"}. This conclusion is displayed with its available provider, indicator and finding evidence; missing evidence is not treated as clean.</div>
    </>}
  </section>;
}
