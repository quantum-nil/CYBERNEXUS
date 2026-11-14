type BLHScanPanelProps = { data?: any };

const tone: Record<string, string> = {
  CRITICAL: "text-danger border-danger/40 bg-danger/10",
  HIGH: "text-danger border-danger/30 bg-danger/5",
  MEDIUM: "text-amber-300 border-amber-300/30 bg-amber-300/5",
  LOW: "text-emerald-300 border-emerald-300/20 bg-emerald-300/5",
};

export default function BLHScanPanel({ data }: BLHScanPanelProps) {
  const blh = data?.blh;
  if (!blh) return null;
  const summary = blh.summary || {};
  const links = blh.external_links || [];
  const findings = blh.findings || [];
  const level = String(summary.risk_level || "LOW").toUpperCase();
  const unavailable = blh.status === "UNAVAILABLE" || blh.status === "BLOCKED";

  return (
    <section className="mt-5 rounded-2xl border border-line bg-black/20 p-4" aria-labelledby="blh-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[10px] uppercase tracking-[.2em] text-cyan">External resource intelligence</div>
          <h3 id="blh-heading" className="mt-1 text-base font-semibold">Broken links & dangling-host detection</h3>
          <p className="mt-1 text-xs text-slate-400">Evidence-only analysis of external assets; scripts are never executed and domains are never claimed.</p>
        </div>
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${tone[level] || tone.LOW}`}>{level} · {summary.risk_score ?? 0}/100</span>
      </div>

      {unavailable ? (
        <div className="mt-4 rounded-xl border border-amber-300/20 bg-amber-300/5 p-3 text-xs text-amber-200">
          BLH analysis is {String(blh.status || "unavailable").toLowerCase()}; missing evidence is not treated as clean.
          {blh.error ? <span className="ml-1 text-slate-400">{blh.error}</span> : null}
        </div>
      ) : (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-4">
            <Metric label="External links" value={summary.total ?? links.length} />
            <Metric label="Broken" value={summary.broken ?? 0} danger={summary.broken > 0} />
            <Metric label="Dangling DNS" value={summary.dangling ?? summary.nxdomain ?? 0} danger={summary.dangling > 0 || summary.nxdomain > 0} />
            <Metric label="Takeover signals" value={summary.potential_takeover ?? 0} danger={summary.potential_takeover > 0} />
          </div>
          {findings.length > 0 && <div className="mt-4 space-y-2">
            {findings.map((finding: any, index: number) => (
              <div key={`${finding.type}-${finding.url}-${index}`} className="rounded-lg border border-danger/20 bg-danger/5 p-3 text-xs">
                <div className="flex flex-wrap justify-between gap-2"><span className="font-semibold text-danger">{String(finding.type || "Finding").replaceAll("_", " ")}</span><span className="text-slate-400">{finding.severity || "UNKNOWN"}</span></div>
                <div className="mt-1 break-all text-slate-400">{finding.url}</div>
                {finding.provider ? <div className="mt-1 text-slate-500">Provider fingerprint: {finding.provider}</div> : null}
                {finding.evidence ? <div className="mt-1 text-slate-500">Evidence: {finding.evidence}</div> : null}
              </div>
            ))}
          </div>}
          <div className="mt-4 space-y-2">
            {links.length === 0 ? <p className="text-xs text-slate-500">No external HTTP(S) resources were discovered.</p> : links.map((item: any, index: number) => (
              <details key={`${item.url}-${index}`} className="rounded-xl border border-line p-3">
                <summary className="cursor-pointer list-none text-xs"><span className={item.broken ? "text-danger" : "text-slate-200"}>{item.status ?? "UNKNOWN"}</span><span className="ml-3 break-all">{item.url}</span><span className="float-right text-slate-500">{item.claimability?.status || "OBSERVED"}</span></summary>
                <div className="mt-3 grid gap-2 text-xs text-slate-400 md:grid-cols-2">
                  <span>Final URL: <b className="break-all text-slate-300">{item.final_url || item.url}</b></span>
                  <span>Redirects: {item.redirects ?? 0}</span>
                  <span>DNS: {item.dns?.nxdomain ? "NXDOMAIN" : item.dns?.dangling ? "Dangling CNAME" : item.dns?.status || "UNKNOWN"}</span>
                  <span>Fingerprint: {item.fingerprint || "None observed"}</span>
                </div>
                {item.claimability?.status === "POTENTIAL" ? <p className="mt-2 text-xs text-amber-200">Potential takeover evidence only; verify ownership through an authorized provider process.</p> : null}
                {item.error ? <p className="mt-2 text-xs text-amber-300">Request unavailable: {item.error}</p> : null}
              </details>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

function Metric({ label, value, danger }: { label: string; value: any; danger?: boolean }) {
  return <div className="rounded-xl border border-line p-3"><div className="text-[10px] uppercase tracking-widest text-slate-500">{label}</div><div className={`mt-1 text-xl font-semibold ${danger ? "text-danger" : "text-slate-100"}`}>{value}</div></div>;
}
