import { useEffect, useState } from "react";
import { api } from "../../lib/api";

function severityTone(sev: string) {
  const s = String(sev || "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "bg-red-950/80 text-red-300 border border-red-800/50";
  if (s === "MEDIUM" || s === "WARNING") return "bg-amber-950/80 text-amber-300 border border-amber-800/50";
  if (s === "PASS" || s === "CLEAN") return "bg-emerald-950/80 text-emerald-300 border border-emerald-800/50";
  return "bg-slate-900 text-slate-400 border border-slate-700/50";
}

function statusTone(status: string) {
  const s = String(status || "").toUpperCase();
  if (s === "UNAVAILABLE" || s === "NOT_CONFIGURED" || s === "RATE_LIMITED" || s === "PROVIDER_ERROR") {
    return "text-red-400 font-semibold";
  }
  if (s === "UNKNOWN" || s === "PENDING") {
    return "text-amber-400 font-semibold";
  }
  if (s === "QUERIED" || s === "AVAILABLE" || s === "COMPLETED") {
    return "text-emerald-400";
  }
  return "text-slate-400";
}

export default function EvidenceProvenancePanel({
  scanId,
  scanJobId,
  scan,
  initialItems,
}: {
  scanId?: number;
  scanJobId?: string;
  scan?: any;
  initialItems?: any[];
}) {
  const [items, setItems] = useState<any[]>(initialItems || []);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [verifiedHashes, setVerifiedHashes] = useState<Record<number, any>>({});
  const [verifyingId, setVerifyingId] = useState<number | null>(null);
  const [filterProvider, setFilterProvider] = useState("");
  const [filterCurrentOnly, setFilterCurrentOnly] = useState(false);

  useEffect(() => {
    if (initialItems && initialItems.length) {
      setItems(initialItems);
      return;
    }
    const currentScanProvenance = scan?.evidence_provenance;
    if (Array.isArray(currentScanProvenance) && currentScanProvenance.length) {
      setItems(currentScanProvenance);
      return;
    }
    const targetScanId = scanId || scan?.id;
    if (targetScanId) {
      setLoading(true);
      setError("");
      api(`/evidence-provenance?scan_id=${targetScanId}`)
        .then((res) => setItems(res.items || []))
        .catch((err: any) => setError(err.message || "Failed to load evidence provenance"))
        .finally(() => setLoading(false));
    } else if (scanJobId) {
      setLoading(true);
      setError("");
      api(`/evidence-provenance?scan_job_id=${encodeURIComponent(scanJobId)}`)
        .then((res) => setItems(res.items || []))
        .catch((err: any) => setError(err.message || "Failed to load evidence provenance"))
        .finally(() => setLoading(false));
    } else {
      setLoading(true);
      setError("");
      api(`/evidence-provenance?limit=50`)
        .then((res) => setItems(res.items || []))
        .catch((err: any) => setError(err.message || "Failed to load evidence provenance"))
        .finally(() => setLoading(false));
    }
  }, [scanId, scanJobId, scan, initialItems]);

  const verifyHash = async (id: number) => {
    setVerifyingId(id);
    try {
      const res = await api(`/evidence-provenance/${id}/verify`, { method: "POST" });
      setVerifiedHashes((prev) => ({ ...prev, [id]: res }));
    } catch (err: any) {
      setVerifiedHashes((prev) => ({
        ...prev,
        [id]: { verified: false, matches: false, error: err.message },
      }));
    } finally {
      setVerifyingId(null);
    }
  };

  const filtered = items.filter((item) => {
    if (filterProvider && !item.source_provider?.toLowerCase().includes(filterProvider.toLowerCase())) {
      return false;
    }
    if (filterCurrentOnly && !item.is_current) {
      return false;
    }
    return true;
  });

  return (
    <section className="glass mt-5 rounded-3xl border border-cyan/20 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-[.2em] text-cyan">Central Traceability</div>
          <h3 className="mt-1 text-xl font-semibold">Evidence Provenance & Finding Chain</h3>
          <p className="mt-1 text-xs text-slate-400">
            Cryptographically anchored finding evidence. Every high-risk result traces back to an immutable SHA-256 hash.
            Unavailable providers remain visibly unavailable; unknown is never presented as clean.
          </p>
        </div>
        <div className="text-right">
          <div className="text-sm font-semibold text-cyan">{filtered.length} Findings Tracked</div>
          <div className="text-[11px] text-slate-500">SHA-256 Verified Storage</div>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <input
          value={filterProvider}
          onChange={(e) => setFilterProvider(e.target.value)}
          placeholder="Filter by provider..."
          className="rounded-lg border border-line bg-ink/60 px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan focus:outline-none"
        />
        <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
          <input
            type="checkbox"
            checked={filterCurrentOnly}
            onChange={(e) => setFilterCurrentOnly(e.target.checked)}
            className="rounded border-line"
          />
          Current evidence only
        </label>
      </div>

      {loading && <div className="mt-4 text-xs text-slate-500">Loading evidence provenance...</div>}
      {error && <div className="mt-4 text-xs text-red-300">{error}</div>}

      {!loading && !filtered.length && (
        <div className="mt-4 rounded-xl border border-line p-4 text-xs text-slate-500">
          No finding provenance records found matching criteria.
        </div>
      )}

      <div className="mt-4 space-y-3">
        {filtered.map((item) => (
          <div key={item.id || item.finding_id} className="rounded-xl border border-line bg-black/20 p-4 transition-colors">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-cyan">{item.title || item.finding_id}</span>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${severityTone(item.severity)}`}>
                  {item.severity || "INFO"}
                </span>
                <span className="text-[11px] text-slate-500">[{item.confidence || "UNKNOWN"} CONFIDENCE]</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs uppercase tracking-wider ${statusTone(item.provider_status)}`}>
                  {item.provider_status || "UNKNOWN"}
                </span>
              </div>
            </div>

            <div className="mt-3 space-y-1.5 text-xs">
              <div className="flex items-start gap-2">
                <span className="text-cyan font-bold whitespace-nowrap">→ Why it exists:</span>
                <span className="text-slate-200">{item.why_it_exists || item.explanation || "No explanation recorded."}</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-cyan font-bold whitespace-nowrap">→ Which provider observed it:</span>
                <span className="text-slate-300">
                  {item.source_provider} <span className="text-slate-500">({item.source_type})</span>
                </span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-cyan font-bold whitespace-nowrap">→ When it was checked:</span>
                <span className="text-slate-300">
                  {item.checked_at ? new Date(item.checked_at).toLocaleString() : (item.observed_at ? new Date(item.observed_at).toLocaleString() : "Unknown")}
                </span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-cyan font-bold whitespace-nowrap">→ Whether evidence is current:</span>
                <span className={item.is_current ? "text-emerald-400 font-medium" : "text-amber-400 font-medium"}>
                  {item.is_current ? "Current (Active Scan Evidence)" : "Historical / Stale"}
                </span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-cyan font-bold whitespace-nowrap">→ Which report revision includes it:</span>
                <span className="text-slate-300">
                  {item.revision_id
                    ? `Report #${item.report_id} · Revision #${item.revision_id}`
                    : (item.report_id
                      ? `Report #${item.report_id} (Unrevised)`
                      : "Standalone Scan (Not yet linked to a report revision)")}
                </span>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-line/60 pt-2 text-xs">
              <div className="font-mono text-[11px] text-slate-400 truncate max-w-md">
                SHA-256: <span className="text-slate-200">{item.content_hash}</span>
              </div>
              <div className="flex items-center gap-2">
                {verifiedHashes[item.id] ? (
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                      verifiedHashes[item.id].matches
                        ? "bg-emerald-950/80 text-emerald-300 border border-emerald-500/30"
                        : "bg-red-950/80 text-red-300 border border-red-500/30"
                    }`}
                  >
                    {verifiedHashes[item.id].matches ? "✓ VERIFIED HASH MATCH" : "✗ HASH MISMATCH"}
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => verifyHash(item.id)}
                    disabled={verifyingId === item.id}
                    className="rounded border border-cyan/40 px-2.5 py-1 text-xs text-cyan hover:bg-cyan/10 transition-colors disabled:opacity-50"
                  >
                    {verifyingId === item.id ? "Verifying..." : "Verify Hash"}
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
