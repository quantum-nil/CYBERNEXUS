import { FormEvent, ReactNode, useEffect, useState } from "react";
import { ArrowUpRight, ShieldCheck } from "lucide-react";
import { api, buildUrl } from "../../lib/api";

type AuthGateProps = { children: ReactNode };

export default function AuthGate({ children }: AuthGateProps) {
  const [config, setConfig] = useState<any>();
  const [me, setMe] = useState<any>();
  const [page, setPage] = useState<"landing" | "signin">("landing");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    const configResult = await api("/auth/config");
    setConfig(configResult);
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (code && state) {
      try {
        const callback = await api(`/auth/oidc/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`);
        window.history.replaceState({}, document.title, window.location.pathname);
        setMe({ authenticated: true, ...callback });
        return;
      } catch (err: any) { setError(err.message || "Organization sign-in failed"); }
    }
    try { setMe(await api("/auth/me")); } catch { setMe({ authenticated: false }); }
  }

  useEffect(() => { load().catch((err: any) => setError(err.message || "Authentication service unavailable")); }, []);

  async function localSignIn(event: FormEvent) {
    event.preventDefault();
    if (!email.trim()) return;
    setBusy(true); setError("");
    try {
      const result = await api("/auth/login", { method: "POST", body: JSON.stringify({ email: email.trim() }) });
      setMe({ authenticated: true, ...result.user });
    } catch (err: any) { setError(err.message || "Sign in failed"); }
    finally { setBusy(false); }
  }

  if (!me) return <div className="min-h-screen grid-bg cinematic-app dark-app grid place-items-center p-6"><div className="glass rounded-3xl p-8 text-sm text-slate-400">Checking secure session…</div></div>;
  if (me.authenticated) return <>{children}</>;

  const oidcReady = Boolean(config?.authorization_url && config?.configured && config?.client_id);
  return <main className="min-h-screen grid-bg cinematic-app dark-app">
    <div className="cinematic-video" aria-hidden="true"><video autoPlay muted loop playsInline preload="auto" src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260809_132544_b6ef0174-ed95-45ad-9a2f-ccb8acfbdce8.mp4" /><video className="cinematic-video-lift" autoPlay muted loop playsInline preload="auto" src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260809_132544_b6ef0174-ed95-45ad-9a2f-ccb8acfbdce8.mp4" /></div>
    <div className="relative z-10 mx-auto flex min-h-screen max-w-[1500px] items-center p-6 md:p-10">
      <section className="grid w-full gap-8 lg:grid-cols-[1.2fr_.8fr] lg:items-center">
        <div className="max-w-3xl"><div className="mb-6 flex items-center gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan text-ink"><ShieldCheck size={22} /></div><div><div className="text-sm font-bold">CYBERNEXUS</div><div className="text-[10px] tracking-[.3em] text-cyan">TRUST INTELLIGENCE</div></div></div><div className="overview-eyebrow">DIGITAL TRUST INTELLIGENCE / SECURE ACCESS</div><h1 className="mt-4 text-5xl font-semibold leading-tight md:text-7xl">Security built into<br /><span className="text-slate-300">every system layer</span></h1><p className="mt-6 max-w-2xl text-base text-slate-400">Evidence-backed threat detection, privacy-aware analysis, and auditable access controls for your digital operations.</p><button type="button" onClick={() => setPage("signin")} className="mt-8 inline-flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-bold text-ink">Enter secure workspace <ArrowUpRight size={16} /></button></div>
        <div className="glass rounded-3xl p-6 md:p-8">{page === "landing" ? <><div className="text-xs uppercase tracking-[.2em] text-cyan">Protected workspace</div><h2 className="mt-3 text-2xl font-semibold">Access is verified before dashboard data loads.</h2><p className="mt-3 text-sm text-slate-400">Your tenant, role, and authorization scope are attached to the session before scans or message history become available.</p><button type="button" onClick={() => setPage("signin")} className="mt-6 w-full rounded-xl border border-line px-4 py-3 text-sm hover:border-cyan">Continue to sign in</button></> : <><div className="text-xs uppercase tracking-[.2em] text-cyan">Identity verification</div><h2 className="mt-3 text-2xl font-semibold">Sign in to CYBERNEXUS</h2><p className="mt-2 text-sm text-slate-400">OIDC is used in production. Local email access is available only when the backend is running in development mode.</p>{oidcReady && <button type="button" onClick={() => window.location.assign(buildUrl("/auth/oidc/start"))} className="mt-6 w-full rounded-xl bg-cyan px-4 py-3 text-sm font-bold text-ink">Continue with organization sign-in</button>}{!config?.required && <form onSubmit={localSignIn} className="mt-4 space-y-3"><label className="block text-xs uppercase tracking-widest text-slate-500" htmlFor="signin-email">Development sign-in</label><input id="signin-email" type="email" required value={email} onChange={event => setEmail(event.target.value)} placeholder="you@example.com" className="w-full rounded-xl border border-line bg-ink/70 p-3 text-sm outline-none focus:border-cyan" /><button disabled={busy} className="w-full rounded-xl border border-cyan px-4 py-3 text-sm text-cyan">{busy ? "Signing in…" : "Sign in locally"}</button></form>}{!oidcReady && config?.required && <div className="mt-5 rounded-xl border border-danger/30 bg-danger/10 p-3 text-xs text-danger">{config?.configuration_error || "Organization sign-in is not configured. Set the OIDC authorization URL and client settings in the backend environment."}</div>}{error && <div className="mt-4 rounded-xl border border-danger/30 bg-danger/10 p-3 text-xs text-danger">{error}</div>}<button type="button" onClick={() => { setError(""); setPage("landing"); }} className="mt-5 text-xs text-slate-500 hover:text-cyan">Back to landing page</button></>}</div>
      </section>
    </div>
  </main>;
}
