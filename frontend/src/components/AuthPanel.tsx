import { useEffect, useState } from 'react';
import { LogIn, LogOut, UserRound } from 'lucide-react';
import { api, buildUrl } from '../../lib/api';

export default function AuthPanel() {
  const [config, setConfig] = useState<any>(); const [me, setMe] = useState<any>(); const [error, setError] = useState('');
  useEffect(() => { Promise.all([api('/auth/config'), api('/auth/me')]).then(([c, user]) => { setConfig(c); setMe(user); }).catch((err: any) => setError(err.message || 'Authentication unavailable')); }, []);
  async function logout() { await api('/auth/logout', { method: 'POST' }); window.location.reload(); }
  const login = () => { if (config?.authorization_url) window.location.assign(buildUrl('/auth/oidc/start')); else setError('OIDC authorization URL is not configured'); };
  const profileName = me?.display_name || me?.name || me?.email || me?.user_id;
  return <div className="fixed right-4 top-4 z-50 rounded-xl border border-line bg-panel/95 p-3 text-xs shadow-xl"><div className="flex items-center gap-3"><UserRound size={16} className="text-cyan"/><div className="min-w-0"><div className="truncate font-semibold text-slate-100">{me?.authenticated ? profileName : config?.required ? 'Sign in required' : 'Development session'}</div>{me?.authenticated && <div className="text-[10px] uppercase tracking-wider text-slate-500">{me.role || 'member'}{me.tenant_id ? ` · ${me.tenant_id}` : ''}</div>}</div>{me?.authenticated ? <button onClick={logout} title="Log out" className="ml-2 inline-flex items-center gap-1 rounded border border-line px-2 py-1 text-slate-300 hover:border-cyan hover:text-cyan"><LogOut size={14}/> Logout</button> : config?.required ? <button onClick={login} title="Sign in" className="ml-2 text-cyan"><LogIn size={15}/></button> : null}</div>{error && <div className="mt-2 max-w-64 text-red-300">{error}</div>}</div>;
}
