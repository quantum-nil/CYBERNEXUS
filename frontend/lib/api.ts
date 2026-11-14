// The browser session uses HttpOnly cookies; credentials are never stored in JS storage.
const isLocal = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');
let rawApi = (import.meta.env.VITE_API_URL as string | undefined)?.trim() || (isLocal ? 'http://127.0.0.1:8000/api' : 'https://cybernexus-api-p8y5.onrender.com/api');
if (rawApi.includes('cybernexus-api-p8y6')) {
  rawApi = rawApi.replace('cybernexus-api-p8y6', 'cybernexus-api-p8y5');
}
const API = rawApi.replace(/\/+$/, '');

function buildUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return `${API}${cleanPath}`;
}

export async function api(path: string, options?: RequestInit) {
  const res = await fetch(buildUrl(path), { ...options, credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) } });
  if (!res.ok) { let detail = `Request failed (${res.status})`; try { const body = await res.json(); detail = body.detail || detail; } catch {} throw new Error(detail); }
  return res.json();
}
export async function upload(path: string, file: File) {
  const form = new FormData(); form.append('file', file);
  const res = await fetch(buildUrl(path), { method: 'POST', body: form, credentials: 'include' });
  if (!res.ok) { let detail = `Upload failed (${res.status})`; try { const body = await res.json(); detail = body.detail || detail; } catch {} throw new Error(detail); }
  return res.json();
}

export async function downloadFile(path: string) {
  const res = await fetch(buildUrl(path), { credentials: 'include' });
  if (!res.ok) {
    let detail = `Download failed (${res.status})`;
    try { const body = await res.json(); detail = body.detail || detail; } catch {}
    throw new Error(detail);
  }
  return { blob: await res.blob(), disposition: res.headers.get('content-disposition') || '' };
}
