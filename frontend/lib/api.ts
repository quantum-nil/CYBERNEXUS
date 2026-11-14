// The browser session uses HttpOnly cookies; credentials are never stored in JS storage.
const isLocal = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');
let rawApi = (import.meta.env.VITE_API_URL as string | undefined)?.trim() || (isLocal ? 'http://127.0.0.1:8000/api' : 'https://cybernexus-api-p8y5.onrender.com/api');
if (rawApi.includes('cybernexus-api-p8y6')) {
  rawApi = rawApi.replace('cybernexus-api-p8y6', 'cybernexus-api-p8y5');
}
export const API = rawApi.replace(/\/+$/, '');

export function buildUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return `${API}${cleanPath}`;
}

export async function api(path: string, options?: RequestInit) {
  try {
    const res = await fetch(buildUrl(path), {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {}),
      },
    });
    if (!res.ok) {
      let detail = '';
      try {
        const body = await res.json();
        detail = body.detail || body.message || '';
      } catch {}

      if (res.status === 401) {
        throw new Error(detail || "Authentication required");
      }
      if (res.status === 403) {
        throw new Error(detail || "Authorization required");
      }
      if (res.status === 429) {
        throw new Error(detail || "Scan quota exceeded. Rate limit active.");
      }
      if (res.status === 503 || res.status === 502 || res.status === 504) {
        throw new Error(detail || "Provider or backend service temporarily unavailable");
      }
      throw new Error(detail || `Request failed (${res.status})`);
    }
    return res.json();
  } catch (err: any) {
    const msg = (err?.message || "").toLowerCase();
    if (msg.includes("failed to fetch") || msg.includes("networkerror") || err.name === "TypeError") {
      throw new Error("Backend service is initializing or unreachable. If running on Render free tier, the backend may take ~50s to spin up. Please retry shortly.");
    }
    throw err;
  }
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
