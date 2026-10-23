// Cloudflare Worker: gives the announcer page a short-lived Azure Speech token.
// The Azure key is NOT in this file. Set it in the Cloudflare dashboard:
//   Secret    AZURE_SPEECH_KEY     - the Azure Speech key (encrypted by Cloudflare)
//   Variable  AZURE_SPEECH_REGION  - e.g. westeurope
//   Variable  ALLOWED_ORIGINS      - optional, comma separated; default below
const DEFAULT_ORIGINS = 'https://alemu06-debug.github.io';

function reply(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map((s) => s.trim()).filter(Boolean);
    const ok = allowed.includes(origin);
    const cors = ok
      ? { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Methods': 'GET, OPTIONS', 'Access-Control-Max-Age': '86400', Vary: 'Origin' }
      : { Vary: 'Origin' };

    if (request.method === 'OPTIONS') return new Response(null, { status: ok ? 204 : 403, headers: cors });
    if (!ok) return reply({ error: 'origin-not-allowed' }, 403, cors);
    if (request.method !== 'GET') return reply({ error: 'method-not-allowed' }, 405, cors);

    const key = env.AZURE_SPEECH_KEY;
    const region = (env.AZURE_SPEECH_REGION || '').trim().toLowerCase();
    if (!key || !/^[a-z0-9]+$/.test(region)) return reply({ error: 'not-configured' }, 500, cors);

    let res;
    try {
      res = await fetch(`https://${region}.api.cognitive.microsoft.com/sts/v1.0/issueToken`, {
        method: 'POST',
        headers: { 'Ocp-Apim-Subscription-Key': key, 'Content-Length': '0' },
      });
    } catch (e) {
      return reply({ error: 'azure-unreachable' }, 502, cors);
    }
    if (!res.ok) return reply({ error: 'azure-error', status: res.status }, 502, cors);

    // Azure tokens are valid for 10 minutes; the page refreshes before that.
    return reply({ token: await res.text(), region, expiresIn: 600 }, 200, cors);
  },
};
