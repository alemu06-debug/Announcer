// Cloudflare Worker for the announcer pages. No keys are in this file. Set them in the Cloudflare dashboard:
//   Secret    AZURE_SPEECH_KEY     - the Azure Speech key (encrypted by Cloudflare)
//   Secret    ELEVENLABS_API_KEY   - the ElevenLabs API key (encrypted by Cloudflare)
//   Secret    ACCESS_CODE          - optional; when set, every request must carry this code in the
//                                    X-Access-Code header. The pages keep it on the guard's device only.
//   Variable  AZURE_SPEECH_REGION  - e.g. westeurope
//   Variable  ALLOWED_ORIGINS      - optional, comma separated; default below
//   Variable  ELEVENLABS_VOICE_ID  - optional; default below
//
// Routes:
//   GET  (any path)       -> short-lived Azure Speech token, used by azure.html
//   POST /voice-changer   -> body is a short recording; returns it as MP3 in the ElevenLabs voice (voice-changer.html)
const DEFAULT_ORIGINS = 'https://alemu06-debug.github.io';
const DEFAULT_VOICE_ID = 'V0stpogHp8KBgdErUZbd';
const STS_MODEL = 'eleven_multilingual_sts_v2';
const MAX_AUDIO_BYTES = 1024 * 1024; // an 8-second recording is about a tenth of this

function reply(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

// Compares SHA-256 digests so the time taken does not reveal how much of the code was right.
async function codeMatches(given, expected) {
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([given, expected].map((s) => crypto.subtle.digest('SHA-256', enc.encode(s))));
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function azureToken(env, cors) {
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
}

async function voiceChanger(request, env, cors) {
  const key = env.ELEVENLABS_API_KEY;
  if (!key) return reply({ error: 'not-configured' }, 500, cors);
  const voiceId = (env.ELEVENLABS_VOICE_ID || DEFAULT_VOICE_ID).trim();
  if (!/^[A-Za-z0-9]+$/.test(voiceId)) return reply({ error: 'not-configured' }, 500, cors);

  if (Number(request.headers.get('Content-Length') || 0) > MAX_AUDIO_BYTES) return reply({ error: 'too-large' }, 413, cors);
  const audio = await request.arrayBuffer();
  if (!audio.byteLength) return reply({ error: 'empty' }, 400, cors);
  if (audio.byteLength > MAX_AUDIO_BYTES) return reply({ error: 'too-large' }, 413, cors);

  // The recording's own type (audio/webm on Chrome/Android, audio/mp4 on iPhone) and a matching file name.
  const type = (request.headers.get('Content-Type') || 'application/octet-stream').split(';')[0].trim();
  const ext = { 'audio/webm': 'webm', 'audio/mp4': 'm4a', 'audio/ogg': 'ogg', 'audio/wav': 'wav', 'audio/mpeg': 'mp3' }[type] || 'bin';

  const form = new FormData();
  form.append('audio', new Blob([audio], { type }), `recording.${ext}`);
  form.append('model_id', STS_MODEL);
  if (new URL(request.url).searchParams.get('noise') === '1') form.append('remove_background_noise', 'true');

  let res;
  try {
    res = await fetch(`https://api.elevenlabs.io/v1/speech-to-speech/${voiceId}?output_format=mp3_44100_128`, {
      method: 'POST',
      headers: { 'xi-api-key': key, Accept: 'audio/mpeg' },
      body: form,
    });
  } catch (e) {
    return reply({ error: 'elevenlabs-unreachable' }, 502, cors);
  }
  if (!res.ok) {
    // ElevenLabs errors look like {"detail":{"status":"quota_exceeded","message":"..."}}; pass on only the short status.
    let detail = '';
    try { const j = await res.json(); detail = (j && j.detail && (j.detail.status || j.detail.code)) || ''; } catch (e) {}
    return reply({ error: 'elevenlabs-error', status: res.status, detail: String(detail).slice(0, 80) }, 502, cors);
  }
  return new Response(res.body, {
    status: 200,
    headers: { 'Content-Type': res.headers.get('Content-Type') || 'audio/mpeg', 'Cache-Control': 'no-store', ...cors },
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map((s) => s.trim()).filter(Boolean);
    const ok = allowed.includes(origin);
    const cors = ok
      ? {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Access-Code',
          'Access-Control-Max-Age': '86400',
          Vary: 'Origin',
        }
      : { Vary: 'Origin' };

    if (request.method === 'OPTIONS') return new Response(null, { status: ok ? 204 : 403, headers: cors });
    if (!ok) return reply({ error: 'origin-not-allowed' }, 403, cors);

    // Until ACCESS_CODE is set the service stays open as before, so the pages keep working during the switch.
    const expected = (env.ACCESS_CODE || '').trim();
    if (expected && !(await codeMatches((request.headers.get('X-Access-Code') || '').trim(), expected))) {
      return reply({ error: 'need-code' }, 401, cors);
    }

    const path = new URL(request.url).pathname.replace(/\/+$/, '');
    if (path === '/voice-changer') {
      if (request.method !== 'POST') return reply({ error: 'method-not-allowed' }, 405, cors);
      return voiceChanger(request, env, cors);
    }
    if (request.method !== 'GET') return reply({ error: 'method-not-allowed' }, 405, cors);
    return azureToken(env, cors);
  },
};
