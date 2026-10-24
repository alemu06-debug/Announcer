// Cloudflare Worker for the announcer pages. Deployed automatically from this folder by Workers Builds
// (see wrangler.toml). No keys are in this file. Set them in the Cloudflare dashboard:
//   Secret    ELEVENLABS_API_KEY   - the ElevenLabs API key
//   Secret    ACCESS_CODE          - the guard's 6-digit daily code
//   Secret    ADMIN_CODE           - the administrator's code
//   Variable  DAILY_LIMIT          - optional; voice changes allowed per day for the whole system, default 30
//                                    (set in the dashboard only; wrangler.toml keeps it on every deploy)
//   Variable  ALLOWED_ORIGINS      - optional, comma separated; default below
//   Variable  ELEVENLABS_VOICE_ID  - optional; default below
// Lockouts and the daily count live in one Durable Object (AnnouncerState), created automatically on deploy.
//
// Routes (all need an allowed Origin; anything else gets 404 without touching the shared state):
//   POST /session            {token}  -> is the guard's session still valid; today's usage only if it is
//   POST /login              {code}   -> session token valid until midnight Israel time
//   POST /voice-changer      header X-Session; body is a short recording -> MP3 in the ElevenLabs voice
//   POST /admin/login        {code}   -> administrator token valid for one hour
//   POST /admin/status       header X-Admin-Session -> today's usage and active lockouts
//   POST /admin/unlock       header X-Admin-Session -> lifts every guard lockout
//   POST /admin/reset-quota  header X-Admin-Session -> sets today's count back to zero
import { DurableObject } from 'cloudflare:workers';

const DEFAULT_ORIGINS = 'https://alemu06-debug.github.io';
const DEFAULT_VOICE_ID = 'V0stpogHp8KBgdErUZbd';
const STS_MODEL = 'eleven_multilingual_sts_v2';
const MAX_AUDIO_BYTES = 1024 * 1024; // an 8-second recording is about a tenth of this
const DEFAULT_DAILY_LIMIT = 30;
const TIME_ZONE = 'Asia/Jerusalem';
const HOUR = 60 * 60 * 1000;
const GUARD_LOCK = { max: 5, ms: HOUR }; // 5 wrong codes from one address -> locked for an hour
const ADMIN_LOCK = { max: 3, ms: 24 * HOUR }; // 3 wrong admin codes from one address -> locked for a day
const ADMIN_SESSION_MS = HOUR;

const enc = new TextEncoder();

function reply(body, status, headers) {
  return new Response(JSON.stringify({ v: 2, ...body }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

// ---------- Israel time ----------
function israelParts(ms) {
  const f = new Intl.DateTimeFormat('en-CA', {
    timeZone: TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  });
  const p = {};
  for (const x of f.formatToParts(new Date(ms))) p[x.type] = x.value;
  return p;
}
function israelDay(ms) {
  const p = israelParts(ms);
  return `${p.year}-${p.month}-${p.day}`;
}
function israelOffset(ms) {
  const p = israelParts(ms);
  return Date.UTC(+p.year, p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - Math.floor(ms / 1000) * 1000;
}
function nextIsraelMidnight(ms) {
  const p = israelParts(ms);
  const localMidnight = Date.UTC(+p.year, p.month - 1, +p.day + 1);
  // Second pass uses the offset at midnight itself, in case daylight saving changes overnight.
  return localMidnight - israelOffset(localMidnight - israelOffset(ms));
}

// ---------- Signed tokens ----------
function b64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
// The signing key mixes a random secret kept in the Durable Object with the current code,
// so changing a code in Cloudflare ends every session made with the old one.
// The random secret never changes once created, so each Worker instance fetches it at most once.
let rootCache = null;
async function rootKey(store) {
  if (!rootCache) rootCache = unb64u(await store.rootKey());
  return rootCache;
}
async function makeToken(store, kind, code, exp) {
  const body = b64u(enc.encode(JSON.stringify({ k: kind, exp })));
  return `${body}.${b64u(await hmac(await hmac(await rootKey(store), `${kind}|${code}`), body))}`;
}
async function readToken(store, kind, code, token) {
  if (!code || !/^[A-Za-z0-9_-]{8,200}\.[A-Za-z0-9_-]{43}$/.test(token || '')) return null;
  const [body, sig] = token.split('.');
  try {
    // Shape, kind and expiry are checked first, so a missing, malformed or expired token
    // is turned away without touching the shared state.
    const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
    if (p.k !== kind || !(p.exp > Date.now())) return null;
    const want = await hmac(await hmac(await rootKey(store), `${kind}|${code}`), body);
    return sameBytes(want, unb64u(sig)) ? p : null;
  } catch (e) {
    return null;
  }
}

// ---------- Shared state ----------
// A single instance holds all state. Each method runs to completion before the next request is let in,
// so parallel guesses cannot slip past a lockout and parallel requests cannot exceed the daily limit.
export class AnnouncerState extends DurableObject {
  async rootKey() {
    let k = await this.ctx.storage.get('rootKey');
    if (!k) {
      k = b64u(crypto.getRandomValues(new Uint8Array(32)));
      await this.ctx.storage.put('rootKey', k);
    }
    return k;
  }

  // Checks a code and keeps count of wrong ones per address, all in one step.
  async attempt(scope, ip, given, expected, max, lockMs) {
    const key = `lock:${scope}:${ip}`;
    const now = Date.now();
    let rec = await this.ctx.storage.get(key);
    if (rec && rec.until > now) return { ok: false, locked: true, until: rec.until };
    // A finished lockout, or mistakes older than the lock period, start a fresh count.
    if (!rec || rec.until || now - rec.since > lockMs) rec = { fails: 0, since: now, until: 0 };
    const a = enc.encode(given), b = enc.encode(expected);
    if (expected && sameBytes(a, b)) {
      await this.ctx.storage.delete(key);
      return { ok: true };
    }
    rec.fails++;
    if (rec.fails >= max) rec.until = now + lockMs;
    await this.ctx.storage.put(key, rec);
    return { ok: false, locked: !!rec.until, until: rec.until, left: Math.max(0, max - rec.fails) };
  }

  async usage(day) {
    const c = await this.ctx.storage.get('count');
    return c && c.day === day ? c.n : 0;
  }
  async reserve(day, limit) {
    const n = await this.usage(day);
    if (n >= limit) return { ok: false, used: n };
    await this.ctx.storage.put('count', { day, n: n + 1 });
    return { ok: true, used: n + 1 };
  }
  // Gives back a reserved conversion when ElevenLabs did not deliver one.
  async release(day) {
    const n = await this.usage(day);
    if (n > 0) await this.ctx.storage.put('count', { day, n: n - 1 });
  }
  async resetQuota() {
    await this.ctx.storage.delete('count');
  }

  async guardLocks() {
    const now = Date.now();
    let active = 0;
    for (const rec of (await this.ctx.storage.list({ prefix: 'lock:guard:' })).values()) if (rec.until > now) active++;
    return active;
  }
  async unlockGuards() {
    const keys = [...(await this.ctx.storage.list({ prefix: 'lock:guard:' })).keys()];
    const active = await this.guardLocks();
    for (let i = 0; i < keys.length; i += 128) await this.ctx.storage.delete(keys.slice(i, i + 128));
    return active;
  }
}

// ---------- ElevenLabs ----------
async function voiceChanger(request, env, audio, type, cors) {
  const key = env.ELEVENLABS_API_KEY;
  const voiceId = (env.ELEVENLABS_VOICE_ID || DEFAULT_VOICE_ID).trim();
  if (!key || !/^[A-Za-z0-9]+$/.test(voiceId)) return reply({ error: 'not-configured' }, 500, cors);

  // The recording's own type (audio/webm on Chrome/Android, audio/mp4 on iPhone) and a matching file name.
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

// ---------- Requests ----------
function dailyLimit(env) {
  const n = parseInt(env.DAILY_LIMIT, 10);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_DAILY_LIMIT;
}
async function readJson(request) {
  try {
    return JSON.parse((await request.text()).slice(0, 2000)) || {};
  } catch (e) {
    return {};
  }
}

async function handle(request, env, cors) {
  const path = new URL(request.url).pathname.replace(/\/+$/, '') || '/';
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  // Getting the handle does not contact the shared state; only calls on it do.
  const store = env.STATE.get(env.STATE.idFromName('main'));
  const now = Date.now();
  const day = israelDay(now);
  const limit = dailyLimit(env);
  const guardCode = (env.ACCESS_CODE || '').trim();
  const adminCode = (env.ADMIN_CODE || '').trim();
  const post = request.method === 'POST';
  const guardSession = () => (/^\d{6}$/.test(guardCode) ? readToken(store, 'g', guardCode, request.headers.get('X-Session') || '') : null);
  const adminSession = () => (adminCode ? readToken(store, 'a', adminCode, request.headers.get('X-Admin-Session') || '') : null);

  if (post && path === '/session') {
    const { token } = await readJson(request);
    const s = /^\d{6}$/.test(guardCode) ? await readToken(store, 'g', guardCode, String(token || '')) : null;
    // Today's usage is shown only to a valid session.
    return reply(s ? { ok: true, exp: s.exp, used: await store.usage(day), limit } : { ok: false }, 200, cors);
  }

  if (post && path === '/login') {
    if (!/^\d{6}$/.test(guardCode)) return reply({ error: 'bad-config' }, 500, cors);
    const code = String((await readJson(request)).code || '').trim();
    // Anything that is not 6 digits can never be right; refuse it without touching the shared state.
    if (!/^\d{6}$/.test(code)) return reply({ error: 'bad-format' }, 400, cors);
    const r = await store.attempt('guard', ip, code, guardCode, GUARD_LOCK.max, GUARD_LOCK.ms);
    if (r.locked) return reply({ error: 'locked', until: r.until }, 429, cors);
    if (!r.ok) return reply({ error: 'wrong-code', left: r.left }, 401, cors);
    const exp = nextIsraelMidnight(now);
    return reply({ token: await makeToken(store, 'g', guardCode, exp), exp }, 200, cors);
  }

  if (path === '/voice-changer') {
    if (!post) return reply({ error: 'method-not-allowed' }, 405, cors);
    if (!(await guardSession())) return reply({ error: 'need-login' }, 401, cors);
    if (Number(request.headers.get('Content-Length') || 0) > MAX_AUDIO_BYTES) return reply({ error: 'too-large' }, 413, cors);
    const audio = await request.arrayBuffer();
    if (!audio.byteLength) return reply({ error: 'empty' }, 400, cors);
    if (audio.byteLength > MAX_AUDIO_BYTES) return reply({ error: 'too-large' }, 413, cors);
    const type = (request.headers.get('Content-Type') || 'application/octet-stream').split(';')[0].trim();

    const slot = await store.reserve(day, limit);
    if (!slot.ok) return reply({ error: 'daily-limit', used: slot.used, limit }, 429, cors);
    const res = await voiceChanger(request, env, audio, type, cors);
    if (res.status !== 200) await store.release(day);
    return res;
  }

  if (path.startsWith('/admin/')) {
    if (!post) return reply({ error: 'method-not-allowed' }, 405, cors);
    if (path === '/admin/login') {
      if (!adminCode) return reply({ error: 'bad-config' }, 500, cors);
      const code = String((await readJson(request)).code || '').trim().slice(0, 200);
      if (!code) return reply({ error: 'bad-format' }, 400, cors);
      const r = await store.attempt('admin', ip, code, adminCode, ADMIN_LOCK.max, ADMIN_LOCK.ms);
      if (r.locked) return reply({ error: 'locked', until: r.until }, 429, cors);
      if (!r.ok) return reply({ error: 'wrong-code', left: r.left }, 401, cors);
      return reply({ token: await makeToken(store, 'a', adminCode, now + ADMIN_SESSION_MS) }, 200, cors);
    }
    if (!(await adminSession())) return reply({ error: 'need-admin' }, 401, cors);
    let unlocked = 0;
    if (path === '/admin/unlock') unlocked = await store.unlockGuards();
    else if (path === '/admin/reset-quota') await store.resetQuota();
    else if (path !== '/admin/status') return reply({ error: 'not-found' }, 404, cors);
    return reply({ ok: true, unlocked, used: await store.usage(day), limit, locks: await store.guardLocks() }, 200, cors);
  }

  return reply({ error: 'not-found' }, 404, cors);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map((s) => s.trim()).filter(Boolean);
    const ok = allowed.includes(origin);
    const cors = ok
      ? {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Session, X-Admin-Session',
          'Access-Control-Max-Age': '86400',
          Vary: 'Origin',
        }
      : { Vary: 'Origin' };

    if (request.method === 'OPTIONS') return new Response(null, { status: ok ? 204 : 403, headers: cors });
    if (!ok) return reply({ error: 'origin-not-allowed' }, 403, cors);
    try {
      return await handle(request, env, cors);
    } catch (e) {
      return reply({ error: 'server-error' }, 500, cors);
    }
  },
};
