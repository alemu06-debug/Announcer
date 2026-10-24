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
// Wrong codes are counted per address group (an IPv6 address counts by its /64), so switching addresses
// inside one network does not give extra guesses. Lock records nobody touched for a day are removed hourly.
//
// Routes (all need an allowed Origin; anything else gets 404 without touching the shared state):
//   POST /session            {token}  -> is the guard's session still valid; today's usage only if it is
//   POST /login              {code}   -> session token valid until midnight Israel time
//   POST /voice-changer      header X-Session; body is a short recording -> MP3 in the ElevenLabs voice
//   POST /admin/login        {code}   -> administrator token valid for one hour
//   POST /admin/status       header X-Admin-Session -> today's usage and active lockouts
//   POST /admin/unlock       header X-Admin-Session -> lifts every guard lockout
//   POST /admin/reset-quota  header X-Admin-Session -> sets today's count back to zero, at most twice a day
import { DurableObject } from 'cloudflare:workers';

const DEFAULT_ORIGINS = 'https://alemu06-debug.github.io';
const DEFAULT_VOICE_ID = 'V0stpogHp8KBgdErUZbd';
const STS_MODEL = 'eleven_multilingual_sts_v2';
// 8.5 seconds measured about 135 KB in Chrome (128 kbps); this leaves room for an iPhone recording
// at twice that rate, and twice again on top, while keeping a long low-bitrate upload out.
const MAX_AUDIO_BYTES = 600 * 1024;
const DEFAULT_DAILY_LIMIT = 30;
const MAX_RESETS = 2; // quota resets allowed per day
const TIME_ZONE = 'Asia/Jerusalem';
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
// Every 5 wrong guard codes from one address group lock it, for longer each time: a minute, 5 minutes, then an hour.
const GUARD_LOCK = { max: 5, steps: [MINUTE, 5 * MINUTE, HOUR] };
const ADMIN_LOCK = { max: 3, steps: [DAY] }; // 3 wrong admin codes from one address group -> locked for a day
const LOCK_MEMORY_MS = DAY; // a group with no wrong code for this long starts over
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
// Compares fixed-length digests, so the time taken does not reveal how long the real code is.
async function sameCode(given, expected) {
  if (!expected) return false;
  const [a, b] = await Promise.all([given, expected].map((s) => crypto.subtle.digest('SHA-256', enc.encode(s))));
  return sameBytes(new Uint8Array(a), new Uint8Array(b));
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

// ---------- Address groups ----------
// An IPv4 address stands for itself. An IPv6 address counts by its first four groups (its /64),
// because one home or one cloud server is handed a whole /64 and can switch addresses inside it at will.
function addrGroup(ip) {
  ip = String(ip || '').trim().toLowerCase().split('%')[0];
  if (!ip.includes(':')) return ip || 'unknown';
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = tail === undefined ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  return `${groups.slice(0, 4).map((g) => (parseInt(g, 16) || 0).toString(16)).join(':')}::/64`;
}

// ---------- Shared state ----------
// A single instance holds all state. Each method runs to completion before the next request is let in,
// so parallel guesses cannot slip past a lockout and parallel requests cannot exceed the daily limit.
// Lock records sit in a SQL table so they can be counted and cleared without loading them all.
export class AnnouncerState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS locks (
      scope TEXT NOT NULL, grp TEXT NOT NULL, fails INTEGER NOT NULL, level INTEGER NOT NULL,
      until INTEGER NOT NULL, touched INTEGER NOT NULL, PRIMARY KEY (scope, grp))`);
    // Lock records of the previous version were kept per address under lock:...; drop them once.
    ctx.blockConcurrencyWhile(async () => {
      if (await ctx.storage.get('locksV2')) return;
      const keys = [...(await ctx.storage.list({ prefix: 'lock:' })).keys()];
      for (let i = 0; i < keys.length; i += 128) await ctx.storage.delete(keys.slice(i, i + 128));
      await ctx.storage.put('locksV2', true);
    });
  }

  async rootKey() {
    let k = await this.ctx.storage.get('rootKey');
    if (!k) {
      k = b64u(crypto.getRandomValues(new Uint8Array(32)));
      await this.ctx.storage.put('rootKey', k);
    }
    return k;
  }

  // Records the result of a code check for one address group. The code itself is compared by the caller;
  // everything up to the write below is synchronous, so no other request can run in between.
  async attempt(scope, grp, correct, max, steps) {
    const now = Date.now();
    const row = this.sql.exec('SELECT fails, level, until, touched FROM locks WHERE scope = ? AND grp = ?', scope, grp).toArray()[0];
    if (row && row.until > now) return { ok: false, locked: true, until: row.until };
    if (correct) {
      if (row) this.sql.exec('DELETE FROM locks WHERE scope = ? AND grp = ?', scope, grp);
      return { ok: true };
    }
    // After a lockout the count starts again, one step longer; a day without mistakes forgets everything.
    const fresh = !row || now - row.touched > LOCK_MEMORY_MS;
    const fails = fresh || row.until ? 1 : row.fails + 1;
    let level = fresh ? 0 : row.level;
    let until = 0;
    if (fails >= max) until = now + steps[Math.min(level++, steps.length - 1)];
    this.sql.exec(
      'INSERT OR REPLACE INTO locks (scope, grp, fails, level, until, touched) VALUES (?, ?, ?, ?, ?, ?)',
      scope, grp, fails, level, until, now,
    );
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(now + HOUR);
    return { ok: false, locked: !!until, until, left: Math.max(0, max - fails) };
  }

  // Hourly cleanup while lock records exist.
  async alarm() {
    const now = Date.now();
    this.sql.exec('DELETE FROM locks WHERE touched < ? AND until < ?', now - LOCK_MEMORY_MS, now);
    if (this.sql.exec('SELECT COUNT(*) AS n FROM locks').one().n) await this.ctx.storage.setAlarm(now + HOUR);
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
  async resets(day) {
    const r = await this.ctx.storage.get('resets');
    return r && r.day === day ? r.n : 0;
  }
  async resetQuota(day, max) {
    const n = await this.resets(day);
    if (n >= max) return { ok: false, resets: n };
    await this.ctx.storage.put('resets', { day, n: n + 1 });
    await this.ctx.storage.delete('count');
    return { ok: true, resets: n + 1 };
  }

  guardLocks() {
    return this.sql.exec("SELECT COUNT(*) AS n FROM locks WHERE scope = 'guard' AND until > ?", Date.now()).one().n;
  }
  unlockGuards() {
    const active = this.guardLocks();
    this.sql.exec("DELETE FROM locks WHERE scope = 'guard'");
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
// Reads a body but stops as soon as it passes max bytes, so an oversized upload is never held in memory.
async function readCapped(body, max) {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.byteLength;
  }
  return out;
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
  const grp = addrGroup(request.headers.get('CF-Connecting-IP'));
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
    const r = await store.attempt('guard', grp, await sameCode(code, guardCode), GUARD_LOCK.max, GUARD_LOCK.steps);
    if (r.locked) return reply({ error: 'locked', until: r.until }, 429, cors);
    if (!r.ok) return reply({ error: 'wrong-code', left: r.left }, 401, cors);
    const exp = nextIsraelMidnight(now);
    return reply({ token: await makeToken(store, 'g', guardCode, exp), exp }, 200, cors);
  }

  if (path === '/voice-changer') {
    if (!post) return reply({ error: 'method-not-allowed' }, 405, cors);
    if (!(await guardSession())) return reply({ error: 'need-login' }, 401, cors);
    // The declared size is checked before reading; a body without one is read only up to the limit.
    if (Number(request.headers.get('Content-Length') || 0) > MAX_AUDIO_BYTES) return reply({ error: 'too-large' }, 413, cors);
    const audio = await readCapped(request.body, MAX_AUDIO_BYTES);
    if (!audio) return reply({ error: 'too-large' }, 413, cors);
    if (!audio.byteLength) return reply({ error: 'empty' }, 400, cors);
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
      const r = await store.attempt('admin', grp, await sameCode(code, adminCode), ADMIN_LOCK.max, ADMIN_LOCK.steps);
      if (r.locked) return reply({ error: 'locked', until: r.until }, 429, cors);
      if (!r.ok) return reply({ error: 'wrong-code', left: r.left }, 401, cors);
      return reply({ token: await makeToken(store, 'a', adminCode, now + ADMIN_SESSION_MS) }, 200, cors);
    }
    if (!(await adminSession())) return reply({ error: 'need-admin' }, 401, cors);
    let unlocked = 0;
    if (path === '/admin/unlock') unlocked = await store.unlockGuards();
    else if (path === '/admin/reset-quota') {
      const r = await store.resetQuota(day, MAX_RESETS);
      if (!r.ok) return reply({ error: 'reset-limit', resets: r.resets, maxResets: MAX_RESETS }, 429, cors);
    } else if (path !== '/admin/status') return reply({ error: 'not-found' }, 404, cors);
    const [used, locks, resets] = await Promise.all([store.usage(day), store.guardLocks(), store.resets(day)]);
    return reply({ ok: true, unlocked, used, limit, locks, resets, maxResets: MAX_RESETS }, 200, cors);
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
