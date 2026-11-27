// worker.js - Stream AI Studio V6
// Deploy: npx wrangler deploy   |   Once: POST /api/init with your passphrase

const API = 'https://api.kick.com/public/v1';
const OAUTH = 'https://id.kick.com/oauth';
const enc = new TextEncoder();
const MAX_PER_TICK = 12;
const LIVE_TTL = 90000;

const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

/* ---------- keys ---------- */
let _hk, _tk;
async function hmacKey(env) {
  if (!_hk) _hk = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return _hk;
}
async function aesKey(env) {
  if (!_tk) {
    const raw = await crypto.subtle.digest('SHA-256', enc.encode(env.TOKEN_KEY));
    _tk = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  return _tk;
}

/* ---------- vault ---------- */
async function seal(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), enc.encode(text));
  return b64u(iv) + '.' + b64u(ct);
}
async function open(env, blob) {
  const [iv, ct] = blob.split('.');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(iv) }, await aesKey(env), unb64u(ct));
  return new TextDecoder().decode(pt);
}

/* ---------- session ---------- */
async function signSession(env, days = 30) {
  const payload = b64u(enc.encode(JSON.stringify({ exp: Date.now() + days * 864e5 })));
  const sig = b64u(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload)));
  return payload + '.' + sig;
}
async function readSession(env, token) {
  if (!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  if (!await crypto.subtle.verify('HMAC', await hmacKey(env), unb64u(sig), enc.encode(payload))) return null;
  try {
    const { exp } = JSON.parse(new TextDecoder().decode(unb64u(payload)));
    return exp > Date.now() ? { exp } : null;
  } catch { return null; }
}

/* ---------- pkce ---------- */
async function pkce() {
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(48)));
  const challenge = b64u(await crypto.subtle.digest('SHA-256', enc.encode(verifier)));
  return { verifier, challenge };
}
function authorizeUrl(env, state, challenge) {
  const u = new URL(OAUTH + '/authorize');
  u.searchParams.set('client_id', env.KICK_CLIENT_ID);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('redirect_uri', env.REDIRECT_URI);
  u.searchParams.set('scope', 'chat:write user:read channel:read');
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('state', state);
  return u.toString();
}

/* ---------- tokens ---------- */
async function tokenCall(env, body) {
  const r = await fetch(OAUTH + '/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...body, client_id: env.KICK_CLIENT_ID, client_secret: env.KICK_CLIENT_SECRET })
  });
  if (!r.ok) throw new Error('token ' + r.status + ' ' + (await r.text()).slice(0, 200));
  return r.json();
}
async function exchangeCode(env, code, verifier) {
  return tokenCall(env, { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: env.REDIRECT_URI });
}
async function refreshAccount(env, acc) {
  const t = await tokenCall(env, { grant_type: 'refresh_token', refresh_token: await open(env, acc.refresh_token) });
  const exp = Date.now() + (t.expires_in || 3600) * 1000 - 5000;
  const rt = t.refresh_token ? await seal(env, t.refresh_token) : acc.refresh_token;
  await env.DB.prepare('UPDATE kick_accounts SET access_token=?, refresh_token=?, expires_at=?, scopes=?, status=? WHERE id=?')
    .bind(await seal(env, t.access_token), rt, exp, t.scope || acc.scopes, 'active', acc.id).run();
  acc.access_token = await seal(env, t.access_token);
  acc.expires_at = exp;
  acc.status = 'active';
}
async function accessToken(env, acc) {
  if (!acc.access_token) throw new Error('no token');
  if (acc.expires_at - Date.now() < 120000) await refreshAccount(env, acc);
  return open(env, acc.access_token);
}
async function appToken(env) {
  const row = await env.DB.prepare("SELECT v, exp FROM app_kv WHERE k='app_token'").first();
  if (row && row.exp > Date.now()) return open(env, row.v);
  const t = await tokenCall(env, { grant_type: 'client_credentials' });
  await env.DB.prepare("INSERT INTO app_kv (k,v,exp) VALUES ('app_token',?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, exp=excluded.exp")
    .bind(await seal(env, t.access_token), Date.now() + (t.expires_in || 3600) * 1000 - 60000).run();
  return t.access_token;
}

/* ---------- chat ---------- */
function truncate(s) {
  let out = Array.from(String(s).trim()).slice(0, 500).join('');
  while (enc.encode(out).length > 2048) out = Array.from(out).slice(0, -1).join('');
  return out;
}
async function sendChat(env, acc, broadcasterId, content) {
  const go = async () => fetch(API + '/chat', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + await accessToken(env, acc), 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'user', content: truncate(content), broadcaster_user_id: Number(broadcasterId) })
  });
  let r = await go();
  if (r.status === 401) { await refreshAccount(env, acc); r = await go(); }
  return { ok: r.ok, http: r.status, retryAfter: Number(r.headers.get('retry-after')) || 0, body: (await r.text()).slice(0, 300) };
}

/* ---------- lookups ---------- */
async function resolveChannel(env, slug) {
  const r = await fetch(API + '/channels?slug=' + encodeURIComponent(slug),
    { headers: { authorization: 'Bearer ' + await appToken(env) } });
  if (!r.ok) return null;
  const c = (await r.json()).data?.[0];
  return c ? { broadcaster_user_id: c.broadcaster_user_id, is_live: !!c.stream?.is_live } : null;
}
async function liveMap(env, ids) {
  const out = {};
  for (let i = 0; i < ids.length; i += 50) {
    const qs = ids.slice(i, i + 50).map(id => 'broadcaster_user_id=' + id).join('&');
    const r = await fetch(API + '/channels?' + qs, { headers: { authorization: 'Bearer ' + await appToken(env) } });
    if (!r.ok) continue;
    for (const c of (await r.json()).data || []) out[c.broadcaster_user_id] = !!c.stream?.is_live;
  }
  return out;
}
async function pickLive(env, lang, exclude) {
  const pool = await env.DB.prepare('SELECT slug FROM rotation_pool WHERE lang=?').all(lang);
  if (pool.results.length) {
    const pick = pool.results[Math.floor(Math.random() * pool.results.length)].slug;
    if (pick !== exclude) {
      const c = await resolveChannel(env, pick);
      if (c?.is_live) return { slug: pick, id: c.broadcaster_user_id };
    }
  }
  const r = await fetch(API + '/livestreams?language_code=' + encodeURIComponent(lang) + '&limit=50',
    { headers: { authorization: 'Bearer ' + await appToken(env) } });
  if (!r.ok) return null;
  const live = ((await r.json()).data || []).filter(l => l.channel?.slug !== exclude);
  if (!live.length) return null;
  const l = live[Math.floor(Math.random() * Math.min(30, live.length))];
  return { slug: l.channel.slug, id: l.broadcaster_user.id };
}

/* ---------- schema ---------- */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS kick_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT,label TEXT NOT NULL UNIQUE,kick_user_id INTEGER,kick_name TEXT,avatar TEXT,access_token TEXT,refresh_token TEXT,expires_at INTEGER DEFAULT 0,scopes TEXT,status TEXT NOT NULL DEFAULT 'active',cooldown_until INTEGER DEFAULT 0,last_used_at INTEGER DEFAULT 0,min_gap_ms INTEGER NOT NULL DEFAULT 8000,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stream_channels (id INTEGER PRIMARY KEY AUTOINCREMENT,slug TEXT NOT NULL UNIQUE,broadcaster_user_id INTEGER,lang TEXT NOT NULL DEFAULT 'en',cadence_sec INTEGER NOT NULL DEFAULT 300,state TEXT NOT NULL DEFAULT 'stopped',cursor INTEGER NOT NULL DEFAULT 0,last_content TEXT,is_live INTEGER,live_checked_at INTEGER DEFAULT 0,next_send_at INTEGER DEFAULT 0,rotate_at INTEGER DEFAULT 0,rotation INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS msg_bank (id INTEGER PRIMARY KEY AUTOINCREMENT,lang TEXT NOT NULL,content TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS msg_queue (id INTEGER PRIMARY KEY AUTOINCREMENT,channel_id INTEGER NOT NULL,account_id INTEGER,content TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,due_at INTEGER NOT NULL,error TEXT,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS send_log (id INTEGER PRIMARY KEY AUTOINCREMENT,channel_id INTEGER,account_id INTEGER,slug TEXT,content TEXT,ok INTEGER NOT NULL,http INTEGER,error TEXT,ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rotation_pool (id INTEGER PRIMARY KEY AUTOINCREMENT,lang TEXT NOT NULL,slug TEXT NOT NULL,UNIQUE(lang,slug));
CREATE TABLE IF NOT EXISTS oauth_state (state TEXT PRIMARY KEY,verifier TEXT NOT NULL,slot TEXT,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS app_kv (k TEXT PRIMARY KEY,v TEXT,exp INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_q_due ON msg_queue (status,due_at);
CREATE INDEX IF NOT EXISTS ix_log_ts ON send_log (ts DESC);
CREATE INDEX IF NOT EXISTS ix_ch_state ON stream_channels (state,next_send_at);
`;

/* ---------- engine ---------- */
async function log(env, channelId, accountId, slug, content, ok, http, error) {
  await env.DB.prepare('INSERT INTO send_log (channel_id,account_id,slug,content,ok,http,error,ts) VALUES (?,?,?,?,?,?,?,?)')
    .bind(channelId, accountId, slug, content, ok ? 1 : 0, http, error, Date.now()).run();
}
async function pickAccount(env, now) {
  return env.DB.prepare("SELECT * FROM kick_accounts WHERE status='active' AND cooldown_until<=? ORDER BY last_used_at ASC LIMIT 1")
    .bind(now).first();
}
async function enqueue(env, ch, now) {
  let msgs = (await env.DB.prepare('SELECT content FROM msg_bank WHERE lang=? AND active=1 ORDER BY id').bind(ch.lang).all()).results;
  if (!msgs.length) msgs = (await env.DB.prepare('SELECT content FROM msg_bank WHERE active=1 ORDER BY id LIMIT 200').all()).results;
  if (!msgs.length) return;
  let i = ch.cursor % msgs.length;
  let content = msgs[i].content;
  if (msgs.length > 1 && content === ch.last_content) { i = (i + 1) % msgs.length; content = msgs[i].content; }
  await env.DB.prepare('INSERT INTO msg_queue (channel_id,content,status,due_at,created_at) VALUES (?,?,?,?,?)')
    .bind(ch.id, content, 'pending', now, now).run();
  await env.DB.prepare('UPDATE stream_channels SET cursor=?, next_send_at=? WHERE id=?')
    .bind(i + 1, now + Math.round(ch.cadence_sec * 1000 * (0.75 + Math.random() * 0.5)), ch.id).run();
}
async function dispatch(env, now) {
  const due = (await env.DB.prepare(
    `SELECT q.id,q.content,q.attempts,q.channel_id,c.slug,c.broadcaster_user_id FROM msg_queue q
     JOIN stream_channels c ON c.id=q.channel_id WHERE q.status='pending' AND q.due_at<=? ORDER BY q.due_at LIMIT ?`
  ).bind(now, MAX_PER_TICK).all()).results;

  for (const row of due) {
    const acc = await pickAccount(env, Date.now());
    if (!acc) break;
    if (!row.broadcaster_user_id) {
      const c = await resolveChannel(env, row.slug);
      if (!c) { await env.DB.prepare("UPDATE msg_queue SET status='failed', error='slug not found' WHERE id=?").bind(row.id).run(); continue; }
      row.broadcaster_user_id = c.broadcaster_user_id;
      await env.DB.prepare('UPDATE stream_channels SET broadcaster_user_id=? WHERE id=?').bind(c.broadcaster_user_id, row.channel_id).run();
    }
    const res = await sendChat(env, acc, row.broadcaster_user_id, row.content);
    const stamp = Date.now();
    if (res.ok) {
      await env.DB.prepare("UPDATE msg_queue SET status='sent', account_id=? WHERE id=?").bind(acc.id, row.id).run();
      await env.DB.prepare('UPDATE kick_accounts SET last_used_at=?, cooldown_until=? WHERE id=?').bind(stamp, stamp + acc.min_gap_ms, acc.id).run();
      await env.DB.prepare('UPDATE stream_channels SET last_content=? WHERE id=?').bind(row.content, row.channel_id).run();
      await log(env, row.channel_id, acc.id, row.slug, row.content, true, res.http, null);
      continue;
    }
    const wait = (res.retryAfter || 5) * 1000;
    if (res.http === 429) await env.DB.prepare('UPDATE kick_accounts SET cooldown_until=? WHERE id=?').bind(stamp + wait, acc.id).run();
    if (res.http === 401 || res.http === 403) await env.DB.prepare("UPDATE kick_accounts SET status='needs_reauth' WHERE id=?").bind(acc.id).run();
    const attempts = row.attempts + 1;
    await env.DB.prepare('UPDATE msg_queue SET status=?, attempts=?, due_at=?, error=? WHERE id=?')
      .bind(attempts >= 3 ? 'failed' : 'pending', attempts, stamp + wait, res.http + ' ' + res.body, row.id).run();
    await log(env, row.channel_id, acc.id, row.slug, row.content, false, res.http, res.body);
    if (res.http === 429) break;
  }
}
async function tick(env) {
  const now = Date.now();
  const running = (await env.DB.prepare("SELECT * FROM stream_channels WHERE state='running'").all()).results;
  if (!running.length) return;

  const accts = (await env.DB.prepare("SELECT * FROM kick_accounts WHERE status IN ('active','cooldown')").all()).results;
  for (const a of accts) {
    if (a.expires_at - now < 300000) {
      try { await refreshAccount(env, a); }
      catch { await env.DB.prepare("UPDATE kick_accounts SET status='needs_reauth' WHERE id=?").bind(a.id).run(); }
    }
  }

  for (const ch of running) {
    if (!ch.rotation || ch.rotate_at > now) continue;
    const next = await pickLive(env, ch.lang, ch.slug);
    if (next) {
      await env.DB.prepare('UPDATE stream_channels SET slug=?, broadcaster_user_id=?, rotate_at=?, is_live=1, live_checked_at=? WHERE id=?')
        .bind(next.slug, next.id, now + ch.cadence_sec * 1000, now, ch.id).run();
      await log(env, ch.id, null, next.slug, 'rotated', true, 200, null);
    } else {
      await env.DB.prepare('UPDATE stream_channels SET rotate_at=? WHERE id=?').bind(now + 60000, ch.id).run();
    }
  }

  const stale = running.filter(c => now - c.live_checked_at > LIVE_TTL && c.broadcaster_user_id);
  if (stale.length) {
    const map = await liveMap(env, stale.map(c => c.broadcaster_user_id));
    for (const c of stale) {
      const live = map[c.broadcaster_user_id] ? 1 : 0;
      await env.DB.prepare('UPDATE stream_channels SET is_live=?, live_checked_at=? WHERE id=?').bind(live, now, c.id).run();
      c.is_live = live;
      if (!live) c.next_send_at = now + 120000;
    }
  }

  for (const ch of running) if (ch.is_live !== 0 && ch.next_send_at <= now) await enqueue(env, ch, now);
  await dispatch(env, now);
}

/* ---------- dashboard ---------- */
const EMO = ['😀','😂','🔥','👋','❤️','👍','🎮','🏆','😎','🤝','💯','🚀','😮','🙏','💪','✨','🎉','👀','😭','🤣','🥇','⚡','🫡','🙌'];

const DASH = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Stream AI Studio V6 - Status</title>
<style>body{margin:0;background:#101814;color:#e8f1eb;font:16px system-ui}main{max-width:720px;margin:auto;padding:22px}section{border:1px solid #415448;border-radius:12px;padding:16px;margin:16px 0;background:#19241d}button,input{font:inherit;padding:12px;border-radius:8px;border:1px solid #64796b;background:#26372d;color:#fff}input{box-sizing:border-box;width:100%;margin:8px 0}button{margin:5px 5px 5px 0;cursor:pointer}#stop{background:#a92530;border-color:#ed6973;font-weight:bold}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:340px;overflow:auto}[hidden]{display:none!important}</style></head>
<body><main><h1>Stream AI Studio V6</h1><p>Status and emergency stop</p>
<section id="gate"><form id="login"><label for="pass">Dashboard passphrase</label><input id="pass" type="password" required autocomplete="current-password"><button type="submit">Unlock</button></form></section>
<p id="notice" role="status" aria-live="polite"></p>
<div id="panel" hidden><section><h2>Emergency controls</h2><button id="stop" type="button">STOP ALL</button><button id="refresh" type="button">Refresh status</button><button id="logout" type="button">Log out</button></section>
<section><h2>Current status</h2><pre id="stats"></pre></section><section><h2>Recent history</h2><pre id="history"></pre></section></div>
</main><script>
const el = id => document.getElementById(id);
async function request(path, method = 'GET', body) {
  const options = { method, credentials: 'same-origin', cache: 'no-store' };
  if (body !== undefined) { options.headers = {'content-type':'application/json'}; options.body = JSON.stringify(body); }
  const r = await fetch(path, options); const data = await r.json();
  if (!r.ok) throw new Error(data.error || 'Request failed: ' + r.status);
  return data;
}
function show(open) { el('gate').hidden = open; el('panel').hidden = !open; if(!open){el('stats').textContent='';el('history').textContent='';} }
async function refresh() {
  const s = await request('/api/stats');
  el('stats').textContent = ['Sent (24h): '+s.sent24h,'Failed (24h): '+s.fail24h,'Pending: '+s.queued,'Live: '+s.live,'Accounts: '+s.accounts].join('\n');
  const h = await request('/api/log');
  el('history').textContent = h.map(x=>new Date(x.ts).toLocaleString()+' | '+x.slug+' | '+(x.ok?'OK':'Failed')+' | '+x.content).join('\n') || 'No history';
  show(true);
}
const notice = msg => {el('notice').textContent=msg;};
el('login').onsubmit=async e=>{e.preventDefault();try{await request('/api/login','POST',{pass:el('pass').value}); el('pass').value=''; await refresh();notice('Unlocked');}catch(e){notice(e.message);}};
el('refresh').onclick=()=>refresh().catch(e=>notice(e.message));
el('stop').onclick=async()=>{if(!confirm('Stop all channels and cancel pending messages?'))return;el('stop').disabled=true;try{const r=await request('/api/stop','POST');if(!r.stopped||!r.queue_cancelled)throw new Error('Stop not confirmed');notice('Stop recorded. In-flight requests may still finish.');try{await refresh();}catch(e){notice('Stop recorded. Status refresh failed: '+e.message);}}catch(e){notice('Stop not confirmed: '+e.message);}finally{el('stop').disabled=false;}};
el('logout').onclick=async()=>{try{await request('/api/logout','POST');show(false);notice('Logged out');}catch(e){notice(e.message);}};
refresh().catch(()=>show(false));
</script></body></html>`;
/* ---------- router ---------- */
const json = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', ...h } });
const cookie = (req, name) => {
  const hit = (req.headers.get('cookie') || '').split(';').map(p => p.trim()).find(p => p.startsWith(name + '='));
  return hit ? hit.slice(name.length + 1) : null;
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    const cors = {
      'access-control-allow-origin': env.ALLOWED_ORIGIN || url.origin,
      'access-control-allow-credentials': 'true',
      'access-control-allow-headers': 'content-type',
      'access-control-allow-methods': 'GET,POST,PATCH,DELETE,OPTIONS'
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });

    try {
      if (p === '/' && req.method === 'GET')
        return new Response(DASH, { headers: { 'content-type': 'text/html; charset=utf-8' } });
      if (p === '/api/health') return json({ ok: true, now: Date.now() }, 200, cors);

      if (p === '/api/init' && req.method === 'POST') {
        const b = await req.json().catch(() => ({}));
        if (b.key !== env.DASHBOARD_PASS) return json({ error: 'bad key' }, 401, cors);
        await env.DB.exec(SCHEMA);
        return json({ ok: true, tables: 8 }, 200, cors);
      }

      if (p === '/api/login' && req.method === 'POST') {
        const { pass } = await req.json().catch(() => ({}));
        if (!pass || pass !== env.DASHBOARD_PASS) return json({ error: 'wrong passphrase' }, 401, cors);
        return json({ ok: true }, 200, { ...cors, 'set-cookie': `sas=${await signSession(env)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000` });
      }
      if (p === '/api/logout' && req.method === 'POST')
        return json({ ok: true }, 200, { ...cors, 'set-cookie': 'sas=; Path=/; Max-Age=0' });

      if (p === '/auth/login') {
        if (!await readSession(env, cookie(req, 'sas'))) return Response.redirect(url.origin + '/', 302);
        const slot = (url.searchParams.get('slot') || 'account').slice(0, 32);
        const state = crypto.randomUUID();
        const { verifier, challenge } = await pkce();
        await env.DB.prepare('INSERT INTO oauth_state (state,verifier,slot,expires_at) VALUES (?,?,?,?)')
          .bind(state, verifier, slot, Date.now() + 600000).run();
        return Response.redirect(authorizeUrl(env, state, challenge), 302);
      }

      if (p === '/auth/callback') {
        const state = url.searchParams.get('state'), code = url.searchParams.get('code');
        const row = await env.DB.prepare('SELECT * FROM oauth_state WHERE state=?').bind(state).first();
        if (!row || row.expires_at < Date.now()) return new Response('bad state', { status: 400 });
        await env.DB.prepare('DELETE FROM oauth_state WHERE state=?').bind(state).run();
        if (!code) return new Response('no code', { status: 400 });
        const t = await exchangeCode(env, code, row.verifier);
        const me = await (await fetch(API + '/users', { headers: { authorization: 'Bearer ' + t.access_token } })).json();
        const u = me.data?.[0];
        if (!u) return new Response('profile lookup failed', { status: 400 });
        await env.DB.prepare(
          `INSERT INTO kick_accounts (label,kick_user_id,kick_name,avatar,access_token,refresh_token,expires_at,scopes,status,created_at)
           VALUES (?,?,?,?,?,?,?,?,'active',?) ON CONFLICT(label) DO UPDATE SET kick_user_id=excluded.kick_user_id,
           kick_name=excluded.kick_name, avatar=excluded.avatar, access_token=excluded.access_token,
           refresh_token=excluded.refresh_token, expires_at=excluded.expires_at, scopes=excluded.scopes, status='active'`
        ).bind(row.slot, u.user_id, u.name, u.profile_picture, await seal(env, t.access_token),
          t.refresh_token ? await seal(env, t.refresh_token) : null,
          Date.now() + (t.expires_in || 3600) * 1000 - 5000, t.scope || '', Date.now()).run();
        return Response.redirect(url.origin + '/?linked=' + encodeURIComponent(u.name), 302);
      }

      if (!await readSession(env, cookie(req, 'sas'))) return json({ error: 'auth' }, 401, cors);
      const m = p.match(/^\/api\/([a-z]+)(?:\/(\d+))?$/);
      if (!m) return json({ error: 'not found' }, 404, cors);
      const res = m[1], id = m[2];
      const body = ['POST', 'PATCH'].includes(req.method) ? await req.json().catch(() => ({})) : {};

      if (res === 'accounts') {
        if (req.method === 'GET') return json((await env.DB.prepare(
          'SELECT id,label,kick_name,avatar,status,expires_at,last_used_at,min_gap_ms,(expires_at>?) AS fresh FROM kick_accounts ORDER BY id')
          .bind(Date.now()).all()).results, 200, cors);
        if (req.method === 'PATCH' && id) {
          if (body.status) await env.DB.prepare('UPDATE kick_accounts SET status=? WHERE id=?').bind(body.status, id).run();
          if (body.min_gap_ms) await env.DB.prepare('UPDATE kick_accounts SET min_gap_ms=? WHERE id=?').bind(body.min_gap_ms, id).run();
          return json({ ok: true }, 200, cors);
        }
        if (req.method === 'DELETE' && id) {
          await env.DB.prepare('DELETE FROM kick_accounts WHERE id=?').bind(id).run();
          return json({ ok: true }, 200, cors);
        }
      }

      if (res === 'channels') {
        if (req.method === 'GET') return json((await env.DB.prepare('SELECT * FROM stream_channels ORDER BY id').all()).results, 200, cors);
        if (req.method === 'POST') {
          const slug = String(body.slug || '').trim().toLowerCase().replace(/^.*kick\.com\//, '').replace(/[/?#].*$/, '');
          if (!slug) return json({ error: 'slug required' }, 400, cors);
          const found = await resolveChannel(env, slug);
          await env.DB.prepare(
            `INSERT INTO stream_channels (slug,broadcaster_user_id,lang,cadence_sec,created_at,rotate_at,next_send_at)
             VALUES (?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET lang=excluded.lang, cadence_sec=excluded.cadence_sec`
          ).bind(slug, found?.broadcaster_user_id || null, body.lang || 'en',
            Math.max(30, Number(body.cadence_sec) || 300), Date.now(), Date.now() + 300000, Date.now() + 15000).run();
          return json({ ok: true, live: !!found?.is_live }, 200, cors);
        }
        if (req.method === 'PATCH' && id) {
          if (body.state) await env.DB.prepare('UPDATE stream_channels SET state=? WHERE id=?').bind(body.state, id).run();
          if (body.lang) await env.DB.prepare('UPDATE stream_channels SET lang=? WHERE id=?').bind(body.lang, id).run();
          if (body.cadence_sec) await env.DB.prepare('UPDATE stream_channels SET cadence_sec=? WHERE id=?').bind(Math.max(30, Number(body.cadence_sec)), id).run();
          if (body.rotation !== undefined) await env.DB.prepare('UPDATE stream_channels SET rotation=? WHERE id=?').bind(body.rotation ? 1 : 0, id).run();
          return json({ ok: true }, 200, cors);
        }
        if (req.method === 'DELETE' && id) {
          await env.DB.prepare('DELETE FROM stream_channels WHERE id=?').bind(id).run();
          return json({ ok: true }, 200, cors);
        }
      }

      if (res === 'messages') {
        if (req.method === 'GET') return json((await env.DB.prepare('SELECT lang, COUNT(*) n FROM msg_bank WHERE active=1 GROUP BY lang').all()).results, 200, cors);
        if (req.method === 'POST') {
          const lang = body.lang || 'en';
          const lines = String(body.text || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean).slice(0, 5000);
          for (const line of lines) await env.DB.prepare('INSERT INTO msg_bank (lang,content,created_at) VALUES (?,?,?)').bind(lang, truncate(line), Date.now()).run();
          return json({ ok: true, added: lines.length }, 200, cors);
        }
        if (req.method === 'DELETE') {
          if (id) await env.DB.prepare('DELETE FROM msg_bank WHERE id=?').bind(id).run();
          else await env.DB.prepare('DELETE FROM msg_bank WHERE lang=?').bind(url.searchParams.get('lang') || 'en').run();
          return json({ ok: true }, 200, cors);
        }
      }

      if (res === 'stop' && req.method === 'POST') {
        await env.DB.batch([
          env.DB.prepare("UPDATE stream_channels SET state='stopped'"),
          env.DB.prepare("UPDATE msg_queue SET status='cancelled' WHERE status='pending'")
        ]);
        return json({ ok: true, stopped: true, queue_cancelled: true }, 200, cors);
      }

if (res === 'msglist' && req.method === 'GET')
        return json((await env.DB.prepare('SELECT id,content FROM msg_bank WHERE lang=? AND active=1 ORDER BY id DESC LIMIT 60')
          .bind(url.searchParams.get('lang') || 'en').all()).results, 200, cors);

      if (res === 'pool') {
        if (req.method === 'GET') return json((await env.DB.prepare('SELECT * FROM rotation_pool ORDER BY lang,slug').all()).results, 200, cors);
        if (req.method === 'POST') {
          for (const s of String(body.text || '').split(/[,\r\n]+/).map(x => x.trim().toLowerCase()).filter(Boolean))
            await env.DB.prepare('INSERT OR IGNORE INTO rotation_pool (lang,slug) VALUES (?,?)').bind(body.lang || 'en', s).run();
          return json({ ok: true }, 200, cors);
        }
        if (req.method === 'DELETE') {
          await env.DB.prepare('DELETE FROM rotation_pool WHERE lang=?').bind(url.searchParams.get('lang') || 'en').run();
          return json({ ok: true }, 200, cors);
        }
      }

      if (res === 'run' && req.method === 'POST') {
        if (id) await env.DB.prepare("UPDATE stream_channels SET state='running', next_send_at=? WHERE id=?").bind(Date.now(), id).run();
        else await env.DB.prepare("UPDATE stream_channels SET state='running', next_send_at=? WHERE state='stopped'").bind(Date.now()).run();
        return json({ ok: true }, 200, cors);
      }
     
      if (res === 'rotate' && req.method === 'POST') {
        await env.DB.prepare("UPDATE stream_channels SET rotate_at=0 WHERE state='running'").run();
        return json({ ok: true }, 200, cors);
      }

      if (res === 'manual' && req.method === 'POST') {
        const ch = await env.DB.prepare('SELECT * FROM stream_channels WHERE id=?').bind(body.channel_id).first();
        if (!ch) return json({ error: 'no channel' }, 404, cors);
        let bid = ch.broadcaster_user_id;
        if (!bid) { const c = await resolveChannel(env, ch.slug); bid = c?.broadcaster_user_id; }
        if (!bid) return json({ error: 'channel unresolved' }, 400, cors);
        const acc = await pickAccount(env, Date.now());
        if (!acc) return json({ error: 'no account free' }, 409, cors);
        const r = await sendChat(env, acc, bid, body.content || '');
        const stamp = Date.now();
        if (r.ok) await env.DB.prepare('UPDATE kick_accounts SET last_used_at=?, cooldown_until=? WHERE id=?').bind(stamp, stamp + acc.min_gap_ms, acc.id).run();
        await log(env, ch.id, acc.id, ch.slug, body.content, r.ok, r.http, r.body);
        return json({ ok: r.ok, http: r.http, as: acc.kick_name, error: r.ok ? null : r.body }, 200, cors);
      }

      if (res === 'log' && req.method === 'GET')
        return json((await env.DB.prepare('SELECT id,slug,content,ok,http,error,ts FROM send_log ORDER BY id DESC LIMIT 80').all()).results, 200, cors);

      if (res === 'stats' && req.method === 'GET') {
        const day = Date.now() - 864e5;
        return json({
          sent24h: (await env.DB.prepare('SELECT COUNT(*) n FROM send_log WHERE ok=1 AND ts>?').bind(day).first()).n,
          fail24h: (await env.DB.prepare('SELECT COUNT(*) n FROM send_log WHERE ok=0 AND ts>?').bind(day).first()).n,
          queued: (await env.DB.prepare("SELECT COUNT(*) n FROM msg_queue WHERE status='pending'").first()).n,
          live: (await env.DB.prepare('SELECT COUNT(*) n FROM stream_channels WHERE is_live=1').first()).n,
          accounts: (await env.DB.prepare("SELECT COUNT(*) n FROM kick_accounts WHERE status='active'").first()).n
        }, 200, cors);
      }

      return json({ error: 'not found' }, 404, cors);
    } catch (e) {
      return json({ error: String(e.message || e) }, 500, cors);
    }
  },

  async scheduled(event, env, ctx) { ctx.waitUntil(tick(env)); }
};
