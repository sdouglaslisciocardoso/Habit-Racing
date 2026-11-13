// RC Life: servidor de avisos (Cloudflare Worker), multiusuário
// Precisa de: KV "HRC" (chaves VAPID), banco D1 "DB" (agendas, contador anônimo de uso e limites da IA) e Cron Trigger "* * * * *".
// Opcional: secret ANTHROPIC_KEY (liga a IA compartilhada para quem não tem chave própria).
// Secret ADMIN_H: hash do código de acesso do painel do dono (painel.html). Sem ele, o painel fica fechado.
//   Valor = SHA-256 do código, em base64url sem "=" (o mesmo formato da função sha() abaixo).
// Deploy: painel da Cloudflare > Workers > habit-rc-avisos > Editar código, colar este arquivo e salvar.
// Contas: login com Google (só identidade) + sessão própria; os dados de cada conta ficam separados no D1.
// Cada aparelho tem um token aleatório; o servidor guarda só o hash dele, o endereço de push e a agenda dos avisos.

// Só o site do RC Life pode chamar este servidor pelo navegador
const ORIGINS = ['https://sdouglaslisciocardoso.github.io'];
// cabeçalhos de cada resposta (um objeto por pedido: pedidos simultâneos não se misturam)
const hdrs = o => { const h = { 'Vary': 'Origin', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' }; if (ORIGINS.includes(o)) Object.assign(h, { 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'content-type', 'Access-Control-Max-Age': '600' }); return h; };
// freio contra robôs: cada endereço de internet pode fazer poucos pedidos por minuto (por instância do servidor)
const RL = new Map();
function tooMany(ip, max) { const now = Date.now(), k = ip || '-'; let r = RL.get(k); if (!r || now - r.t > 60000) { r = { t: now, n: 0 }; RL.set(k, r); } r.n++; if (RL.size > 5000) for (const [a, v] of RL) if (now - v.t > 60000) RL.delete(a); return r.n > max; }
// comparação em tempo constante (não vaza o token por tempo de resposta)
const same = (a, b) => { a = String(a); b = String(b); let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; };
async function body(req, max = 400000) { const n = Number(req.headers.get('content-length') || 0); if (n > max) return null; const t = await req.text(); if (t.length > max) return null; try { return JSON.parse(t); } catch (e) { return {}; } }
const te = new TextEncoder();
const b64u = b => { let s = ''; new Uint8Array(b).forEach(c => s += String.fromCharCode(c)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const ub64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); const r = atob(s + '==='.slice((s.length + 3) % 4)); return Uint8Array.from(r, c => c.charCodeAt(0)); };
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; a.forEach(x => { o.set(x, i); i += x.length; }); return o; };

// Chaves VAPID: criadas sozinhas no primeiro uso e guardadas no KV
async function vapid(env) {
  let v = await env.HRC.get('v', 'json');
  if (v) return v;
  const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  v = { pub: b64u(await crypto.subtle.exportKey('raw', k.publicKey)), jwk: await crypto.subtle.exportKey('jwk', k.privateKey) };
  await env.HRC.put('v', JSON.stringify(v));
  return v;
}

async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}

// Criptografia do conteúdo (RFC 8291, aes128gcm)
async function encrypt(sub, data) {
  const ua = ub64(sub.keys.p256dh), auth = ub64(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, ecdh, cat(te.encode('WebPush: info\0'), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(data, new Uint8Array([2]))));
  const hdr = new Uint8Array(86); hdr.set(salt, 0); new DataView(hdr.buffer).setUint32(16, 4096); hdr[20] = 65; hdr.set(asPub, 21);
  return cat(hdr, ct);
}

async function push(env, u, msg) {
  const v = await vapid(env);
  const aud = new URL(u.sub.endpoint).origin;
  const head = b64u(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u(te.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: u.origin && u.origin.startsWith('https://') ? u.origin : 'https://habit-rc.app' })));
  const key = await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(head + '.' + body));
  const payload = await encrypt(u.sub, te.encode(JSON.stringify(msg)));
  return fetch(u.sub.endpoint, {
    method: 'POST',
    headers: { TTL: '3600', Urgency: 'high', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', Authorization: `vapid t=${head}.${body}.${b64u(sig)}, k=${v.pub}` },
    body: payload
  });
}

const sha = async t => b64u(await crypto.subtle.digest('SHA-256', te.encode(String(t))));
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS u (id TEXT PRIMARY KEY, sub TEXT, origin TEXT, items TEXT, nxt INTEGER, sent INTEGER DEFAULT 0, at INTEGER, lt INTEGER DEFAULT 0)",
  "CREATE INDEX IF NOT EXISTS u_nxt ON u(nxt)",
  // contador anônimo de uso: só o hash de um código aleatório do aparelho, sem nenhum dado pessoal
  "CREATE TABLE IF NOT EXISTS pg (d TEXT PRIMARY KEY, f INTEGER, l INTEGER, n INTEGER DEFAULT 1, p TEXT, i INTEGER DEFAULT 0)",
  "CREATE INDEX IF NOT EXISTS pg_l ON pg(l)",
  "CREATE TABLE IF NOT EXISTS pd (dy TEXT, d TEXT, PRIMARY KEY (dy, d))",
  "CREATE TABLE IF NOT EXISTS ai (d TEXT, dy TEXT, n INTEGER DEFAULT 0, PRIMARY KEY (d, dy))",
  // contas: o Google só confirma quem é a pessoa; os dados de cada conta ficam separados aqui
  "CREATE TABLE IF NOT EXISTS acct (sub TEXT PRIMARY KEY, em TEXT, nm TEXT, ct INTEGER, la INTEGER)",
  "CREATE TABLE IF NOT EXISTS ses (h TEXT PRIMARY KEY, sub TEXT, exp INTEGER, ct INTEGER)",
  "CREATE INDEX IF NOT EXISTS ses_sub ON ses(sub)",
  "CREATE TABLE IF NOT EXISTS dat (sub TEXT PRIMARY KEY, upd INTEGER, b TEXT, at INTEGER)"
];
// ---------- login com Google (só identidade) e sessão própria de longa duração ----------
const GID = '1084181239561-43t77l64li8nh7q1fa902ndj9fofae5t.apps.googleusercontent.com';
const SES_DAYS = 180, DAT_MAX = 1900000;
let JWKS = null;
async function gKeys(force) {
  if (JWKS && !force && Date.now() < JWKS.exp) return JWKS.k;
  const r = await fetch('https://www.googleapis.com/oauth2/v3/certs');
  if (!r.ok) throw new Error('certs');
  const j = await r.json(), m = /max-age=(\d+)/.exec(r.headers.get('cache-control') || '');
  JWKS = { k: j.keys || [], exp: Date.now() + Math.min(Number(m && m[1]) || 3600, 21600) * 1000 };
  return JWKS.k;
}
// confere a assinatura e os dados do "ID token" que o Google entrega ao app
async function verifyIdt(idt) {
  const p = String(idt || '').split('.');
  if (p.length !== 3) throw new Error('formato');
  const dj = s => JSON.parse(new TextDecoder().decode(ub64(s)));
  const h = dj(p[0]), c = dj(p[1]);
  if (h.alg !== 'RS256') throw new Error('alg');
  let k = (await gKeys()).find(x => x.kid === h.kid);
  if (!k) k = (await gKeys(true)).find(x => x.kid === h.kid);
  if (!k) throw new Error('chave');
  const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: k.n, e: k.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, ub64(p[2]), te.encode(p[0] + '.' + p[1]));
  if (!ok) throw new Error('assinatura');
  const now = Date.now() / 1000;
  if (c.aud !== GID) throw new Error('aud');
  if (c.iss !== 'accounts.google.com' && c.iss !== 'https://accounts.google.com') throw new Error('iss');
  if (!(c.exp > now - 60) || !(c.iat < now + 300) || !(c.iat > now - 900)) throw new Error('expirado');
  if (!c.sub) throw new Error('sub');
  return c;
}
async function sesOf(D, tk) {
  if (!/^[a-f0-9]{64}$/.test(String(tk || ''))) return null;
  const h = await sha('ses:' + tk), r = await D.prepare('SELECT sub, exp FROM ses WHERE h=?').bind(h).first();
  if (!r || r.exp < Date.now()) return null;
  // sessão se renova sozinha enquanto a pessoa usa
  if (r.exp - Date.now() < (SES_DAYS - 7) * 864e5) await D.prepare('UPDATE ses SET exp=? WHERE h=?').bind(Date.now() + SES_DAYS * 864e5, h).run();
  return r.sub;
}
// IA compartilhada: a chave fica só no secret ANTHROPIC_KEY do Cloudflare, nunca no app
const AI_LIM = 40;     // pedidos por aparelho por dia
const AI_DAY = 1500;   // teto total por dia (protege os créditos)
const AI_IP = 80;      // pedidos por endereço de internet por dia (trocar o código do aparelho não fura o limite)
const AI_MODEL = 'claude-sonnet-5-5';
// só ferramentas do próprio app (nada de ferramentas pagas do lado da Anthropic) e só mensagens de usuário/IA
const aiTools = t => Array.isArray(t) && JSON.stringify(t).length < 120000 ? t.filter(x => x && typeof x.name === 'string' && x.input_schema && typeof x.input_schema === 'object' && (!x.type || x.type === 'custom')).slice(0, 80).map(x => ({ name: x.name.slice(0, 64), description: String(x.description || '').slice(0, 2000), input_schema: x.input_schema })) : null;
// últimas 40 mensagens, sempre começando por uma pergunta da pessoa (nunca no meio de um pedido de ferramenta)
const aiMsgs = m => { const r = m.slice(-40).filter(x => x && (x.role === 'user' || x.role === 'assistant')).map(x => ({ role: x.role, content: x.content })); while (r.length && !(r[0].role === 'user' && (typeof r[0].content === 'string' || (Array.isArray(r[0].content) && !r[0].content.some(c => c && c.type === 'tool_result'))))) r.shift(); return r; };
// painel do dono: só quem tem o código de acesso vê os números; o hash dele fica no secret ADMIN_H da Cloudflare
// (fora do código, porque este repositório é público)
const dia = (t, off = 0) => new Date(t - 3 * 36e5 - off * 864e5).toISOString().slice(0, 10); // dia no horário de Brasília
let ready = false;
async function db(env) { if (!ready) { for (const q of SCHEMA) await env.DB.prepare(q).run(); ready = true; } return env.DB; }
const nextTs = (items, after) => { let m = null; for (const i of items) if (i.ts > after && (m === null || i.ts < m)) m = i.ts; return m; };
const ENDPOINT = /^https:\/\/[a-z0-9.-]+\.(push\.apple\.com|googleapis\.com|mozilla\.com|mozaws\.net|notify\.windows\.com)\//i;

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin'), H = hdrs(origin), ip = req.headers.get('CF-Connecting-IP') || '';
    const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...H, 'content-type': 'application/json' } });
    const aiErr = (m, s) => json({ error: { message: m } }, s);
    if (req.method === 'OPTIONS') return new Response(null, { status: ORIGINS.includes(origin) ? 204 : 403, headers: H });
    if (req.method === 'POST' && origin && !ORIGINS.includes(origin)) return json({ erro: 'origem não permitida' }, 403);
    if (!env.HRC || !env.DB) return json({ erro: 'Servidor sem KV (HRC) ou banco (DB) ligado.' }, 500);
    const p = new URL(req.url).pathname;
    // freio por endereço (a sincronização com sessão tem folga maior: confere a cada 5 s)
    if (req.method === 'POST' && tooMany(ip, p.startsWith('/data/') ? 240 : 60)) return json({ erro: 'Muitos pedidos seguidos. Espere um minuto.' }, 429);
    if (p === '/vapid') return json({ publicKey: (await vapid(env)).pub });
    if (p === '/ai') {
      const on = !!env.ANTHROPIC_KEY;
      if (req.method !== 'POST') return json({ on, lim: AI_LIM });
      if (!ORIGINS.includes(origin)) return aiErr('origem não permitida', 403);
      if (!on) return aiErr('A IA do app ainda não foi ligada.', 503);
      const b = await body(req);
      if (!b || !/^[a-f0-9]{32}$/.test(String(b.d)) || !b.b || !Array.isArray(b.b.messages)) return aiErr('pedido inválido', 400);
      const D = await db(env), now = Date.now(), hj = dia(now), id = await sha('ai:' + b.d), ipId = await sha('aip:' + ip);
      const [me, byIp, all] = await Promise.all([
        D.prepare('SELECT n FROM ai WHERE d=? AND dy=?').bind(id, hj).first(),
        D.prepare('SELECT n FROM ai WHERE d=? AND dy=?').bind(ipId, hj).first(),
        D.prepare("SELECT n FROM ai WHERE d='*' AND dy=?").bind(hj).first()
      ]);
      if ((me && me.n >= AI_LIM) || (byIp && byIp.n >= AI_IP)) return aiErr('Você usou os ' + AI_LIM + ' pedidos de IA de hoje. Amanhã libera de novo.', 429);
      if (all && all.n >= AI_DAY) return aiErr('A IA do app atingiu o limite de hoje. Amanhã libera de novo.', 429);
      const x = b.b, q = { model: AI_MODEL, max_tokens: Math.min(Math.max(+x.max_tokens || 600, 50), 4000), messages: aiMsgs(x.messages) };
      if (!q.messages.length) return aiErr('pedido inválido', 400);
      if (typeof x.system === 'string') q.system = x.system.slice(0, 80000);
      const tl = aiTools(x.tools); if (tl && tl.length) q.tools = tl;
      await D.batch([
        D.prepare('INSERT INTO ai (d,dy,n) VALUES (?,?,1) ON CONFLICT(d,dy) DO UPDATE SET n=n+1').bind(id, hj),
        D.prepare('INSERT INTO ai (d,dy,n) VALUES (?,?,1) ON CONFLICT(d,dy) DO UPDATE SET n=n+1').bind(ipId, hj),
        D.prepare("INSERT INTO ai (d,dy,n) VALUES ('*',?,1) ON CONFLICT(d,dy) DO UPDATE SET n=n+1").bind(hj)
      ]);
      try {
        const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' }, body: JSON.stringify(q) });
        if (r.status === 401 || r.status === 403) return aiErr('A IA do app está indisponível no momento.', 503);
        return new Response(await r.text(), { status: r.status, headers: { ...H, 'content-type': 'application/json' } });
      } catch (e) { return aiErr('Não consegui falar com a IA agora. Tente de novo.', 502); }
    }
    if (req.method === 'POST' && p === '/auth') {
      const b = await body(req);
      if (!b || !b.idt) return json({ erro: 'login' }, 400);
      let c; try { c = await verifyIdt(b.idt); } catch (e) { return json({ erro: 'Login do Google não confirmado (' + e.message + ').' }, 401); }
      const D = await db(env), now = Date.now(), tk = [...crypto.getRandomValues(new Uint8Array(32))].map(x => x.toString(16).padStart(2, '0')).join('');
      await D.batch([
        D.prepare('INSERT INTO acct (sub,em,nm,ct,la) VALUES (?1,?2,?3,?4,?4) ON CONFLICT(sub) DO UPDATE SET em=?2, nm=?3, la=?4').bind(String(c.sub), String(c.email || '').slice(0, 200), String(c.name || '').slice(0, 120), now),
        D.prepare('INSERT INTO ses (h,sub,exp,ct) VALUES (?,?,?,?)').bind(await sha('ses:' + tk), String(c.sub), now + SES_DAYS * 864e5, now),
        D.prepare('DELETE FROM ses WHERE exp < ?').bind(now),
        D.prepare('DELETE FROM ses WHERE sub=?1 AND h NOT IN (SELECT h FROM ses WHERE sub=?1 ORDER BY ct DESC LIMIT 20)').bind(String(c.sub))
      ]);
      return json({ tk, em: c.email || '', nm: c.name || '' });
    }
    if (req.method === 'POST' && p.startsWith('/data/') || req.method === 'POST' && p === '/logout') {
      const b = await body(req, DAT_MAX + 4000);
      if (!b) return json({ erro: 'Seus dados passaram do tamanho máximo da sincronização.' }, 413);
      const D = await db(env), sub = await sesOf(D, b.tk);
      if (!sub) return json({ erro: 'sessao' }, 401);
      if (p === '/logout') { await D.prepare('DELETE FROM ses WHERE h=?').bind(await sha('ses:' + b.tk)).run(); return json({ ok: true }); }
      if (p === '/data/head') { const r = await D.prepare('SELECT upd FROM dat WHERE sub=?').bind(sub).first(); return json({ upd: r ? r.upd : 0 }); }
      if (p === '/data/get') { const r = await D.prepare('SELECT upd, b FROM dat WHERE sub=?').bind(sub).first(); return json(r ? { upd: r.upd, b: r.b } : { upd: 0 }); }
      if (p === '/data/del') { await D.prepare('DELETE FROM dat WHERE sub=?').bind(sub).run(); return json({ ok: true }); }
      if (p === '/data/put') {
        const upd = Math.floor(Number(b.upd)), base = Math.floor(Number(b.base) || 0), blob = typeof b.b === 'string' ? b.b : '';
        if (!(upd > 0) || !blob) return json({ erro: 'dados' }, 400);
        if (blob.length > DAT_MAX) return json({ erro: 'Seus dados passaram do tamanho máximo da sincronização.' }, 413);
        const now = Date.now(), cur = await D.prepare('SELECT upd FROM dat WHERE sub=?').bind(sub).first();
        // só grava se ninguém mudou desde a última vez que este aparelho viu (senão ele junta antes)
        if (cur && cur.upd !== base) return json({ conflito: 1, upd: cur.upd }, 409);
        const r = cur ? await D.prepare('UPDATE dat SET upd=?, b=?, at=? WHERE sub=? AND upd=?').bind(upd, blob, now, sub, base).run()
                      : await D.prepare('INSERT OR IGNORE INTO dat (sub,upd,b,at) VALUES (?,?,?,?)').bind(sub, upd, blob, now).run();
        if (!r.meta || !r.meta.changes) { const c2 = await D.prepare('SELECT upd FROM dat WHERE sub=?').bind(sub).first(); return json({ conflito: 1, upd: c2 ? c2.upd : 0 }, 409); }
        return json({ ok: true, upd });
      }
      return json({ erro: 'rota' }, 404);
    }
    if (req.method === 'POST' && p === '/ping') {
      const b = await body(req);
      if (!b || !/^[a-f0-9]{32}$/.test(String(b.d))) return json({ erro: 'aparelho' }, 400);
      const D = await db(env), id = await sha('pg:' + b.d), now = Date.now();
      const pf = ['ios', 'android', 'desktop'].includes(b.p) ? b.p : 'outro', inst = b.i ? 1 : 0;
      // nova "visita" quando o aparelho ficou mais de 30 min sem aparecer
      await D.batch([
        D.prepare('INSERT INTO pg (d,f,l,n,p,i) VALUES (?1,?2,?2,1,?3,?4) ON CONFLICT(d) DO UPDATE SET n = n + (CASE WHEN ?2 - l > 1800000 THEN 1 ELSE 0 END), l=?2, p=?3, i=?4').bind(id, now, pf, inst),
        D.prepare('INSERT OR IGNORE INTO pd (dy,d) VALUES (?,?)').bind(dia(now), id)
      ]);
      return json({ ok: true });
    }
    if (req.method === 'POST' && p === '/painel') {
      const b = await body(req);
      if (!b || !env.ADMIN_H || !same(await sha(String(b.k || '')), String(env.ADMIN_H))) { await new Promise(r => setTimeout(r, 800)); return json({ erro: 'Código de acesso inválido.' }, 401); }
      const D = await db(env), now = Date.now(), hj = dia(now);
      const one = async (q, ...v) => ((await D.prepare(q).bind(...v).first()) || {}).c || 0;
      const t0 = Date.parse(hj + 'T03:00:00Z');
      const [agora, h15, h1, hoje, d7, d30, total, novos, visitas] = await Promise.all([
        one('SELECT COUNT(*) c FROM pg WHERE l > ?', now - 150000),
        one('SELECT COUNT(*) c FROM pg WHERE l > ?', now - 15 * 6e4),
        one('SELECT COUNT(*) c FROM pg WHERE l > ?', now - 36e5),
        one('SELECT COUNT(*) c FROM pd WHERE dy = ?', hj),
        one('SELECT COUNT(DISTINCT d) c FROM pd WHERE dy >= ?', dia(now, 6)),
        one('SELECT COUNT(DISTINCT d) c FROM pd WHERE dy >= ?', dia(now, 29)),
        one('SELECT COUNT(*) c FROM pg'),
        one('SELECT COUNT(*) c FROM pg WHERE f >= ?', t0),
        one('SELECT COALESCE(SUM(n),0) c FROM pg')
      ]);
      const serie = ((await D.prepare('SELECT dy, COUNT(*) c FROM pd WHERE dy >= ? GROUP BY dy ORDER BY dy').bind(dia(now, 13)).all()).results) || [];
      const plat = ((await D.prepare('SELECT p, i, COUNT(*) c FROM pg WHERE l > ? GROUP BY p, i').bind(now - 7 * 864e5).all()).results) || [];
      const novosSerie = ((await D.prepare("SELECT strftime('%Y-%m-%d', (f - 10800000) / 1000, 'unixepoch') dy, COUNT(*) c FROM pg WHERE f >= ? GROUP BY dy").bind(now - 14 * 864e5).all()).results) || [];
      const ia = ((await D.prepare("SELECT n c FROM ai WHERE d='*' AND dy=?").bind(hj).first()) || {}).c || 0;
      const contas = await one('SELECT COUNT(*) c FROM acct'), sinc = await one('SELECT COUNT(*) c FROM dat WHERE at > ?', now - 864e5);
      return json({ agora, h15, h1, hoje, d7, d30, total, novos, visitas, serie, plat, novosSerie, ia, iaOn: !!env.ANTHROPIC_KEY, iaLim: AI_DAY, contas, sinc, ts: now });
    }
    if (req.method === 'POST' && (p === '/sync' || p === '/test')) {
      const b = await body(req);
      if (!b) return json({ erro: 'grande demais' }, 413);
      if (!b.tk || !/^[a-f0-9]{32,128}$/.test(String(b.tk))) return json({ erro: 'token' }, 400);
      const D = await db(env), id = await sha(b.tk);
      const u = await D.prepare('SELECT * FROM u WHERE id=?').bind(id).first();
      if (p === '/test') {
        if (!u || !u.sub) return json({ erro: 'Conecte primeiro.' }, 400);
        if (u.lt && Date.now() - u.lt < 15000) return json({ erro: 'Aguarde alguns segundos.' }, 429);
        await D.prepare('UPDATE u SET lt=? WHERE id=?').bind(Date.now(), id).run();
        const r = await push(env, { sub: JSON.parse(u.sub), origin: u.origin }, { title: 'RC Life', body: 'Teste de aviso: está tudo funcionando! 🏁', tag: 'teste' });
        return json({ ok: r.ok, status: r.status });
      }
      if (!b.sub || !b.sub.keys || !ENDPOINT.test(String(b.sub.endpoint))) return json({ erro: 'inscrição inválida' }, 400);
      const now = Date.now();
      const items = (Array.isArray(b.items) ? b.items : []).filter(i => i && +i.ts > now - 6e4 && +i.ts < now + 9 * 864e5).slice(0, 500)
        .map(i => typeof i.c === 'string' ? { ts: +i.ts, c: i.c.slice(0, 1500), tag: String(i.tag || '').slice(0, 40) } : { ts: +i.ts, title: String(i.title || '').slice(0, 80), body: String(i.body || '').slice(0, 160), tag: String(i.tag || '').slice(0, 40) });
      const sub = JSON.stringify({ endpoint: String(b.sub.endpoint).slice(0, 800), keys: { p256dh: String(b.sub.keys.p256dh || '').slice(0, 200), auth: String(b.sub.keys.auth || '').slice(0, 100) } });
      const og = ORIGINS.includes(String(b.origin)) ? String(b.origin) : '';
      if (b.off) { await D.prepare('DELETE FROM u WHERE id=?').bind(id).run(); return json({ ok: true, avisos: 0 }); }
      await D.prepare('INSERT INTO u (id,sub,origin,items,nxt,sent,at) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET sub=?2,origin=?3,items=?4,nxt=?5,sent=?6,at=?7')
        .bind(id, sub, og, JSON.stringify(items), nextTs(items, now - 6e4), now - 6e4, now).run();
      return json({ ok: true, avisos: items.length });
    }
    return new Response('RC Life: servidor de avisos ativo.', { headers: { ...H, 'content-type': 'text/plain; charset=utf-8' } });
  },
  async scheduled(ev, env, ctx) {
    if (!env.HRC || !env.DB) return;
    const D = await db(env), t = ev.scheduledTime;
    const { results } = await D.prepare('SELECT * FROM u WHERE nxt IS NOT NULL AND nxt <= ? LIMIT 200').bind(t).all();
    await Promise.all((results || []).map(async row => {
      try {
        const items = JSON.parse(row.items || '[]'), u = { sub: JSON.parse(row.sub), origin: row.origin };
        const due = items.filter(i => i.ts > Math.max(row.sent || 0, t - 15 * 6e4) && i.ts <= t);
        let gone = false;
        for (const i of due) {
          const r = await push(env, u, i.c ? { c: i.c, tag: i.tag } : { title: i.title, body: i.body, tag: i.tag });
          if (r.status === 404 || r.status === 410) { gone = true; break; }
        }
        if (gone) return D.prepare('DELETE FROM u WHERE id=?').bind(row.id).run();
        await D.prepare('UPDATE u SET sent=?, nxt=? WHERE id=?').bind(t, nextTs(items, t), row.id).run();
      } catch (e) { await D.prepare('UPDATE u SET nxt=? WHERE id=?').bind(t + 6e4, row.id).run(); }
    }));
    // limpeza diária: agendas paradas há mais de 30 dias
    if (new Date(t).getUTCHours() === 6 && new Date(t).getUTCMinutes() === 0) { await D.prepare('DELETE FROM u WHERE at < ?').bind(t - 30 * 864e5).run(); await D.prepare('DELETE FROM pd WHERE dy < ?').bind(dia(t, 120)).run(); await D.prepare('DELETE FROM ai WHERE dy < ?').bind(dia(t, 7)).run(); }
  }
};
