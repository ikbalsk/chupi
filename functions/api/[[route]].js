const J = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } });
const sha = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
const RESERVED = ['api', 'inbox', 'admin', 'u', 'chupi', 'login'];

async function authed(req, env) {
  const n = req.headers.get('x-name'), k = req.headers.get('x-key');
  if (!n || !k) return null;
  return env.DB.prepare('SELECT name FROM users WHERE name=?1 AND key_hash=?2').bind(n, await sha(k)).first();
}

let ready = false;
async function setup(DB) {
  if (ready) return;
  await DB.batch([
    DB.prepare("CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, key_hash TEXT NOT NULL, prompt TEXT DEFAULT 'Say something to me secretly 🤫', created INTEGER NOT NULL)"),
    DB.prepare("CREATE TABLE IF NOT EXISTS msgs (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, text TEXT NOT NULL, mood TEXT DEFAULT '💬', ip TEXT, read INTEGER DEFAULT 0, ts INTEGER NOT NULL)"),
    DB.prepare('CREATE INDEX IF NOT EXISTS idx_msgs_owner ON msgs(owner, ts DESC)')
  ]);
  ready = true;
}

export async function onRequest({ request: req, env }) {
  if (!env.DB) return J({ error: 'D1 binding named DB is missing. Add it in Pages > Settings > Bindings.' }, 500);
  await setup(env.DB);
  {
    const url = new URL(req.url), p = url.pathname, now = Date.now();
    const body = req.method === 'POST' ? await req.json().catch(() => ({})) : {};

    if (p === '/api/create' && req.method === 'POST') {
      const name = String(body.name || '').toLowerCase().trim();
      if (!/^[a-z0-9_]{3,20}$/.test(name) || RESERVED.includes(name)) return J({ error: 'Use 3–20 letters, numbers or _' }, 400);
      if (await env.DB.prepare('SELECT 1 FROM users WHERE name=?1').bind(name).first()) return J({ error: 'That name is taken. Try another.' }, 409);
      const key = [...crypto.getRandomValues(new Uint8Array(12))].map(b => b.toString(16).padStart(2, '0')).join('');
      await env.DB.prepare('INSERT INTO users(name,key_hash,created) VALUES(?1,?2,?3)').bind(name, await sha(key), now).run();
      return J({ name, key });
    }

    if (p === '/api/login' && req.method === 'POST') {
      const u = await env.DB.prepare('SELECT name FROM users WHERE name=?1 AND key_hash=?2').bind(String(body.name || '').toLowerCase(), await sha(String(body.key || ''))).first();
      return u ? J({ ok: 1 }) : J({ error: 'Wrong name or key' }, 401);
    }

    let m = p.match(/^\/api\/profile\/([a-z0-9_]+)$/);
    if (m) {
      const u = await env.DB.prepare('SELECT name,prompt FROM users WHERE name=?1').bind(m[1]).first();
      return u ? J(u) : J({ error: 'not found' }, 404);
    }

    m = p.match(/^\/api\/send\/([a-z0-9_]+)$/);
    if (m && req.method === 'POST') {
      const text = String(body.text || '').trim().slice(0, 600);
      if (text.length < 1) return J({ error: 'Write something first' }, 400);
      if (!(await env.DB.prepare('SELECT 1 FROM users WHERE name=?1').bind(m[1]).first())) return J({ error: 'not found' }, 404);
      const ip = await sha(req.headers.get('cf-connecting-ip') || 'x');
      const r = await env.DB.prepare('SELECT COUNT(*) c FROM msgs WHERE ip=?1 AND ts>?2').bind(ip, now - 60000).first();
      if (r.c >= 3) return J({ error: 'Slow down a little 🐢 try again in a minute' }, 429);
      await env.DB.prepare('INSERT INTO msgs(owner,text,mood,ip,ts) VALUES(?1,?2,?3,?4,?5)').bind(m[1], text, String(body.mood || '💬').slice(0, 4), ip, now).run();
      return J({ ok: 1 });
    }

    if (p.startsWith('/api/')) {
      const me = await authed(req, env);
      if (!me) return J({ error: 'unauthorized' }, 401);
      if (p === '/api/inbox') {
        const { results } = await env.DB.prepare('SELECT id,text,mood,ts,read FROM msgs WHERE owner=?1 ORDER BY ts DESC LIMIT 200').bind(me.name).all();
        const u = await env.DB.prepare('SELECT prompt FROM users WHERE name=?1').bind(me.name).first();
        return J({ msgs: results, prompt: u.prompt });
      }
      if (p === '/api/read') { await env.DB.prepare('UPDATE msgs SET read=1 WHERE owner=?1').bind(me.name).run(); return J({ ok: 1 }); }
      if (p === '/api/del') { await env.DB.prepare('DELETE FROM msgs WHERE id=?1 AND owner=?2').bind(+body.id, me.name).run(); return J({ ok: 1 }); }
      if (p === '/api/prompt') { await env.DB.prepare('UPDATE users SET prompt=?1 WHERE name=?2').bind(String(body.prompt || '').slice(0, 80), me.name).run(); return J({ ok: 1 }); }
    }
    return J({ error: 'not found' }, 404);
  }
}
