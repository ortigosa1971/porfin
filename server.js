// server.js — sesión única, reemplaza sesión anterior automáticamente, con claim atómico
// Listo para Railway: incluye /health y raíz '/'
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');

const app = express();
app.set('trust proxy', 1);

// ====== Carpetas ======
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');

// ====== Sesiones (SQLite) ======
const store = new SQLiteStore({ db: 'sessions.sqlite', dir: DB_DIR });

app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'cambia-esta-clave',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.SAMESITE || 'lax', // 'none' si front/back en dominios distintos (+ secure:true)
    secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Promesas para store.get/destroy
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

// Body y estáticos
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ====== DB usuarios ======
const db = new Database(path.join(DB_DIR, 'usuarios.db'));
db.pragma('journal_mode = wal');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

const DEBUG = process.env.DEBUG_SINGLE_SESSION === '1';
const log = (...a) => DEBUG && console.log('[single-session]', ...a);

// ====== Healthcheck (PUBLICO) ======
app.get('/health', (req, res) => res.status(200).send('OK'));

// ====== Raíz (PUBLICO) ======
app.get('/', (req, res) => {
  const loginFile = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(loginFile)) return res.sendFile(loginFile);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
  <body>
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="usuario" placeholder="usuario" required>
      <input type="password" name="password" placeholder="password" required>
      <button>Entrar</button>
    </form>
  </body></html>`);
});

// ====== Helper: autenticar (ajusta a tu lógica real) ======
function autenticar(username, password) {
  const row = db.prepare('SELECT username, password, session_id FROM users WHERE username = ?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row;
}

// ====== LOGIN: reemplaza SIEMPRE la sesión anterior + claim atómico ======
app.post('/login', async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = usuario || username;
    if (!userField) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(userField, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    // 1) Si había una sesión previa, EXPULSARLA SIEMPRE (reemplazo automático)
    if (user.session_id) {
      await storeDestroy(user.session_id).catch(() => {});
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    // 2) Regenerar sesión para nuevo SID (evita fijación y choques)
    await new Promise((resolve, reject) => {
      req.session.regenerate(err => (err ? reject(err) : resolve()));
    });

    // 3) Claim ATÓMICO: tomar la sesión solo si sigue NULL
    const claim = db.prepare(
      'UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL'
    ).run(req.sessionID, user.username);

    if (claim.changes === 0) {
      return res.redirect('/login.html?error=sesion_activa');
    }

    // 4) Completar sesión de app
    req.session.usuario = user.username;
    log('login OK (reemplazo + claim)', user.username, 'sid:', req.sessionID);
    return res.redirect('/inicio.html');
  } catch (e) {
    console.error(e);
    return res.redirect('/login.html?error=interno');
  }
});

// ====== Middleware: sesión única ======
async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');

    const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!row) return res.redirect('/login.html');

    if (!row.session_id) {
      req.session.destroy(() => res.redirect('/login.html?error=sesion_invalida'));
      return;
    }

    if (row.session_id !== req.sessionID) {
      req.session.destroy(() => res.redirect('/login.html?error=conectado_en_otra_maquina'));
      return;
    }

    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(req.session.usuario);
      req.session.destroy(() => res.redirect('/login.html?error=sesion_expirada'));
      return;
    }

    next();
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
}

// ====== Rutas protegidas ======
app.get('/inicio', requiereSesionUnica, (req, res) => {
  const inicioFile = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(inicioFile)) return res.sendFile(inicioFile);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Inicio</title></head>
  <body><h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>
  <form method="POST" action="/logout"><button>Salir</button></form>
  </body></html>`);
});

app.get('/api/datos', requiereSesionUnica, (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario, sid: req.sessionID });
});

app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session?.usuario });
});

// ====== Logout ======
app.post('/logout', (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;

  req.session.destroy(async () => {
    if (usuario) {
      const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(usuario);
      if (row?.session_id === sid) {
        db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(usuario);
      }
    }
    res.redirect('/login.html?msg=logout');
  });
});

// ====== Arranque ======
const PORT = process.env.PORT || 8080;

/* ========= RUTA EXISTENTE: total de lluvia acumulada (API externa configurable)
   Usa process.env.LLUVIA_API_URL y trata de deducir el total de varias formas
   (se mantiene como tenías).  ========= */
app.get('/api/lluvia/total', requiereSesionUnica, async (req, res) => {
  try {
    const apiUrl = process.env.LLUVIA_API_URL;
    if (!apiUrl) {
      return res.status(501).json({ error: 'Config faltante', detalle: 'Define LLUVIA_API_URL en .env con el endpoint de tu API.' });
    }
    const r = await fetch(apiUrl);
    if (!r.ok) throw new Error('API externa HTTP ' + r.status);
    const datos = await r.json();

    const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

    if (typeof datos === 'number' || (typeof datos === 'string' && !Number.isNaN(Number(datos)))) {
      return res.json({ total_mm: num(datos) });
    }

    if (datos && typeof datos === 'object') {
      for (const k of ['total_mm','total','acumulado','acumulado_mm','acumulado_dia_mm']) {
        if (k in datos && (typeof datos[k] === 'number' || typeof datos[k] === 'string')) {
          return res.json({ total_mm: num(datos[k]) });
        }
      }
    }

    const arr = Array.isArray(datos) ? datos
              : (datos && (Array.isArray(datos.items) ? datos.items : (Array.isArray(datos.data) ? datos.data : null)));

    if (arr) {
      const pickAccum = (o) => o?.acumulado_mm ?? o?.acumulado ?? o?.acumulado_dia_mm ?? null;
      let hadAccum = false;
      const byDate = [];
      for (const it of arr) {
        const acc = pickAccum(it);
        if (acc != null) {
          hadAccum = true;
          byDate.push({ fecha: it?.fecha || it?.date || it?.timestamp || null, val: num(acc) });
        }
      }
      if (hadAccum) {
        const withFecha = byDate.filter(x => x.fecha);
        if (withFecha.length) {
          withFecha.sort((a,b) => (new Date(a.fecha)) - (new Date(b.fecha)));
          return res.json({ total_mm: num(withFecha[withFecha.length-1].val) });
        }
        const maxVal = byDate.reduce((m,x) => Math.max(m, x.val), 0);
        return res.json({ total_mm: num(maxVal) });
      }

      const total = arr.reduce((acc, d) => {
        const v = d?.mm ?? d?.lluvia ?? d?.precip_mm ?? d?.rain ?? 0;
        return acc + num(v);
      }, 0);
      return res.json({ total_mm: Number(total.toFixed(2)) });
    }

    return res.status(500).json({ error: 'Formato no reconocido', detalle: 'No se encontró un total ni un array utilizable.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'No se pudo calcular el total', detalle: String(e.message || e) });
  }
});
// === Fin ruta existente ===

/* ========= RUTA NUEVA (PÚBLICA): lluvia acumulada del AÑO ACTUAL (WU) =========
   1) Intenta /v2/pws/history/daily (rango completo)
   2) Si WU devuelve 400/404/!=200, Fallback a /v2/pws/history/all por día,
      sumando la máxima metric.precipTotal de cada fecha.
   Requiere WU_API_KEY y WU_STATION_ID en .env/.Railway
*/
app.get('/api/lluvia/total/year', async (req, res) => {
  try {
    const apiKey = process.env.WU_API_KEY;
    const stationId = process.env.WU_STATION_ID;
    if (!apiKey || !stationId) {
      return res.status(400).json({ error: 'config_missing', detalle: 'Define WU_API_KEY y WU_STATION_ID' });
    }

    const hoy = new Date();
    const year = hoy.getFullYear();
    const pad = n => String(n).padStart(2,'0');
    const ymd = d => `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}`;
    const desdeISO = `${year}-01-01`;
    const hastaISO = `${year}-${pad(hoy.getMonth()+1)}-${pad(hoy.getDate())}`;

    // 1) Intento rápido: history/daily
    const urlDaily = `https://api.weather.com/v2/pws/history/daily?stationId=${encodeURIComponent(stationId)}&format=json&units=m&startDate=${year}0101&endDate=${ymd(hoy)}&apiKey=${encodeURIComponent(apiKey)}`;

    let totalMM = 0;
    let ok = false;

    try {
      const r = await fetch(urlDaily);
      if (r.ok) {
        const data = await r.json();
        const arr = Array.isArray(data?.observations) ? data.observations : [];
        totalMM = arr.reduce((acc, d) => {
          const v = Number(d?.metric?.precipTotal ?? 0);
          return acc + (Number.isFinite(v) ? v : 0);
        }, 0);
        ok = true;
      } else {
        console.warn('[WU daily] status:', r.status);
      }
    } catch (e) {
      console.warn('[WU daily] error:', e?.message || e);
    }

    // 2) Fallback: history/all por día
    if (!ok) {
      const urlAll = (yyyymmdd) =>
        `https://api.weather.com/v2/pws/history/all?stationId=${encodeURIComponent(stationId)}&format=json&units=m&date=${yyyymmdd}&apiKey=${encodeURIComponent(apiKey)}`;
      const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };

      let cursor = new Date(`${year}-01-01T00:00:00Z`);
      const fin = new Date(`${hastaISO}T00:00:00Z`);
      let suma = 0;

      while (cursor <= fin) {
        const dStr = ymd(cursor);
        try {
          const r = await fetch(urlAll(dStr));
          if (!r.ok) {
            console.warn('[WU all] status', dStr, r.status);
          } else {
            const data = await r.json();
            const obs = Array.isArray(data?.observations) ? data.observations : [];
            let maxTotal = 0;
            for (const o of obs) {
              const pt = Number(o?.metric?.precipTotal ?? 0);
              if (Number.isFinite(pt) && pt > maxTotal) maxTotal = pt;
            }
            suma += maxTotal;
          }
        } catch (e) {
          console.warn('[WU all] error', dStr, e?.message || e);
        }
        // Si te preocupa rate limit, puedes pausar aquí:
        // await new Promise(r => setTimeout(r, 100));
        cursor = addDays(cursor, 1);
      }
      totalMM = Number(suma.toFixed(2));
    }

    return res.json({
      total_mm: Number(totalMM.toFixed(2)),
      year,
      desde: desdeISO,
      hasta: hastaISO,
      origen: ok ? 'WU history/daily' : 'WU history/all (fallback)'
    });
  } catch (e) {
    console.error('Error /api/lluvia/total/year:', e);
    res.status(500).json({ error: 'calc_failed', detalle: String(e.message || e) });
  }
});
// === Fin ruta nueva ===

app.listen(PORT, () => console.log(`🚀 http://0.0.0.0:${PORT} — reemplazo automático de sesión activado`));

