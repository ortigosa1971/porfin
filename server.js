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
const store = new SQLiteStore({
  db: 'sessions.sqlite',
  dir: DB_DIR
});

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
      await storeDestroy(user.session_id).catch(() => {}); // ignora error si ya expiró
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
      // Alguna carrera extrema: otro proceso tomó la sesión en microsegundos
      return res.redirect('/login.html?error=sesion_activa');
    }

    // 4) Completar sesión de app
    req.session.usuario = user.username;
    log('login OK (reemplazo + claim) para', user.username, 'sid:', req.sessionID);
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
   (lo dejo tal cual estaba en tu archivo).  ========= */
app.get('/api/lluvia/total', requiereSesionUnica, async (req, res) => {
  try {
    const apiUrl = process.env.LLUVIA_API_URL;
    if (!apiUrl) {
      return res.status(501).json({ error: 'Config faltante', detalle: 'Define LLUVIA_API_URL en .env con el endpoint de tu API.' });
    }
    const r = await fetch(apiUrl);
    if (!r.ok) throw new Error('API externa HTTP ' + r.status);
    const datos = await r.json();

    // Helper para castear a número seguro
    const num = (v) => {
      const n = Number(v);
      return Number.isFinite(n) ? n : 0;
    };

    // 0) Si viene directamente un número (o string numérico)
    if (typeof datos === 'number' || (typeof datos === 'string' && !Number.isNaN(Number(datos)))) {
      return res.json({ total_mm: num(datos) });
    }

    // 1) Si viene total directo
    if (datos && typeof datos === 'object') {
      for (const k of ['total_mm','total','acumulado','acumulado_mm','acumulado_dia_mm']) {
        if (k in datos && (typeof datos[k] === 'number' || typeof datos[k] === 'string')) {
          return res.json({ total_mm: num(datos[k]) });
        }
      }
    }

    // 2) Si viene array (posible lista de lecturas / días)
    const arr = Array.isArray(datos) ? datos
              : (datos && (Array.isArray(datos.items) ? datos.items : (Array.isArray(datos.data) ? datos.data : null)));

    if (arr) {
      // 2.a) Si los elementos ya traen 'acumulado*', usar el último por fecha o el mayor valor
      const pickAccum = (o) => o?.acumulado_mm ?? o?.acumulado ?? o?.acumulado_dia_mm ?? null;
      let hadAccum = false;
      let byDate = [];
      for (const it of arr) {
        const acc = pickAccum(it);
        if (acc != null) {
          hadAccum = true;
          byDate.push({
            fecha: it?.fecha || it?.date || it?.timestamp || null,
            val: num(acc)
          });
        }
      }
      if (hadAccum) {
        // Preferir último por fecha si existe alguna
        const withFecha = byDate.filter(x => x.fecha);
        if (withFecha.length) {
          // Ordenar por fecha asc y coger el último
          withFecha.sort((a,b) => (new Date(a.fecha)) - (new Date(b.fecha)));
          return res.json({ total_mm: num(withFecha[withFecha.length-1].val) });
        }
        // En su defecto, el mayor valor (acumulado final)
        const maxVal = byDate.reduce((m,x) => Math.max(m, x.val), 0);
        return res.json({ total_mm: num(maxVal) });
      }

      // 2.b) Si NO traen 'acumulado*', sumar por campos típicos
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

/* ========= RUTA NUEVA: lluvia acumulada del AÑO ACTUAL (WU) =========
   Suma metric.precipTotal de /v2/pws/history/daily entre 1/enero y hoy.
   Requiere WU_API_KEY y WU_STATION_ID en .env
*/
app.get('/api/lluvia/total/year', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey = process.env.WU_API_KEY;
    const stationId = process.env.WU_STATION_ID;
    if (!apiKey || !stationId) {
      return res.status(400).json({
        error: 'config_missing',
        detalle: 'Define WU_API_KEY y WU_STATION_ID en el .env'
      });
    }

    const ahora = new Date();
    const year = ahora.getFullYear();
    const pad = (n) => String(n).padStart(2, '0');
    const startDate = `${year}0101`; // inclusive
    const endDate = `${year}${pad(ahora.getMonth() + 1)}${pad(ahora.getDate())}`; // inclusive

    const url = `https://api.weather.com/v2/pws/history/daily?stationId=${encodeURIComponent(stationId)}&format=json&units=m&startDate=${startDate}&endDate=${endDate}&apiKey=${encodeURIComponent(apiKey)}`;

    const r = await fetch(url);
    if (!r.ok) throw new Error(`WU HTTP ${r.status}`);
    const data = await r.json();

    const arr = Array.isArray(data?.observations) ? data.observations : [];
    const totalYear = arr.reduce((acc, d) => {
      const mm = Number(d?.metric?.precipTotal ?? 0);
      return acc + (Number.isFinite(mm) ? mm : 0);
    }, 0);

    return res.json({
      total_mm: Number(totalYear.toFixed(2)),
      year,
      desde: `${year}-01-01`,
      hasta: `${year}-${pad(ahora.getMonth() + 1)}-${pad(ahora.getDate())}`,
      origen: 'WU history/daily'
    });
  } catch (e) {
    console.error('Error /api/lluvia/total/year:', e);
    res.status(500).json({ error: 'calc_failed', detalle: String(e.message || e) });
  }
});
// === Fin ruta nueva ===

app.listen(PORT, () => console.log(`🚀 http://0.0.0.0:${PORT} — reemplazo automático de sesión activado`));
