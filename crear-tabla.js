
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./db/usuarios.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    session_id TEXT
  )`, (err) => {
    if (err) {
      return console.error("❌ Error creando la tabla:", err.message);
    }
    console.log("✅ Tabla 'users' verificada o creada.");
    
    db.run('INSERT OR IGNORE INTO users (username, password, session_id) VALUES (?, ?, ?)', ['admin', 'admin', null], (err) => {
      if (err) {
        return console.error("❌ Error insertando admin:", err.message);
      }
      console.log("✅ Usuario admin creado correctamente.");
      db.close();
    });
  });
});
