
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./db/usuarios.db');

const username = 'admin';
const password = 'admin'; // Puedes cambiarlo si quieres
const session_id = null;

db.run('INSERT INTO users (username, password, session_id) VALUES (?, ?, ?)', [username, password, session_id], (err) => {
  if (err) {
    return console.error("❌ Error insertando admin:", err.message);
  }
  console.log("✅ Usuario admin creado correctamente.");
  db.close();
});
