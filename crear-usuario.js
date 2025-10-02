
const Database = require('better-sqlite3');
const db = new Database('./db/usuarios.db');

// Cambia estos valores si quieres otro usuario
const usuario = 'admin';
const password = '1234';

try {
  db.prepare("INSERT OR REPLACE INTO usuarios (usuario, password) VALUES (?, ?)").run(usuario, password);
  console.log(`✅ Usuario creado correctamente: ${usuario}`);
} catch (err) {
  console.error("❌ Error al crear el usuario:", err.message);
}
