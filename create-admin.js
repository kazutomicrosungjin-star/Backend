// Usage: node create-admin.js <username> <password> <pin>
// Creates (or updates the password+PIN of) an admin account using real
// bcrypt hashes — this is the only supported way to get an admin into the
// database; there is no hand-typed hash anywhere in this project. The PIN
// is admin login's second factor (see /api/admin/login/verify-pin in
// server.js) — an admin can't get a usable session without one set.
require('dotenv').config();
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const { dbSslOptions } = require('./db-ssl');

async function main() {
  const [, , username, password, pin] = process.argv;
  if (!username || !password || !pin) {
    console.error('Usage: node create-admin.js <username> <password> <pin>');
    process.exit(1);
  }
  if (password.length < 8) {
    console.error('Use a password of at least 8 characters.');
    process.exit(1);
  }
  if (!/^\d{4}$/.test(pin)) {
    console.error('PIN must be exactly 4 digits.');
    process.exit(1);
  }

  const pool = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: dbSslOptions(),
  });

  const passwordHash = await bcrypt.hash(password, 10);
  const pinHash = await bcrypt.hash(pin, 10);

  // Parameterized query — the username/hash values are never concatenated
  // into the SQL string, so this is not vulnerable to SQL injection.
  await pool.execute(
    `INSERT INTO admins (username, password_hash, pin_hash) VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), pin_hash = VALUES(pin_hash)`,
    [username, passwordHash, pinHash]
  );

  console.log(`Admin "${username}" created/updated (password + PIN set).`);
  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
