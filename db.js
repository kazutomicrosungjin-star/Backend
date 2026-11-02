require('dotenv').config();
const mysql = require('mysql2/promise');
const { dbSslOptions } = require('./db-ssl');

// A pool, not a single connection — reused across requests, handles
// reconnects, and every query below goes through parameterized `?`
// placeholders so user input is never concatenated into SQL text.
// Set DB_SSL=true in .env when the database isn't on the same private
// network as this server (e.g. a managed/hosted MySQL reached over the
// public internet) — otherwise credentials and every query/row travel in
// the clear between this process and the DB. Left unset so local/dev MySQL
// without TLS configured keeps working out of the box.
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: dbSslOptions(),
});

module.exports = pool;
