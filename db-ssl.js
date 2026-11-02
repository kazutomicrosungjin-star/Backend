// Shared TLS options for every MySQL connection. When DB_SSL is true, an
// optional DB_SSL_CA is trusted explicitly so a provider certificate signed by
// a private CA verifies; without it, behavior stays as it was before.
function dbSslOptions() {
  if (process.env.DB_SSL !== 'true') return undefined;

  // Host variable fields often store the PEM with literal "\n" sequences.
  const ca = (process.env.DB_SSL_CA || '').replace(/\\n/g, '\n').trim();
  return ca ? { ca, rejectUnauthorized: true } : { rejectUnauthorized: true };
}

module.exports = { dbSslOptions };
