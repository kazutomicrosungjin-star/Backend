// PayCST backend — MySQL + Express.
//
// What this replaces from the Flutter demo (item #15): the demo app keeps
// every username, password, PIN, and balance in a plain Dart Map that
// lives only in the app's RAM. Here, credentials are salted+hashed with
// bcrypt (never stored or compared as plaintext), every query is
// parameterized (no SQL injection surface), and login is enforced as two
// real steps — password, then a separately-verified PIN — before a usable
// session token is issued (items #1 / #11).
//
// This file intentionally covers the security-relevant slice (auth, PIN,
// wallet-to-wallet payment, groups with the 6-member cap, and admin
// oversight) rather than reimplementing every screen (bills/load/etc.) —
// those follow the exact same parameterized-query + hashed-auth pattern,
// so ask if you'd like them added too.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { mergeSort, comparators } = require('./mergeSort');
const { Stack } = require('./stack');
const { Queue } = require('./queue');

// ---------- pending-loan queue (FIFO — item: mandatory "Queue") ----------
const loanQueue = new Queue();

async function loadLoanQueueFromDatabase() {
  const [rows] = await pool.query(
    "SELECT id AS loanId, user_id AS userId FROM loans WHERE status = 'pending' ORDER BY created_at ASC"
  );
  loanQueue.items = []; // reset before rebuilding
  for (const row of rows) {
    loanQueue.enqueue(row);
  }
  console.log(`Loaded ${rows.length} pending loans into queue`);
}

const { DoublyLinkedList } = require('./dll');

// ---------- account doubly linked list (item: mandatory "Doubly Linked List") ----------
const accountList = new DoublyLinkedList();

async function loadAccountListFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users ORDER BY id ASC');
  accountList.clear();
  for (const row of rows) {
    accountList.insert(row.id, row);
  }
  console.log(`Loaded ${rows.length} accounts into doubly linked list`);
}

const { AVLTree } = require('./avl');

// ---------- wallet-ID AVL tree (item: mandatory "AVL Tree") ----------
const walletAvl = new AVLTree();

async function loadWalletAvlFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users');
  walletAvl.clear();
  for (const row of rows) {
    walletAvl.insert(row.wallet_id, row);
  }
  console.log(`Loaded ${rows.length} accounts into AVL tree (height: ${walletAvl.height()})`);
}

// ---------- per-user undo stacks (LIFO — item: mandatory "Stack") ----------
const undoStacks = new Map(); // userId -> Stack of transferRefs

function getUndoStack(userId) {
  if (!undoStacks.has(userId)) undoStacks.set(userId, new Stack());
  return undoStacks.get(userId);
}
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const http = require('http');
const { WebSocketServer } = require('ws');
const pool = require('./db');
const { sendSms, smsIsReal } = require('./sms');
const { getNowShowing } = require('./movies');
const { PROVIDERS, findCheapestRoute } = require('./graph');
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection (server stayed up):', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception (server stayed up):', err);
});

const app = express();

// Railway (like most hosting platforms) puts the app behind a reverse
// proxy, so the real client IP arrives via the X-Forwarded-For header
// rather than the raw socket address. Without this, Express's req.ip
// (which express-rate-limit keys on) can't be trusted, and rate limiting
// silently fails to count attempts correctly per visitor.
app.set('trust proxy', 1);

// ---------- security middleware ----------
// helmet sets a batch of standard protective HTTP response headers
// (clickjacking protection, MIME-sniffing prevention, etc.) with sane
// defaults for an API-only server.
app.use(helmet());

// CORS is only relevant to browser clients (Flutter mobile doesn't send an
// Origin header, so this never affects the phone app either way). Set
// CORS_ORIGIN in .env to a comma-separated allowlist once you know your
// real web origin(s) (e.g. "https://app.paycst.com,https://paycst.com") to
// stop arbitrary sites from reading this API in a logged-in user's
// browser. Left unset, this keeps today's fully-open behavior so nothing
// breaks before you're ready to lock it down.
const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim()).filter(Boolean)
  : null;
if (!corsOrigins) {
  console.warn('WARNING: CORS_ORIGIN is not set - any website origin is allowed. Set it in production.');
}
app.use(cors({ origin: corsOrigins || true }));
// Verification upgrades upload multiple photos and call Face++, so throttle
// them per account like the login-adjacent routes (not by IP, since requireAuth
// runs first). Defined before the body parser mount so the 35mb parser only
// runs after auth and this limiter have accepted the request.
const verificationUpgradeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.userId ? `verification-upgrade:${req.userId}` : ipKeyGenerator(req)),
  message: { error: 'Too many verification upgrade attempts. Please try again later.' },
});

// Default express.json() limit is 100kb, which is too small for base64 photos.
// Registration's three photos keep their existing 15mb limit. Verification
// upgrades are sized for the six-photo worst case (6 x 6,000,000 characters),
// so 35mb (36,700,160 bytes) covers 36,000,000 bytes plus JSON overhead
// without raising the limit on any other route.
app.use('/api/register', express.json({ limit: '15mb' }));
// Auth and throttling run before the large parser, so rejected requests never
// parse a 35mb body. requireAuth is a hoisted function declaration.
app.use('/api/verification/upgrade', requireAuth, verificationUpgradeLimiter, express.json({ limit: '35mb' }));
app.use(express.json({ limit: '100kb' }));

// Rate limiting on the endpoints most worth protecting against
// brute-force/credential-stuffing. A 4-digit PIN only has 10,000 possible
// values.
//
// Keyed by USERNAME rather than IP: Railway's multi-hop edge network can
// present a different X-Forwarded-For chain length per request, which
// makes req.ip unreliable even with `trust proxy` set — the same client
// can appear to come from a different "IP" on consecutive requests,
// silently defeating IP-based limiting. Username is a fixed, real value
// tied to the account under attack, so it can't be dodged by an attacker
// rotating source IPs — if anything this is the stronger defense for
// credential-stuffing specifically. Falls back to req.ip only when no
// username is present in the body (shouldn't normally happen on these
// routes, but keeps behavior sane rather than throwing).
function authKeyGenerator(req) {
  const username = req.body?.username?.toString().trim().toLowerCase();
  return username || ipKeyGenerator(req);
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per username per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authKeyGenerator,
  message: { error: 'Too many attempts. Please try again later.' },
});

// verify-pin doesn't carry a username in its body (it identifies the user
// via the pendingToken instead), so it needs its own keyGenerator that
// pulls the uid out of that token — otherwise every pending login in the
// last 5 minutes would fall back to the same req.ip bucket regardless of
// which account is actually being verified.
const pinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const payload = req.body?.pendingToken && verify(req.body.pendingToken);
    return payload?.uid ? `pin:${payload.uid}` : ipKeyGenerator(req);
  },
  message: { error: 'Too many attempts. Please try again later.' },
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authKeyGenerator,
  message: { error: 'Too many attempts. Please try again later.' },
});

// Second factor for admin login, mirroring pinLimiter above — keyed off
// the pendingToken's uid rather than username/IP for the same reason:
// this route doesn't carry a username in its body.
const adminPinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const payload = req.body?.pendingToken && verify(req.body.pendingToken);
    return payload?.uid ? `adminpin:${payload.uid}` : ipKeyGenerator(req);
  },
  message: { error: 'Too many attempts. Please try again later.' },
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET is missing or shorter than 32 characters.');
  process.exit(1);
}

// A precomputed bcrypt hash of a value nobody will ever type, used to keep
// login timing constant whether or not the username exists. Without this,
// a lookup miss returns instantly (skips bcrypt entirely) while a real
// username takes ~100ms for the hash compare, letting an attacker
// enumerate valid usernames purely from response time.
const DUMMY_BCRYPT_HASH = '$2b$10$mmbttYBoG2ai04iUGNVN1e//S9B9Ae8.xo6roaVcGlvA47DDiwhwO';
const MAX_GROUP_MEMBERS = 6;
const MAX_CENTAVOS = 100_000_000_00; // ₱100,000,000.00 — sanity ceiling, adjust as you like

// ---------- in-memory indexes (item #6 fix) ----------
// NOT the source of truth — MySQL is. These are fast lookup caches built
// from the database at startup and kept in sync after every commit that
// touches a user row. Safe to discard and rebuild at any time via
// loadIndexesFromDatabase().
const usersByUsername = new Map(); // username -> user row
const usersByWalletId = new Map(); // wallet_id -> user row 
async function loadIndexesFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users');
  usersByUsername.clear();
  usersByWalletId.clear();
  for (const row of rows) {
    usersByUsername.set(row.username, row);
    usersByWalletId.set(row.wallet_id, row);
  }
  console.log(`Loaded ${rows.length} users into hash map indexes`);
}

// ---------- live balance push (WebSocket) ----------
// userId -> Set of open sockets. A user can have more than one (two
// devices, a hot-reloaded app, etc), so every route just calls
// refreshUserInIndex(id) as it already did — this rides along on that
// same call rather than needing its own call site at every transfer.
const userSockets = new Map();

function registerSocket(userId, ws) {
  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(ws);
}

function unregisterSocket(userId, ws) {
  const set = userSockets.get(userId);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userSockets.delete(userId);
}

function pushToUser(userId, payload) {
  const set = userSockets.get(userId);
  if (!set || set.size === 0) return;
  const msg = JSON.stringify(payload);
  for (const ws of set) {
    if (ws.readyState === ws.OPEN) ws.send(msg);
  }
}

async function refreshUserInIndex(userId) {
  try {
    await refreshUserInIndexUnsafe(userId);
  } catch (err) {
    console.error('refreshUserInIndex failed:', err.message);
  }
}

async function refreshUserInIndexUnsafe(userId) {
  const [[row]] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
  if (!row) {
    // User was deleted — grab the wallet_id from what we still have
    // cached (the DB row is already gone) so we can clean up the AVL
    // tree too, then remove from both structures.
    const oldNode = accountList.nodesByKey.get(userId);
    if (oldNode) {
      walletAvl.delete(oldNode.data.wallet_id);
      accountList.delete(userId);
    }
    return;
  }

  usersByUsername.set(row.username, row);
  usersByWalletId.set(row.wallet_id, row);

  if (accountList.nodesByKey.has(userId)) {
    accountList.update(userId, row);
  } else {
    accountList.insert(userId, row);
  }

  // item: mandatory "AVL Tree" — insert on first sight, update
  // thereafter (insert() handles both cases). Keyed by wallet_id, which
  // never changes once assigned, so this is safe to call every time.
  walletAvl.insert(row.wallet_id, row);

  // Push the fresh balance straight to any connected device for this
  // user — this is what makes an incoming transfer show up live instead
  // of waiting for the next poll/login. Every route that changes a
  // balance (send, wallet pay, group withdraw approval, loan payout,
  // admin reversal, undo, etc.) already calls refreshUserInIndex() for
  // every affected user right after commit, so hooking it here covers
  // all of them for free instead of needing a push call at each one.
  pushToUser(userId, { type: 'balance', balanceCentavos: toCentavos(row.balance) });
}

// ---------- money handling: integer centavos everywhere (item #1 fix) ----------
//
// Every peso amount that touches the database, an API request/response
// body, or in-process arithmetic is now a plain INTEGER count of centavos
// (₱1.00 == 100 centavos, so ₱150.50 == 15050). Previously amounts were
// JS `Number`s backed by MySQL `DECIMAL` columns — both are float-adjacent
// representations, and repeated add/subtract (payments, contributions,
// loan repayments) can silently drift a centavo here and there over time,
// or accept "amounts" like 10.005 that don't correspond to real money.
// Integers don't have that failure mode.
//
// CLIENT CONTRACT CHANGE: the Flutter app must send and expect every
// amount field as an integer number of centavos, not a decimal like
// 150.50 — send 15050 instead, and divide by 100 only when *displaying*
// a value to the user. See the migration note at the bottom of this file
// for the required DB column changes (DECIMAL -> INT).

// Validates an amount coming FROM a client request. Only accepts a
// strictly positive integer (fractional centavos aren't a real unit).
// Returns null (not a thrown error) on anything invalid so callers can
// respond with a normal 400.
function parseCentavos(value) {
  const n = typeof value === 'string' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isFinite(n)) return null;
  if (!Number.isInteger(n)) return null;
  if (n <= 0) return null;
  if (n > MAX_CENTAVOS) return null;
  return n;
}

// Normalizes a value coming FROM the database. mysql2 returns some large
// integer column types as strings rather than JS numbers, so every stored
// balance/amount is passed through this before arithmetic or comparisons.
function toCentavos(dbValue) {
  const n = typeof dbValue === 'string' ? parseInt(dbValue, 10) : dbValue;
  return Number.isSafeInteger(n) ? n : 0;
}

// ---------- wallet limits and reference numbers ----------
// Demo values, like a real wallet's account limits. Override with env variables (in pesos).
const LIMITS = {
  perTransactionCentavos: Number(process.env.LIMIT_PER_TRANSACTION_PESOS || 50000) * 100,
  dailyCentavos: Number(process.env.LIMIT_DAILY_PESOS || 100000) * 100,
  maxBalanceCentavos: Number(process.env.LIMIT_MAX_BALANCE_PESOS || 500000) * 100,
};

const FULLY_VERIFIED_LIMIT_ENV = {
  perTransactionCentavos: 'FULLY_VERIFIED_LIMIT_PER_TRANSACTION_PESOS',
  dailyCentavos: 'FULLY_VERIFIED_LIMIT_DAILY_PESOS',
  maxBalanceCentavos: 'FULLY_VERIFIED_LIMIT_MAX_BALANCE_PESOS',
};

function fullyVerifiedLimitCentavos(envName, fallbackCentavos) {
  const raw = process.env[envName];
  if (raw === undefined || String(raw).trim() === '') return fallbackCentavos;
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value * 100 : fallbackCentavos;
}

const fullyVerifiedConfigured = Object.values(FULLY_VERIFIED_LIMIT_ENV).every(
  (envName) => process.env[envName] !== undefined && String(process.env[envName]).trim() !== ''
);

const FULLY_VERIFIED_LIMITS = {
  perTransactionCentavos: fullyVerifiedLimitCentavos(
    FULLY_VERIFIED_LIMIT_ENV.perTransactionCentavos,
    LIMITS.perTransactionCentavos
  ),
  dailyCentavos: fullyVerifiedLimitCentavos(
    FULLY_VERIFIED_LIMIT_ENV.dailyCentavos,
    LIMITS.dailyCentavos
  ),
  maxBalanceCentavos: fullyVerifiedLimitCentavos(
    FULLY_VERIFIED_LIMIT_ENV.maxBalanceCentavos,
    LIMITS.maxBalanceCentavos
  ),
};

if (!fullyVerifiedConfigured) {
  console.warn('[limits] FULLY_VERIFIED_LIMIT_* is not fully configured; using verified limits for missing values.');
}

const LIMITS_BY_LEVEL = {
  verified: LIMITS,
  fully_verified: FULLY_VERIFIED_LIMITS,
};

function limitsForUser(level) {
  return level === 'fully_verified' ? LIMITS_BY_LEVEL.fully_verified : LIMITS_BY_LEVEL.verified;
}

// Money going out of the wallet counts toward the daily limit (store, food and games are bill payments).
const SPENDING_TYPES = ['Send Money', 'Load', 'Bill Payment', 'QR Payment', 'Loan Repayment', 'Event Ticket', 'Contribution', 'Savings Deposit'];

function pesoText(centavos) {
  return `\u20B1${(centavos / 100).toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

async function spentInLast24h(conn, userId) {
  const [[row]] = await conn.query(
    `SELECT COALESCE(SUM(amount), 0) AS total FROM transactions
      WHERE account_type = 'user' AND account_id = ? AND is_credit = 0
        AND type IN (${SPENDING_TYPES.map(() => '?').join(',')})
        AND created_at > (NOW() - INTERVAL 24 HOUR)`,
    [userId, ...SPENDING_TYPES]
  );
  return toCentavos(row.total);
}

// Error message if this payment would break a limit, otherwise null.
async function outgoingLimitError(conn, userId, amt, limits = LIMITS) {
  if (amt > limits.perTransactionCentavos) {
    return `The most you can send in one transaction is ${pesoText(limits.perTransactionCentavos)}.`;
  }
  const used = await spentInLast24h(conn, userId);
  if (used + amt > limits.dailyCentavos) {
    const left = Math.max(0, limits.dailyCentavos - used);
    return `This would pass your daily limit of ${pesoText(limits.dailyCentavos)}. You can still spend ${pesoText(left)} in the next 24 hours.`;
  }
  return null;
}

function recipientCapError(balanceCentavos, amt, limits = LIMITS) {
  return balanceCentavos + amt > limits.maxBalanceCentavos ? "That wallet can't receive this amount because it would pass the maximum balance." : null;
}

// ---------- double-charge protection ----------
// The app sends an Idempotency-Key header with every payment. If the same key arrives
// again (a retry after a dropped connection, or a double tap), the server answers with
// the first result instead of charging twice. Requests without the header still work.
pool.execute(
  `CREATE TABLE IF NOT EXISTS idempotency_keys (
     user_id INT NOT NULL,
     idem_key VARCHAR(64) NOT NULL,
     request_hash CHAR(64) NULL,
     status ENUM('processing','done') NOT NULL DEFAULT 'processing',
     response_status SMALLINT NULL,
     response_body TEXT NULL,
     created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
     PRIMARY KEY (user_id, idem_key)
   ) ENGINE=InnoDB`
).catch((err) => console.error('Could not create idempotency_keys table:', err.message));

let idempotencyCalls = 0;

// Hash the operation, not the credentials: keys are sorted so reordered JSON
// still matches, and PIN/token fields are omitted before hashing.
function stableBodyForHash(value) {
  if (Array.isArray(value)) return value.map(stableBodyForHash);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const normalized = key.toLowerCase();
      if (normalized.endsWith('pin') || normalized.includes('token')) continue;
      out[key] = stableBodyForHash(value[key]);
    }
    return out;
  }
  return value;
}

function idempotencyHash(req) {
  const body = JSON.stringify(stableBodyForHash(req.body ?? null));
  return crypto.createHash('sha256')
    .update(req.method)
    .update('\n')
    .update(req.originalUrl)
    .update('\n')
    .update(body)
    .digest('hex');
}

async function idempotent(req, res, next) {
  const key = req.get('Idempotency-Key');
  if (!key) return next();
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(key)) {
    return res.status(400).json({ error: 'Invalid Idempotency-Key' });
  }
  try {
    const requestHash = idempotencyHash(req);
    // Housekeeping: keys stuck "processing" (the server restarted mid-request) and old results.
    await pool.execute("DELETE FROM idempotency_keys WHERE status = 'processing' AND created_at < (NOW() - INTERVAL 2 MINUTE)");
    if (++idempotencyCalls % 50 === 0) {
      await pool.execute('DELETE FROM idempotency_keys WHERE created_at < (NOW() - INTERVAL 1 DAY)');
    }
    const [inserted] = await pool.execute(
      'INSERT IGNORE INTO idempotency_keys (user_id, idem_key, request_hash) VALUES (?, ?, ?)',
      [req.userId, key, requestHash]
    );
    if (inserted.affectedRows === 0) {
      const [[row]] = await pool.query(
        'SELECT status, response_status, response_body, request_hash FROM idempotency_keys WHERE user_id = ? AND idem_key = ?',
        [req.userId, key]
      );
      if (row && row.request_hash && row.request_hash !== requestHash) {
        return res.status(409).json({ error: 'Idempotency-Key was already used for a different request' });
      }
      if (row && row.status === 'done') {
        res.set('Idempotent-Replay', 'true');
        return res.status(row.response_status || 200).type('json').send(row.response_body);
      }
      return res.status(409).json({ error: 'This payment is already being processed. Please wait a moment.' });
    }
  } catch (err) {
    return next(err);
  }

  req.idempotency = { key, finalized: false };

  // Fallback for routes that have not switched to commitWithIdempotency yet.
  // Once a route calls it, the helper owns the done state and this wrapper only
  // sends the response.
  const sendJson = res.json.bind(res);
  res.json = (body) => {
    res.json = sendJson;
    const status = res.statusCode;
    if (req.idempotency.finalized) {
      return sendJson(body);
    }
    const saved =
      status < 400
        ? pool.execute(
            "UPDATE idempotency_keys SET status = 'done', response_status = ?, response_body = ? WHERE user_id = ? AND idem_key = ? AND status = 'processing'",
            [status, JSON.stringify(body), req.userId, key]
          )
        : pool.execute(
            "DELETE FROM idempotency_keys WHERE user_id = ? AND idem_key = ? AND status = 'processing'",
            [req.userId, key]
          );
    saved.catch((err) => console.error('Could not update idempotency key:', err.message));
    return sendJson(body);
  };
  next();
}

async function commitWithIdempotency(conn, req, status, body) {
  const idem = req.idempotency;
  if (idem?.key) {
    if (!Number.isInteger(status) || status < 200 || status >= 400) {
      throw new Error('commitWithIdempotency requires a success status');
    }
    const [result] = await conn.execute(
      `UPDATE idempotency_keys
          SET status = 'done', response_status = ?, response_body = ?
        WHERE user_id = ? AND idem_key = ? AND status = 'processing'`,
      [status, JSON.stringify(body), req.userId, idem.key]
    );
    if (result.affectedRows !== 1) {
      const err = new Error('Idempotency key is no longer processing');
      err.code = 'IDEMPOTENCY_KEY_LOST';
      throw err;
    }
    idem.finalized = true;
  }
  await conn.commit();
}

// 13 digits, shown as "4829 105 837261" on receipts.
function newReferenceNumber() {
  return String(crypto.randomInt(0, 10 ** 13)).padStart(13, '0');
}
function referenceDetails(ref) {
  return JSON.stringify({ 'Reference No.': `${ref.slice(0, 4)} ${ref.slice(4, 7)} ${ref.slice(7)}` });
}

// Only for building human-readable error/display strings — never for
// storage or arithmetic.
function centavosToPesosLabel(centavos) {
  return (centavos / 100).toFixed(2);
}

// Pinned explicitly on both sign and verify so a token is only ever
// accepted under the one algorithm this server actually issues — jwt.verify
// otherwise accepts whatever algorithm family matches the secret's type,
// which is unnecessary attack surface to leave open even though a
// symmetric secret isn't vulnerable to the classic RS256->HS256 confusion
// attack.
const JWT_ALGORITHM = 'HS256';

function sign(payload, expiresIn) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn, algorithm: JWT_ALGORITHM });
}

function verify(token) {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
  } catch {
    return null;
  }
}

// Wraps an async Express route handler so any rejected promise (a thrown
// error, a failed query, a missing table, etc.) is forwarded to
// Express's error-handling middleware via next(err) instead of being
// silently swallowed as an "unhandled rejection" — which previously left
// the client hanging forever with no response at all.
function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

// Requires a FULL session token (password + PIN both verified).
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const payload = token && verify(token);
    if (!payload || payload.stage !== 'full' || payload.role !== 'user') {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    // Suspension must take effect immediately, not only at the next login -
    // a 2h token issued before suspension would otherwise keep working.
    const [[row]] = await pool.query(
      'SELECT status, session_version, verification_level FROM users WHERE id = ?',
      [payload.uid]
    );
    if (!row) return res.status(401).json({ error: 'Not authenticated' });
    if (row.status === 'suspended') {
      return res.status(403).json({ error: 'This account has been suspended. Contact support for assistance.' });
    }
    if ((payload.sv ?? 0) !== row.session_version) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    req.userId = payload.uid;
    req.verificationLevel = row.verification_level;
    next();
  } catch (err) {
    next(err);
  }
}

// ---------- extra hardening helpers ----------
// Per-user cap on money actions, so one login can't hammer send/pay/load/bills
// (or guess which numbers are registered through "recipient not found").
const moneyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.userId ? `u:${req.userId}` : ipKeyGenerator(req)),
  message: { error: 'Too many payments in a short time. Please wait a minute and try again.' },
});

// Records what each admin did. Best effort: a logging problem never blocks the action.
async function logAdmin(req, action, targetType, targetId, details) {
  try {
    await pool.execute(
      'INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, details, ip) VALUES (?,?,?,?,?,?)',
      [req.adminId, action, targetType, String(targetId ?? ''), details ? JSON.stringify(details) : null, (req.ip || '').toString().slice(0, 64)]
    );
  } catch (err) {
    console.error('Audit log write failed:', err.message);
  }
}

// Admin sign-in attempts (successful and failed) go in the same log, so you
// can see if someone is guessing admin passwords or PINs.
async function logAdminEvent(req, action, adminId, who) {
  try {
    await pool.execute(
      'INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, details, ip) VALUES (?,?,?,?,?,?)',
      [adminId ?? null, action, 'admin_login', cleanText(who, 60), null, (req.ip || '').toString().slice(0, 64)]
    );
  } catch (err) {
    console.error('Audit log write failed:', err.message);
  }
}

// ID photos waiting for review are encrypted in the database (AES-256-GCM).
// Set PHOTO_ENCRYPTION_KEY to 64 hex characters:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// Without the key, photos are stored as before. Set it before the first sign-up.
const PHOTO_KEY = /^[0-9a-f]{64}$/i.test(process.env.PHOTO_ENCRYPTION_KEY || '')
  ? Buffer.from(process.env.PHOTO_ENCRYPTION_KEY, 'hex')
  : null;
if (!PHOTO_KEY) console.warn('WARNING: PHOTO_ENCRYPTION_KEY is not set - ID photos are stored unencrypted.');

function encryptPhoto(text) {
  if (!PHOTO_KEY || !text) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', PHOTO_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return 'enc:v1:' + Buffer.concat([iv, cipher.getAuthTag(), enc]).toString('base64');
}

function decryptPhoto(text) {
  if (typeof text !== 'string' || !text.startsWith('enc:v1:')) return text;
  if (!PHOTO_KEY) return '';
  try {
    const raw = Buffer.from(text.slice(7), 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', PHOTO_KEY, raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

// Free text that admins will read (group names, reasons, loan purpose...):
// trimmed, length-capped, and stripped of < > and control characters so it
// can't carry HTML/script into the admin panel.
function cleanText(value, max) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f<>]/g, '')
    .trim()
    .slice(0, max);
}

// Money actions (send, QR pay, load, bill pay) need the PIN again, so a stolen
// login token alone can't drain a wallet. Uses the same persistent lockout
// counter as the login PIN step, so guessing is throttled the same way.
async function verifyActionPin(userId, pin) {
  if (typeof pin !== 'string' || !/^\d{4}$/.test(pin)) {
    return { status: 400, error: 'Enter your 4-digit PIN to confirm' };
  }
  const identifier = `pin:${userId}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return { status: 429, error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` };
  }
  const [[row]] = await pool.query('SELECT pin_hash FROM users WHERE id = ?', [userId]);
  const ok = await bcrypt.compare(pin, row ? row.pin_hash : DUMMY_BCRYPT_HASH);
  if (!ok) {
    await recordFailedAttempt(identifier);
    return { status: 401, error: 'Incorrect PIN' };
  }
  await clearAttempts(identifier);
  return null;
}

async function requirePin(req, res, next) {
  try {
    const failure = await verifyActionPin(req.userId, req.body?.pin);
    if (failure) return res.status(failure.status).json({ error: failure.error });
    next();
  } catch (err) {
    next(err);
  }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verify(token);
  if (!payload || payload.role !== 'admin' || payload.stage !== 'full') {
    return res.status(401).json({ error: 'Not authenticated as admin' });
  }
  req.adminId = payload.uid;
  next();
}


// ---------- database-backed login lockout ----------
//
// Complements (doesn't replace) the in-memory express-rate-limit above.
// That limiter resets on every restart/redeploy — fine as a first line of
// defense, but not durable. This is the real enforcement: it persists in
// MySQL, so a restart can't reset an attacker's attempt count back to
// zero. Mirrors the "3 attempts then a cooldown" behavior the Flutter
// UI already implies client-side, except enforced here on the server so
// it can't be bypassed by calling the API directly (as our own curl
// testing demonstrated the client-side version could be).
// Escalating lockout tiers, strictest first. A flat "3 attempts, wait 30s"
// forever is cheap for an attacker to grind through indefinitely,
// especially against a 4-digit PIN (10,000 possibilities) — so repeated
// cycles of failures now escalate into much longer locks instead of
// resetting to the same 30s cost every time.
const LOCKOUT_TIERS = [
  { attempts: 10, lockoutSeconds: 30 * 60 }, // 10 failures in 30 min -> 30 min lock
  { attempts: 6, lockoutSeconds: 5 * 60 },   // 6 failures in 5 min -> 5 min lock
  { attempts: 3, lockoutSeconds: 30 },       // 3 failures in 30 sec -> 30 sec lock
];

// Returns null if not locked, or the number of seconds remaining if it is.
async function checkLockout(identifier) {
  for (const tier of LOCKOUT_TIERS) {
    const [[{ count }]] = await pool.query(
      'SELECT COUNT(*) AS count FROM login_attempts WHERE identifier = ? AND attempted_at > (NOW() - INTERVAL ? SECOND)',
      [identifier, tier.lockoutSeconds]
    );
    if (count < tier.attempts) continue;

    const [[oldest]] = await pool.query(
      'SELECT attempted_at FROM login_attempts WHERE identifier = ? ORDER BY attempted_at DESC LIMIT 1 OFFSET ?',
      [identifier, tier.attempts - 1]
    );
    const unlockAt = new Date(oldest.attempted_at).getTime() + tier.lockoutSeconds * 1000;
    const secondsLeft = Math.max(1, Math.ceil((unlockAt - Date.now()) / 1000));
    if (secondsLeft > 0) return secondsLeft;
  }
  return null;
}

async function recordFailedAttempt(identifier) {
  await pool.execute('INSERT INTO login_attempts (identifier) VALUES (?)', [identifier]);
}

async function clearAttempts(identifier) {
  await pool.execute('DELETE FROM login_attempts WHERE identifier = ?', [identifier]);
}

// ---------- Face++ face-matching (identity verification) ----------
//
// Compares two face photos (a government ID photo and a live selfie) and
// returns a similarity score from 0-100. This is a REAL third-party call —
// unlike the provider-routing simulation elsewhere in this file — but the
// score alone doesn't decide anything by itself; the caller decides the
// threshold for auto-approval vs. sending to manual admin review.

const FACEPP_API_KEY = process.env.FACEPP_API_KEY;
const FACEPP_API_SECRET = process.env.FACEPP_API_SECRET;
const FACEPP_COMPARE_URL = 'https://api-us.faceplusplus.com/facepp/v3/compare';

// image1Base64 / image2Base64 should be raw base64 (no "data:image/..." prefix).
// Returns { confidence, matched } on success, or throws on a Face++/network error.
// Free Face++ keys only allow about one request at a time. Registration makes
// several Face++ calls in a row (duplicate search, ID comparison, adding the
// face), so any of them can come back "CONCURRENCY_LIMIT_EXCEEDED". Instead of
// failing (which sent accounts to manual review with no score), wait a moment
// and try again, up to 4 times.
async function faceppFetch(url, form) {
  let last = null;
  for (const waitMs of [0, 1200, 2400, 3600]) {
    if (waitMs) await new Promise((resolve) => setTimeout(resolve, waitMs));
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const data = await res.json();
    last = { res, data };
    if (!/CONCURRENCY_LIMIT_EXCEEDED/i.test(data.error_message || '')) break;
  }
  return last;
}

async function compareFaces(image1Base64, image2Base64) {
  if (!FACEPP_API_KEY || !FACEPP_API_SECRET) {
    throw new Error('Face verification is not configured on the server');
  }

  const form = new URLSearchParams();
  form.set('api_key', FACEPP_API_KEY);
  form.set('api_secret', FACEPP_API_SECRET);
  form.set('image_base64_1', image1Base64);
  form.set('image_base64_2', image2Base64);

  const { res, data } = await faceppFetch(FACEPP_COMPARE_URL, form);

  if (!res.ok || data.error_message) {
    throw new Error(data.error_message || 'Face comparison failed');
  }
  if (!data.faces1?.length || !data.faces2?.length) {
    throw new Error('Could not detect a face in one or both images');
  }

  // Face++'s own suggested threshold for a 1e-3 false-accept-rate is roughly
  // 62.3 — using 65 here as a slightly stricter, simple constant. Anything
  // under this goes to manual admin review rather than auto-rejecting, since
  // lighting/angle can legitimately lower a real match's score.
  const confidence = data.confidence ?? 0;
  return { confidence, matched: confidence >= 65 };
}

// ---------- Face++ duplicate-face check (one face = one account) ----------
//
// compareFaces() above only checks that the selfie matches the ID photo in the
// SAME submission. It can't tell if this face already has another account. For
// that, every registered selfie is stored in a Face++ FaceSet and each new
// selfie is searched against it. If any Face++ call fails the check is
// skipped (fail-open, same as compareFaces) so registration never breaks.
const FACEPP_BASE = 'https://api-us.faceplusplus.com/facepp/v3';
const FACESET_OUTER_ID = process.env.FACESET_OUTER_ID || 'paycst_users';
// Similarity (0-100) at or above which a new selfie counts as "already registered".
const FACE_DUPLICATE_THRESHOLD = Number(process.env.FACE_DUPLICATE_THRESHOLD || 80);
let faceSetReady = false;

async function faceppPost(path, fields) {
  const form = new URLSearchParams();
  form.set('api_key', FACEPP_API_KEY);
  form.set('api_secret', FACEPP_API_SECRET);
  for (const [k, v] of Object.entries(fields)) form.set(k, v);
  const { res, data } = await faceppFetch(`${FACEPP_BASE}${path}`, form);
  if (!res.ok || data.error_message) throw new Error(data.error_message || `Face++ ${path} failed`);
  return data;
}

async function ensureFaceSet() {
  if (faceSetReady) return;
  try {
    await faceppPost('/faceset/create', { outer_id: FACESET_OUTER_ID, display_name: 'PayCST users' });
  } catch (err) {
    if (!/FACESET_EXIST/i.test(err.message)) throw err;
  }
  faceSetReady = true;
}

async function detectFaceToken(imageBase64) {
  const data = await faceppPost('/detect', { image_base64: imageBase64 });
  if (!data.faces?.length) throw new Error('No face detected in selfie');
  return data.faces[0].face_token;
}

// Returns the best match ({ confidence, ... }) if this face is already in the
// FaceSet at/above the threshold, otherwise null.
async function findDuplicateFace(faceToken) {
  try {
    const data = await faceppPost('/search', { face_token: faceToken, outer_id: FACESET_OUTER_ID });
    const top = data.results?.[0];
    return top && top.confidence >= FACE_DUPLICATE_THRESHOLD ? top : null;
  } catch (err) {
    if (/EMPTY_FACESET|FACESET_NOT_FOUND/i.test(err.message)) return null; // nobody registered yet
    throw err;
  }
}

async function addFaceToIndex(faceToken) {
  await faceppPost('/faceset/addface', { outer_id: FACESET_OUTER_ID, face_tokens: faceToken });
}

// Lets the app tell people "username / number already used" BEFORE they go
// through the ID + selfie scan. Answers only those two yes/no questions.
const availabilityLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many attempts. Please try again later.' },
});

// ---------- phone number verification (SMS code) ----------
// Sign-up flow: the app asks for a code (send-otp), the person types the 6 digits
// they received (verify-otp), and the server hands back a short-lived signed token
// that /api/register requires. Codes are stored hashed, expire after 5 minutes,
// allow 5 wrong guesses, and can only be re-sent once a minute.
const OTP_TTL_SECONDS = 5 * 60;
const OTP_RESEND_SECONDS = 60;
const OTP_MAX_ATTEMPTS = 5;
const OTP_MAX_SENDS_PER_HOUR = 5;
// Global cap across all numbers, separate from the per-number limit above.
const SMS_MAX_SENDS_PER_HOUR = (() => {
  const parsed = Number(process.env.SMS_MAX_SENDS_PER_HOUR);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 100;
})();
// Turn off only for local testing of old app builds: REQUIRE_PHONE_OTP=false
const REQUIRE_PHONE_OTP = process.env.REQUIRE_PHONE_OTP !== 'false';
// Dev mode: with no SMS provider set, the code is returned to the app so the demo works.
// Never leave this on once real SMS is configured (it is ignored then anyway).
const OTP_DEV_MODE = !smsIsReal && process.env.OTP_DEV_MODE === 'true';

pool.execute(
  `CREATE TABLE IF NOT EXISTS phone_otps (
     id INT AUTO_INCREMENT PRIMARY KEY,
     phone_number VARCHAR(20) NOT NULL,
     code_hash CHAR(64) NOT NULL,
     attempts INT NOT NULL DEFAULT 0,
     expires_at DATETIME NOT NULL,
     consumed TINYINT(1) NOT NULL DEFAULT 0,
     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
     KEY idx_phone_otps (phone_number, created_at)
   ) ENGINE=InnoDB`
).catch((err) => console.error('Could not create phone_otps table:', err.message));

function hashOtp(phone, code) {
  return crypto.createHmac('sha256', JWT_SECRET).update(`${phone}:${code}`).digest('hex');
}

// Canonical phone shape used by users.phone_number and users.wallet_id:
// 09XXXXXXXXX. Mirrors normalizePhMobile() in the Flutter app exactly, so the
// client and server agree on what a valid PH mobile number is.
function normalizePhone(value) {
  if (typeof value !== 'string') return null;
  let digits = value.replace(/[\s-]/g, '');
  if (digits.startsWith('+63')) digits = `0${digits.slice(3)}`;
  else if (digits.startsWith('63') && digits.length === 12) digits = `0${digits.slice(2)}`;
  return /^09\d{9}$/.test(digits) ? digits : null;
}

// These routes read the phone before their own validation, so normalize at the
// route edge. Exact paths only: PCST-123456 returns null from normalizePhone()
// and is left exactly as it was.
app.post('/api/register', (req, res, next) => {
  const phone = normalizePhone(req.body?.phoneNumber);
  if (phone) req.body.phoneNumber = phone;
  next();
});
app.get('/api/wallet/lookup', (req, res, next) => {
  const phone = normalizePhone(req.query?.walletId);
  if (phone) req.query.walletId = phone;
  next();
});
app.get('/api/admin/users', (req, res, next) => {
  const phone = normalizePhone(req.query?.search);
  if (phone) req.query.search = phone;
  next();
});

const otpSendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many code requests from this network. Please try again later.' },
});

const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many attempts. Please try again later.' },
});

app.post('/api/phone/send-otp', otpSendLimiter, asyncRoute(async (req, res) => {
  const phoneNumber = normalizePhone(req.body?.phoneNumber);
  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number must be 11 digits starting with 09 (e.g. 09171234567)' });
  }
  if (!smsIsReal && !OTP_DEV_MODE) {
    return res.status(503).json({ error: 'Phone verification is not configured' });
  }
  const [taken] = await pool.execute('SELECT id FROM users WHERE phone_number = ? OR wallet_id = ?', [phoneNumber, phoneNumber]);
  if (taken.length > 0) {
    return res.status(409).json({ error: 'That phone number is already registered to an account' });
  }

  // Cooldown between sends + hourly cap per number.
  const [recent] = await pool.execute(
    `SELECT TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age FROM phone_otps
      WHERE phone_number = ? ORDER BY id DESC LIMIT 1`,
    [phoneNumber]
  );
  if (recent.length > 0 && recent[0].age < OTP_RESEND_SECONDS) {
    const wait = OTP_RESEND_SECONDS - recent[0].age;
    return res.status(429).json({ error: `Please wait ${wait}s before asking for a new code`, retryAfterSeconds: wait });
  }
  const [hourly] = await pool.execute(
    'SELECT COUNT(*) AS n FROM phone_otps WHERE phone_number = ? AND created_at > (NOW() - INTERVAL 1 HOUR)',
    [phoneNumber]
  );
  if (hourly[0].n >= OTP_MAX_SENDS_PER_HOUR) {
    return res.status(429).json({ error: 'Too many codes sent to this number. Please try again in an hour.' });
  }
  const [recentTotal] = await pool.execute(
    'SELECT COUNT(*) AS n FROM phone_otps WHERE created_at > (NOW() - INTERVAL 1 HOUR)'
  );
  if (recentTotal[0].n >= SMS_MAX_SENDS_PER_HOUR) {
    console.warn('OTP SMS hourly cap reached');
    return res.status(429).json({ error: 'Too many requests right now. Please try again later.' });
  }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  // Older codes for this number stop working as soon as a new one is issued.
  await pool.execute('UPDATE phone_otps SET consumed = 1 WHERE phone_number = ? AND consumed = 0', [phoneNumber]);
  const [result] = await pool.execute(
    `INSERT INTO phone_otps (phone_number, code_hash, expires_at)
     VALUES (?, ?, NOW() + INTERVAL ${OTP_TTL_SECONDS} SECOND)`,
    [phoneNumber, hashOtp(phoneNumber, code)]
  );

  try {
    await sendSms(phoneNumber, `Your PayCST verification code is ${code}. It expires in 5 minutes. Do not share it with anyone.`);
  } catch (err) {
    console.error('SMS send failed:', err.message);
    await pool.execute('DELETE FROM phone_otps WHERE id = ?', [result.insertId]);
    return res.status(502).json({ error: 'We could not send the text message. Please try again in a moment.' });
  }

  const body = { ok: true, expiresInSeconds: OTP_TTL_SECONDS, resendAfterSeconds: OTP_RESEND_SECONDS };
  if (OTP_DEV_MODE) body.devCode = code;
  res.json(body);
}));

app.post('/api/phone/verify-otp', otpVerifyLimiter, asyncRoute(async (req, res) => {
  const { code } = req.body || {};
  const phoneNumber = normalizePhone(req.body?.phoneNumber);
  if (!phoneNumber || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Enter the 6-digit code we sent you' });
  }
  const [rows] = await pool.execute(
    `SELECT id, code_hash, attempts, (expires_at < NOW()) AS expired FROM phone_otps
      WHERE phone_number = ? AND consumed = 0 ORDER BY id DESC LIMIT 1`,
    [phoneNumber]
  );
  if (rows.length === 0) {
    return res.status(400).json({ error: 'No active code for this number. Please request a new one.' });
  }
  const row = rows[0];
  if (row.expired) {
    await pool.execute('UPDATE phone_otps SET consumed = 1 WHERE id = ?', [row.id]);
    return res.status(400).json({ error: 'That code has expired. Please request a new one.' });
  }
  if (row.attempts >= OTP_MAX_ATTEMPTS) {
    await pool.execute('UPDATE phone_otps SET consumed = 1 WHERE id = ?', [row.id]);
    return res.status(429).json({ error: 'Too many wrong tries. Please request a new code.' });
  }

  const given = Buffer.from(hashOtp(phoneNumber, code), 'hex');
  const real = Buffer.from(row.code_hash, 'hex');
  if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) {
    await pool.execute('UPDATE phone_otps SET attempts = attempts + 1 WHERE id = ?', [row.id]);
    const left = OTP_MAX_ATTEMPTS - (row.attempts + 1);
    return res.status(400).json({
      error: left > 0 ? `Wrong code. ${left} ${left === 1 ? 'try' : 'tries'} left.` : 'Too many wrong tries. Please request a new code.',
    });
  }

  await pool.execute('UPDATE phone_otps SET consumed = 1 WHERE id = ?', [row.id]);
  // Proof of ownership that /api/register checks. Valid for 15 minutes (long enough
  // to finish the ID + selfie steps) and only for this exact phone number.
  const verificationToken = sign({ purpose: 'phone-verify', phone: phoneNumber }, '15m');
  res.json({ ok: true, verificationToken });
}));

// ---------- registration / login (password, THEN pin) ----------

app.get('/api/register/check', availabilityLimiter, asyncRoute(async (req, res) => {
  const username = (req.query.username || '').toString().trim();
  const phoneInput = (req.query.phone || '').toString().trim();
  const phone = normalizePhone(phoneInput) || phoneInput;
  let usernameTaken = false;
  let phoneTaken = false;
  if (username) {
    const [rows] = await pool.execute('SELECT id FROM users WHERE username = ?', [username]);
    usernameTaken = rows.length > 0;
  }
  if (phone) {
    const [rows] = await pool.execute('SELECT id FROM users WHERE phone_number = ? OR wallet_id = ?', [phone, phone]);
    phoneTaken = rows.length > 0;
  }
  res.json({ usernameTaken, phoneTaken });
}));

// Per-IP cap on sign-ups, on top of the per-username limit (which an attacker
// could dodge by changing the username every time).
const registerIpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many sign-up attempts from this network. Please try again later.' },
});

// ~4.5 MB of image per photo. Checks the size and that the bytes really are a
// JPEG / PNG / WebP image (not some other file dressed up as a photo).
const MAX_PHOTO_BASE64_CHARS = 6_000_000;
function looksLikeImage(b64) {
  if (typeof b64 !== 'string' || b64.length < 100 || b64.length > MAX_PHOTO_BASE64_CHARS) return false;
  const head = Buffer.from(b64.slice(0, 32), 'base64');
  const jpeg = head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff;
  const png = head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47;
  const webp = head.toString('latin1', 0, 4) === 'RIFF' && head.toString('latin1', 8, 12) === 'WEBP';
  return jpeg || png || webp;
}

// Set KEEP_ID_PHOTOS=true in Railway to keep ID photos after a decision.
const KEEP_ID_PHOTOS = process.env.KEEP_ID_PHOTOS === 'true';

app.post('/api/register', registerIpLimiter, authLimiter, asyncRoute(async (req, res) => {
   const {
    username, password, pin, phoneNumber,
    termsAccepted, governmentIdNumber,
    governmentIdPhotoFrontBase64, governmentIdPhotoBackBase64, selfiePhotoBase64,
    phoneVerificationToken,
  } = req.body || {};

  if (!username || !password || !pin || !phoneNumber) {
    return res.status(400).json({ error: 'username, password, pin, and phoneNumber are required' });
  }
  if ([username, password, pin, phoneNumber].some((v) => typeof v !== 'string')) {
    return res.status(400).json({ error: 'Invalid request' });
  }
  if (!/^[A-Za-z0-9_. -]{3,30}$/.test(username.trim())) {
    return res.status(400).json({ error: 'Username must be 3-30 characters: letters, numbers, spaces, . _ -' });
  }
  if (password.length > 72) return res.status(400).json({ error: 'Password must be 72 characters or fewer' });
  // Same rules as the app's checklist: 8+ chars, a letter, a number, and one of @ * _ -
  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password) || !/[@*_-]/.test(password)) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters and include a letter, a number, and one of @ * _ -',
    });
  }
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
  if (!/^09\d{9}$/.test(phoneNumber)) {
    return res.status(400).json({ error: 'Phone number must be 11 digits starting with 09 (e.g. 09171234567)' });
  }
  if (!termsAccepted) {
    return res.status(400).json({ error: 'You must accept the Terms and Conditions to register' });
  }
  if (REQUIRE_PHONE_OTP) {
    const proof = typeof phoneVerificationToken === 'string' ? verify(phoneVerificationToken) : null;
    if (!proof || proof.purpose !== 'phone-verify' || proof.phone !== phoneNumber) {
      return res.status(400).json({ error: 'Please verify your phone number with the code we text you' });
    }
  }
  if (!governmentIdNumber || !governmentIdNumber.toString().trim()) {
    return res.status(400).json({ error: 'A government-issued ID number is required' });
  }
  if (
    !looksLikeImage(governmentIdPhotoFrontBase64) ||
    !looksLikeImage(governmentIdPhotoBackBase64) ||
    !looksLikeImage(selfiePhotoBase64)
  ) {
    return res.status(400).json({ error: 'The ID and selfie photos must be JPEG or PNG images under about 4 MB each' });
  }
  if (!governmentIdPhotoFrontBase64 || !governmentIdPhotoBackBase64 || !selfiePhotoBase64) {
    return res.status(400).json({ error: 'Photos of the front and back of your ID, plus a live selfie, are required' });
  }

  // Same ID written differently ("ab-123 456" vs "AB123456") must count as one.
  const normalizedId = governmentIdNumber.toString().toUpperCase().replace(/[\s-]/g, '');

  const conn = await pool.getConnection();
  try {
    if (usersByUsername.has(username)) {
      return res.status(409).json({ error: 'That username is already taken' });
    }
    const [existingUsername] = await conn.execute('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsername.length > 0) return res.status(409).json({ error: 'That username is already taken' });

    const [existingPhone] = await conn.execute('SELECT id FROM users WHERE phone_number = ?', [phoneNumber]);
    if (existingPhone.length > 0) {
      return res.status(409).json({ error: 'That phone number is already registered to an account' });
    }

    const [existingId] = await conn.execute(
      "SELECT id FROM users WHERE REPLACE(REPLACE(UPPER(government_id_number), ' ', ''), '-', '') = ?",
      [normalizedId]
    );
    if (existingId.length > 0) {
      return res.status(409).json({ error: 'That government ID is already registered to an account' });
    }

    // One face = one account: search the new selfie against every selfie
    // already registered. Skipped (not blocked) if Face++ is unavailable.
    let selfieFaceToken = null;
    if (FACEPP_API_KEY && FACEPP_API_SECRET) {
      try {
        await ensureFaceSet();
        selfieFaceToken = await detectFaceToken(selfiePhotoBase64);
        const duplicateFace = await findDuplicateFace(selfieFaceToken);
        if (duplicateFace) {
          return res.status(409).json({ error: 'This face is already registered to another account' });
        }
      } catch (err) {
        console.error('Duplicate-face check skipped:', err.message);
        selfieFaceToken = null;
      }
    }

    // Face match: compares the live selfie against the photo on the ID. This
    // only confirms the selfie matches THIS ID photo; the duplicate-face search
    // just above is what stops the same face registering under another account.
    let confidence = null;
    let verificationStatus = 'pending';
    try {
       const result = await compareFaces(governmentIdPhotoFrontBase64, selfiePhotoBase64);
      confidence = result.confidence;
      verificationStatus = result.matched ? 'approved' : 'pending';
    } catch (err) {
      // Face++ failure (bad image, no face detected, API error) does NOT
      // block registration — it just leaves the account pending for an
      // admin to review manually, same as a low-confidence score would.
      console.error('Face comparison failed during registration:', err.message);
      verificationStatus = 'pending';
    }

    // Only a sign-up confirmed with a real fingerprint touch may be approved
    // automatically. Phones with just a screen lock, no lock, or a browser go
    // to an admin even if the face matched. (This is what the app reports; a
    // modified app could claim 'fingerprint', so it is a safeguard, not proof.)
    const verificationMethod = typeof req.body?.verificationMethod === 'string' ? req.body.verificationMethod : 'none';
    if (verificationMethod !== 'fingerprint' && verificationStatus === 'approved') {
      verificationStatus = 'pending';
    }
    // The app sets this when the ID number had to be typed in, or the live
    // selfie check was skipped after repeated misses. An admin reviews those
    // photos by hand, whatever the face score says.
    if (req.body?.needsManualReview === true && verificationStatus === 'approved') {
      verificationStatus = 'pending';
    }

    // Informational only: this does not decide whether the account is approved.
    // The current app has one `needsManualReview` flag for "typed ID or skipped
    // liveness", so the conservative value is 'skipped'. Browser sign-up also
    // has no real liveness step and reports verificationMethod 'web'.
    const livenessSkipped =
      req.body?.needsManualReview === true ||
      req.body?.livenessSkipped === true ||
      req.body?.skipped === true ||
      req.body?.livenessPassed === false ||
      req.body?.livenessStatus === 'skipped' ||
      verificationMethod === 'web';
    const livenessStatus = livenessSkipped ? 'skipped' : 'passed';

    const passwordHash = await bcrypt.hash(password, 10);
    const pinHash = await bcrypt.hash(pin, 10);
    const walletId = phoneNumber;

    let result;
    try {
      [result] = await conn.execute(
      `INSERT INTO users
         (username, password_hash, pin_hash, wallet_id, balance, phone_number,
          government_id_number, government_id_photo, government_id_photo_back, selfie_photo,
          terms_accepted_at, verification_status, liveness_status, face_match_confidence)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)`,
      [
        username, passwordHash, pinHash, walletId, 0, phoneNumber,
        normalizedId, encryptPhoto(governmentIdPhotoFrontBase64), encryptPhoto(governmentIdPhotoBackBase64), encryptPhoto(selfiePhotoBase64),
        verificationStatus, livenessStatus, confidence,
      ]
    );
    } catch (err) {
      // Two sign-ups racing each other can both pass the SELECT checks above;
      // the database's UNIQUE keys (see sql/add_unique_constraints.sql) catch that.
      if (err.code === 'ER_DUP_ENTRY') {
        const m = err.sqlMessage || '';
        const msg = /phone|wallet/i.test(m)
          ? 'That phone number is already registered to an account'
          : /government|gov_id/i.test(m)
            ? 'That government ID is already registered to an account'
            : 'That username is already taken';
        return res.status(409).json({ error: msg });
      }
      throw err;
    }

    if (selfieFaceToken) {
      try {
        await addFaceToIndex(selfieFaceToken);
      } catch (err) {
        console.error('Could not add face to index:', err.message);
      }
    }

    if (verificationStatus === 'approved' && !KEEP_ID_PHOTOS) {
      await conn.execute(
        "UPDATE users SET government_id_photo = '', government_id_photo_back = '', selfie_photo = '' WHERE id = ?",
        [result.insertId]
      );
    }

    await refreshUserInIndex(result.insertId);

    res.json({
      ok: true,
      walletId,
      verificationStatus,
      message: verificationStatus === 'approved'
        ? 'Account verified — you can log in now.'
        : 'Account created. Your ID is pending verification by an admin before you can log in.',
    });
  } finally {
    conn.release();
  }
}));

// Step 1: password only. Returns a short-lived "pending" token that is
// NOT enough to call any authenticated endpoint — it only unlocks the
// pin-verify step below.
app.post('/api/login', authLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

  const identifier = `login:${username.toString().trim().toLowerCase()}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

        const [rows] = await pool.execute(
    'SELECT id, password_hash, status, verification_status FROM users WHERE username = ?',
    [username]
  );
  const user = rows[0];
  // Always run bcrypt, even when the username doesn't exist, so a lookup
  // miss takes the same time as a real-but-wrong-password attempt —
  // otherwise the instant-return-on-miss path leaks which usernames are
  // registered via response timing.
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_BCRYPT_HASH);
  if (!user || !ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  // Checked AFTER password verification (not before) so a wrong-password
  // attempt against a suspended account still just says "incorrect
  // username or password" — it doesn't leak account status to a guesser.
  if (user.status === 'suspended') {
    return res.status(403).json({ error: 'This account has been suspended. Contact support for assistance.' });
  }
  if (user.verification_status === 'pending') {
    return res.status(403).json({ error: 'Your account is still pending ID verification. Please check back later.' });
  }
  if (user.verification_status === 'rejected') {
    return res.status(403).json({ error: 'Your ID verification was not approved. Contact support for assistance.' });
  }
  await clearAttempts(identifier);

  const pendingToken = sign({ uid: user.id, stage: 'pending', role: 'user' }, '5m');
  res.json({ pendingToken });
}));

// Step 2: the PIN, checked separately from the password. Only after this
// succeeds does the client get a token any other endpoint will accept.
app.post('/api/login/verify-pin', pinLimiter, asyncRoute(async (req, res) => {
  const { pendingToken, pin } = req.body || {};
  const payload = pendingToken && verify(pendingToken);
  if (!payload || payload.stage !== 'pending' || payload.role !== 'user') {
    return res.status(401).json({ error: 'Login session expired, please log in again' });
  }

  const identifier = `pin:${payload.uid}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, username, wallet_id, pin_hash, balance, session_version FROM users WHERE id = ?', [
    payload.uid,
  ]);
  const user = rows[0];
  const ok = await bcrypt.compare(pin, user ? user.pin_hash : DUMMY_BCRYPT_HASH);
  if (!user || !ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect PIN' });
  }
  await clearAttempts(identifier);

  const token = sign({ uid: user.id, stage: 'full', role: 'user', sv: user.session_version }, '2h');
  res.json({
    token,
    // balance is returned as an integer count of centavos — the client
    // divides by 100 only when displaying it.
    user: { id: user.id, username: user.username, walletId: user.wallet_id, balance: toCentavos(user.balance) },
  });
}));

// ---------- fingerprint / device login ----------
// After a normal login the person can switch on "fingerprint login" in the
// app. The server then gives that phone a random device token (only its
// SHA-256 hash is stored here). The phone keeps the token in its secure
// keystore and only reveals it after a fingerprint check. Logging in with it
// gives a normal 2-hour session without typing password + PIN. The token is
// replaced with a fresh one on every use, expires after 30 days of not being
// used, and can be revoked. Money actions still ask for the PIN.
const DEVICE_TOKEN_DAYS = 30;
const MAX_DEVICES_PER_USER = 5;
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

const deviceLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many attempts. Please try again later.' },
});

app.post('/api/device/enroll', requireAuth, moneyLimiter, requirePin, asyncRoute(async (req, res) => {
  const deviceName = cleanText(req.body?.deviceName, 100) || 'Phone';

  // Keep at most MAX_DEVICES_PER_USER phones: drop the oldest ones.
  const [existing] = await pool.execute('SELECT id FROM device_tokens WHERE user_id = ? ORDER BY created_at DESC', [req.userId]);
  if (existing.length >= MAX_DEVICES_PER_USER) {
    const dropIds = existing.slice(MAX_DEVICES_PER_USER - 1).map((r) => r.id);
    await pool.query('DELETE FROM device_tokens WHERE id IN (?)', [dropIds]);
  }

  const deviceToken = crypto.randomBytes(32).toString('hex');
  await pool.execute(
    'INSERT INTO device_tokens (user_id, token_hash, device_name, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? DAY))',
    [req.userId, sha256(deviceToken), deviceName, DEVICE_TOKEN_DAYS]
  );
  res.json({ deviceToken });
}));

app.post('/api/login/device', deviceLoginLimiter, asyncRoute(async (req, res) => {
  const expired = { error: 'Fingerprint login expired. Please log in with your password.' };
  const deviceToken = req.body?.deviceToken;
  if (typeof deviceToken !== 'string' || !/^[0-9a-f]{64}$/.test(deviceToken)) {
    return res.status(401).json(expired);
  }
  const oldHash = sha256(deviceToken);
  const [[row]] = await pool.query(
    `SELECT d.id AS device_id, u.id, u.username, u.wallet_id, u.balance, u.status, u.verification_status, u.session_version
       FROM device_tokens d JOIN users u ON u.id = d.user_id
      WHERE d.token_hash = ? AND d.expires_at > NOW()`,
    [oldHash]
  );
  if (!row) return res.status(401).json(expired);
  if (row.status === 'suspended') {
    return res.status(403).json({ error: 'This account has been suspended. Contact support for assistance.' });
  }
  if (row.verification_status !== 'approved') {
    return res.status(403).json({ error: 'Your account is not verified. Please log in with your password.' });
  }

  // Swap in a new token. The WHERE on the old hash means an old token that was
  // already used (replayed, or raced) matches nothing and is refused.
  const newToken = crypto.randomBytes(32).toString('hex');
  const [swap] = await pool.execute(
    'UPDATE device_tokens SET token_hash = ?, last_used_at = NOW(), expires_at = DATE_ADD(NOW(), INTERVAL ? DAY) WHERE id = ? AND token_hash = ?',
    [sha256(newToken), DEVICE_TOKEN_DAYS, row.device_id, oldHash]
  );
  if (swap.affectedRows !== 1) return res.status(401).json(expired);

  res.json({
    token: sign({ uid: row.id, stage: 'full', role: 'user', sv: row.session_version }, '2h'),
    deviceToken: newToken,
    user: { id: row.id, username: row.username, walletId: row.wallet_id, balance: toCentavos(row.balance) },
  });
}));

// Turn fingerprint login off for this phone (or all phones if no token is sent).
app.post('/api/device/revoke', requireAuth, asyncRoute(async (req, res) => {
  const deviceToken = req.body?.deviceToken;
  if (typeof deviceToken === 'string' && /^[0-9a-f]{64}$/.test(deviceToken)) {
    await pool.execute('DELETE FROM device_tokens WHERE user_id = ? AND token_hash = ?', [req.userId, sha256(deviceToken)]);
  } else {
    await pool.execute('DELETE FROM device_tokens WHERE user_id = ?', [req.userId]);
  }
  res.json({ ok: true });
}));

// Kills every live session and every enrolled fingerprint phone for this
// account. The version bump is the part that matters: tokens already handed
// out carry the old `sv`, and requireAuth rejects any token whose `sv` no
// longer matches users.session_version. A fresh token is returned so the
// caller - who just re-proved the PIN - is not logged out by its own request.
app.post('/api/auth/revoke-all', requireAuth, requirePin, asyncRoute(async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute('UPDATE users SET session_version = session_version + 1 WHERE id = ?', [req.userId]);
    await conn.execute('DELETE FROM device_tokens WHERE user_id = ?', [req.userId]);
    // Read the new version on the same connection and inside the transaction,
    // so the token below is signed with exactly the value that was committed.
    const [[row]] = await conn.query(
      'SELECT id, username, wallet_id, balance, session_version FROM users WHERE id = ?',
      [req.userId]
    );
    if (!row) {
      await conn.rollback();
      return res.status(404).json({ error: 'User not found' });
    }
    await conn.commit();
    res.json({
      token: sign({ uid: row.id, stage: 'full', role: 'user', sv: row.session_version }, '2h'),
      user: { id: row.id, username: row.username, walletId: row.wallet_id, balance: toCentavos(row.balance) },
    });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// Changes the wallet PIN. The current PIN is verified with the same durable
// lockout counter as login and money actions, so this cannot be used as an
// unthrottled guessing oracle. A PIN change invalidates every other session
// and every enrolled fingerprint phone, then hands the caller a fresh token.
app.post('/api/auth/change-pin', requireAuth, pinLimiter, asyncRoute(async (req, res) => {
  const { currentPin, newPin } = req.body || {};
  if (typeof currentPin !== 'string' || !/^\d{4}$/.test(currentPin)) {
    return res.status(400).json({ error: 'Enter your current 4-digit PIN' });
  }
  // Same rule as registration.
  if (typeof newPin !== 'string' || !/^\d{4}$/.test(newPin)) {
    return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
  }
  if (newPin === currentPin) {
    return res.status(400).json({ error: 'The new PIN must be different from the current PIN' });
  }

  const identifier = `pin:${req.userId}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }
  const [[user]] = await pool.query('SELECT pin_hash FROM users WHERE id = ?', [req.userId]);
  const ok = await bcrypt.compare(currentPin, user ? user.pin_hash : DUMMY_BCRYPT_HASH);
  if (!ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect PIN' });
  }
  await clearAttempts(identifier);

  // Same bcrypt cost as registration.
  const pinHash = await bcrypt.hash(newPin, 10);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute('UPDATE users SET pin_hash = ?, session_version = session_version + 1 WHERE id = ?', [pinHash, req.userId]);
    await conn.execute('DELETE FROM device_tokens WHERE user_id = ?', [req.userId]);
    // Same connection and transaction as the writes above, so the token is
    // signed with the version that is actually committed.
    const [[row]] = await conn.query(
      'SELECT id, username, wallet_id, balance, session_version FROM users WHERE id = ?',
      [req.userId]
    );
    if (!row) {
      await conn.rollback();
      return res.status(404).json({ error: 'User not found' });
    }
    await conn.commit();
    res.json({
      token: sign({ uid: row.id, stage: 'full', role: 'user', sv: row.session_version }, '2h'),
      user: { id: row.id, username: row.username, walletId: row.wallet_id, balance: toCentavos(row.balance) },
    });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- password recovery ----------
//
// This deployment has no email column and no mail provider, so recovery is
// admin-assisted: the admin route below issues the code and returns it to the
// authenticated admin, who hands it to the user out of band. Delivery sits
// behind deliverResetCode() so SMS can be added later without touching the
// request/reset flow.
//
// Codes are 6 digits, stored only as an HMAC-SHA256 hex digest bound to the
// user id, valid for 10 minutes, and dead on first use, after 5 wrong tries,
// or at expiry. The PIN is never touched here.
const RESET_CODE_TTL_SECONDS = 10 * 60;
const RESET_MAX_ATTEMPTS = 5;

function hashResetCode(userId, code) {
  return crypto.createHmac('sha256', JWT_SECRET)
    .update(`reset:${userId}:${code}`)
    .digest('hex');
}

async function deliverResetCode(user, code) {
  // No provider yet. This function must never log or return the code; the
  // admin route returns it to the authenticated admin instead. When SMS is
  // wired, this is the only function that changes.
  return 'admin';
}

async function issueResetCode(user) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  // One live code per account: older unused codes stop working immediately.
  await pool.execute(
    'UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL',
    [user.id]
  );
  await pool.execute(
    `INSERT INTO password_resets (user_id, code_hash, expires_at)
     VALUES (?, ?, NOW() + INTERVAL ${RESET_CODE_TTL_SECONDS} SECOND)`,
    [user.id, hashResetCode(user.id, code)]
  );
  return code;
}

// Same shape as the phone-OTP limiters: an IP bucket plus a per-identifier
// bucket, so rotating IPs does not buy unlimited guesses for one account.
const resetIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many attempts. Please try again later.' },
});

const resetIdentifierLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const raw = String(req.body?.identifier || '').trim().toUpperCase();
    const identifier = normalizePhone(raw) || raw;
    return identifier ? `pwreset:${identifier}` : ipKeyGenerator(req);
  },
  message: { error: 'Too many attempts. Please try again later.' },
});

// The only shapes this database stores: the 09XXXXXXXXX the app already
// normalizes to (normalizePhMobile), and the legacy PCST-123456 wallet id.
// Email is not collected in the schema, so it cannot identify an account.
function isResetIdentifier(value) {
  return /^09\d{9}$/.test(value) || /^PCST-\d{6}$/.test(value);
}

async function findResetUser(identifier) {
  const [[user]] = await pool.query(
    `SELECT id, username, phone_number, wallet_id
       FROM users
      WHERE (phone_number = ? OR wallet_id = ?) AND status = 'active'
      LIMIT 1`,
    [identifier, identifier]
  );
  return user || null;
}

app.post('/api/auth/forgot-password', resetIpLimiter, resetIdentifierLimiter, asyncRoute(async (req, res) => {
  const rawIdentifier = String(req.body?.identifier || '').trim().toUpperCase();
  const identifier = normalizePhone(rawIdentifier) || rawIdentifier;
  // Identical body and status whether the account exists or not.
  const generic = {
    ok: true,
    message: 'If that account exists, a reset code has been created. Contact PayCST support to receive it.',
  };
  if (!isResetIdentifier(identifier)) return res.json(generic);

  const user = await findResetUser(identifier);
  if (user) {
    const code = await issueResetCode(user);
    await deliverResetCode(user, code);
  }
  res.json(generic);
}));

app.post('/api/auth/reset-password', resetIpLimiter, resetIdentifierLimiter, asyncRoute(async (req, res) => {
  const rawIdentifier = String(req.body?.identifier || '').trim().toUpperCase();
  const identifier = normalizePhone(rawIdentifier) || rawIdentifier;
  const { code, newPassword } = req.body || {};
  // One message for "no account", "no live code", "expired", "too many tries"
  // and "wrong code" so the endpoint cannot be used to probe accounts.
  const invalidCode = { error: 'That code is invalid or has expired. Please request a new one.' };

  if (!isResetIdentifier(identifier) || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(400).json(invalidCode);
  }
  // Same rule as /api/register.
  if (typeof newPassword !== 'string' || newPassword.length > 72) {
    return res.status(400).json({ error: 'Password must be 72 characters or fewer' });
  }
  if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword) || !/[@*_-]/.test(newPassword)) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters and include a letter, a number, and one of @ * _ -',
    });
  }

  const user = await findResetUser(identifier);
  if (!user) return res.status(400).json(invalidCode);

  const [[row]] = await pool.execute(
    `SELECT id, code_hash, attempts, (expires_at < NOW()) AS expired
       FROM password_resets
      WHERE user_id = ? AND used_at IS NULL
      ORDER BY id DESC
      LIMIT 1`,
    [user.id]
  );
  if (!row) return res.status(400).json(invalidCode);
  if (row.expired || row.attempts >= RESET_MAX_ATTEMPTS) {
    // Expired or already burned: make sure it can never be used later.
    await pool.execute(
      'UPDATE password_resets SET used_at = NOW() WHERE id = ? AND used_at IS NULL',
      [row.id]
    );
    return res.status(400).json(invalidCode);
  }

  const given = Buffer.from(hashResetCode(user.id, code), 'hex');
  const real = Buffer.from(row.code_hash, 'hex');
  if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) {
    // Atomic increment: the 5th wrong try kills the code in the same statement.
    await pool.execute(
      `UPDATE password_resets
          SET attempts = attempts + 1,
              used_at = IF(attempts + 1 >= ${RESET_MAX_ATTEMPTS}, NOW(), used_at)
        WHERE id = ? AND used_at IS NULL`,
      [row.id]
    );
    return res.status(400).json(invalidCode);
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    // Claim the code first: two requests racing on the same code cannot both win.
    const [claimed] = await conn.execute(
      'UPDATE password_resets SET used_at = NOW() WHERE id = ? AND used_at IS NULL',
      [row.id]
    );
    if (claimed.affectedRows !== 1) {
      await conn.rollback();
      return res.status(400).json(invalidCode);
    }
    await conn.execute(
      'UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?',
      [passwordHash, user.id]
    );
    // Same session invalidation as /api/auth/revoke-all: live tokens carry the
    // old `sv`, and enrolled fingerprint devices are dropped.
    await conn.execute('DELETE FROM device_tokens WHERE user_id = ?', [user.id]);
    // Any other unused code for this account is dead too.
    await conn.execute(
      'UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL',
      [user.id]
    );
    await conn.commit();
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }

  await refreshUserInIndex(user.id);
  res.json({ ok: true, message: 'Password updated. Log in with your new password.' });
}));

// The fingerprint phones enrolled on this account. Only metadata leaves the
// server: token_hash is the credential these rows exist to protect, so it is
// never selected and never returned. expires_at is included so the client can
// tell a live enrollment from one that has already lapsed.
app.get('/api/auth/devices', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT id, device_name, created_at, last_used_at, expires_at
       FROM device_tokens
      WHERE user_id = ?
      ORDER BY created_at DESC`,
    [req.userId]
  );
  res.json(rows);
}));

app.get('/api/me', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT id, username, wallet_id, balance, verification_level, liveness_status FROM users WHERE id = ?',
    [req.userId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  const u = rows[0];

  // A fully verified account has no upgrade badge. Otherwise the latest
  // upgrade row decides it: 'approved' is represented by
  // verification.level = 'fully_verified', so only pending/rejected map back
  // here (the requested upgradeStatus vocabulary is none | pending | rejected).
  const [[latestUpgrade]] = await pool.execute(
    'SELECT status FROM verification_upgrades WHERE user_id = ? ORDER BY id DESC LIMIT 1',
    [req.userId]
  );
  const upgradeStatus =
    u.verification_level === 'fully_verified'
      ? 'none'
      : latestUpgrade && (latestUpgrade.status === 'pending' || latestUpgrade.status === 'rejected')
        ? latestUpgrade.status
        : 'none';

  // Both spellings are returned on purpose. The app reads `walletId` (it is
  // what /api/login and the device-login route send), and the client's
  // refreshMe() replaces its whole user map with this response every 8 s, so a
  // snake_case-only payload silently empties the Wallet ID and the "My QR" code.
  // wallet_id stays for anything already reading it. Keep the two in sync.
  res.json({
    id: u.id,
    username: u.username,
    wallet_id: u.wallet_id,
    walletId: u.wallet_id,
    balance: toCentavos(u.balance),
    verification: {
      level: u.verification_level,
      livenessStatus: u.liveness_status,
      upgradeStatus,
    },
  });
}));

// Post-login upgrade from 'verified' to 'fully_verified'. This never trusts
// the client's liveness flag and never grants the level by itself: it only
// creates a pending review row. An admin must approve it.
// requireAuth, the verification limiter and the 35mb parser are mounted above
// this route (before the global 100kb parser) so rejected requests are never
// parsed. They must not be repeated here or the limiter would count twice.
app.post('/api/verification/upgrade', asyncRoute(async (req, res) => {
  const requestedMethod = req.body?.upgradeMethod;
  if (requestedMethod !== undefined && requestedMethod !== 'self' && requestedMethod !== 'guardian') {
    return res.status(400).json({ error: "upgradeMethod must be 'self' or 'guardian'" });
  }
  // Existing clients send no upgradeMethod, so the self path stays the default.
  const upgradeMethod = requestedMethod === 'guardian' ? 'guardian' : 'self';

  const {
    governmentIdPhotoFrontBase64,
    governmentIdPhotoBackBase64,
    selfiePhotoBase64,
    guardianPhotoBase64,
    guardianIdPhotoFrontBase64,
    guardianIdPhotoBackBase64,
    birthCertificatePhotoBase64,
    guardianName: rawGuardianName,
    guardianRelationship,
    consent,
  } = req.body || {};

  let guardianName = null;
  if (upgradeMethod === 'guardian') {
    if (
      !looksLikeImage(selfiePhotoBase64) ||
      !looksLikeImage(guardianPhotoBase64) ||
      !looksLikeImage(guardianIdPhotoFrontBase64) ||
      !looksLikeImage(guardianIdPhotoBackBase64) ||
      !looksLikeImage(birthCertificatePhotoBase64)
    ) {
      return res.status(400).json({ error: 'Guardian verification requires the account holder selfie, guardian live photo, front and back of the guardian ID, and a birth certificate photo as JPEG or PNG images under about 4 MB each' });
    }
    if (typeof rawGuardianName !== 'string') {
      return res.status(400).json({ error: 'guardianName must be 2-100 characters' });
    }
    guardianName = cleanText(rawGuardianName, 100);
    if (guardianName.length < 2) {
      return res.status(400).json({ error: 'guardianName must be 2-100 characters' });
    }
    if (guardianRelationship !== 'parent' && guardianRelationship !== 'legal_guardian') {
      return res.status(400).json({ error: "guardianRelationship must be 'parent' or 'legal_guardian'" });
    }
    if (consent !== true) {
      return res.status(400).json({ error: 'Guardian consent is required' });
    }
  } else {
    if (
      !looksLikeImage(governmentIdPhotoFrontBase64) ||
      !looksLikeImage(governmentIdPhotoBackBase64) ||
      !looksLikeImage(selfiePhotoBase64)
    ) {
      return res.status(400).json({ error: 'The ID and selfie photos must be JPEG or PNG images under about 4 MB each' });
    }
    if (!governmentIdPhotoFrontBase64 || !governmentIdPhotoBackBase64 || !selfiePhotoBase64) {
      return res.status(400).json({ error: 'Photos of the front and back of your ID, plus a live selfie, are required' });
    }
  }

  // Accept the same flag shapes the clients use. A missing flag is a 400 for
  // the self path rather than an implicit 'passed'; the value is shown to the
  // admin, not used to approve anything automatically. Guardian submissions
  // default to 'skipped' because their live photo is reviewed manually.
  let livenessStatus = null;
  if (req.body?.livenessStatus === 'passed' || req.body?.livenessStatus === 'skipped') {
    livenessStatus = req.body.livenessStatus;
  } else if (typeof req.body?.livenessPassed === 'boolean') {
    livenessStatus = req.body.livenessPassed ? 'passed' : 'skipped';
  } else if (typeof req.body?.livenessSkipped === 'boolean') {
    livenessStatus = req.body.livenessSkipped ? 'skipped' : 'passed';
  } else if (typeof req.body?.liveness === 'boolean') {
    livenessStatus = req.body.liveness ? 'passed' : 'skipped';
  } else if (typeof req.body?.skipped === 'boolean') {
    livenessStatus = req.body.skipped ? 'skipped' : 'passed';
  } else if (req.body?.needsManualReview === true) {
    livenessStatus = 'skipped';
  }
  if (upgradeMethod === 'self' && !livenessStatus) {
    return res.status(400).json({ error: 'livenessStatus must be passed or skipped' });
  }
  if (upgradeMethod === 'guardian' && !livenessStatus) {
    livenessStatus = 'skipped';
  }

  const [[user]] = await pool.execute(
    'SELECT id, verification_level, verification_status FROM users WHERE id = ?',
    [req.userId]
  );
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.verification_status !== 'approved') {
    return res.status(403).json({ error: 'Your account is not approved for verification upgrades' });
  }
  if (user.verification_level === 'fully_verified') {
    return res.status(409).json({ error: 'Your account is already fully verified' });
  }

  const [[pending]] = await pool.execute(
    "SELECT id FROM verification_upgrades WHERE user_id = ? AND status = 'pending' LIMIT 1",
    [req.userId]
  );
  if (pending) {
    return res.status(409).json({ error: 'You already have a verification upgrade waiting for review' });
  }

  // Face++ only produces a score for the admin. A Face++ outage must not lose
  // the request; the review is manual in that case, exactly like registration.
  // The guardian path compares the guardian ID front with the guardian live
  // photo; the birth certificate is deliberately not sent to Face++.
  let confidence = null;
  let guardianFaceConfidence = null;
  if (upgradeMethod === 'guardian') {
    try {
      const result = await compareFaces(guardianIdPhotoFrontBase64, guardianPhotoBase64);
      guardianFaceConfidence = result.confidence;
    } catch (err) {
      console.error('Face comparison failed during guardian verification upgrade:', err.message);
    }
  } else {
    try {
      const result = await compareFaces(governmentIdPhotoFrontBase64, selfiePhotoBase64);
      confidence = result.confidence;
    } catch (err) {
      console.error('Face comparison failed during verification upgrade:', err.message);
    }
  }

  let encryptedFront = null;
  let encryptedBack = null;
  let encryptedSelfie = null;
  let encryptedGuardianPhoto = null;
  let encryptedGuardianIdFront = null;
  let encryptedGuardianIdBack = null;
  let encryptedBirthCertificate = null;
  if (upgradeMethod === 'guardian') {
    encryptedSelfie = encryptPhoto(selfiePhotoBase64);
    encryptedGuardianPhoto = encryptPhoto(guardianPhotoBase64);
    encryptedGuardianIdFront = encryptPhoto(guardianIdPhotoFrontBase64);
    encryptedGuardianIdBack = encryptPhoto(guardianIdPhotoBackBase64);
    encryptedBirthCertificate = encryptPhoto(birthCertificatePhotoBase64);
  } else {
    encryptedFront = encryptPhoto(governmentIdPhotoFrontBase64);
    encryptedBack = encryptPhoto(governmentIdPhotoBackBase64);
    encryptedSelfie = encryptPhoto(selfiePhotoBase64);
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Locking the user row serializes two simultaneous submissions from the
    // same account, so both cannot pass the pending check and insert rows.
    const [[lockedUser]] = await conn.query(
      'SELECT id, verification_level, verification_status FROM users WHERE id = ? FOR UPDATE',
      [req.userId]
    );
    if (!lockedUser) {
      await conn.rollback();
      return res.status(404).json({ error: 'User not found' });
    }
    if (lockedUser.verification_status !== 'approved') {
      await conn.rollback();
      return res.status(403).json({ error: 'Your account is not approved for verification upgrades' });
    }
    if (lockedUser.verification_level === 'fully_verified') {
      await conn.rollback();
      return res.status(409).json({ error: 'Your account is already fully verified' });
    }

    const [[pendingLocked]] = await conn.query(
      "SELECT id FROM verification_upgrades WHERE user_id = ? AND status = 'pending' LIMIT 1",
      [req.userId]
    );
    if (pendingLocked) {
      await conn.rollback();
      return res.status(409).json({ error: 'You already have a verification upgrade waiting for review' });
    }

    let result;
    if (upgradeMethod === 'guardian') {
      [result] = await conn.execute(
        `INSERT INTO verification_upgrades
           (user_id, status, liveness_status, upgrade_method, guardian_name,
            guardian_relationship, selfie_photo, guardian_photo,
            guardian_id_photo, guardian_id_photo_back, birth_certificate_photo,
            guardian_face_match_confidence, consent_at)
         VALUES (?, 'pending', ?, 'guardian', ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          req.userId,
          livenessStatus,
          guardianName,
          guardianRelationship,
          encryptedSelfie,
          encryptedGuardianPhoto,
          encryptedGuardianIdFront,
          encryptedGuardianIdBack,
          encryptedBirthCertificate,
          guardianFaceConfidence,
        ]
      );
    } else {
      [result] = await conn.execute(
        `INSERT INTO verification_upgrades
           (user_id, status, liveness_status, face_match_confidence,
            government_id_photo, government_id_photo_back, selfie_photo)
         VALUES (?, 'pending', ?, ?, ?, ?, ?)`,
        [
          req.userId,
          livenessStatus,
          confidence,
          encryptedFront,
          encryptedBack,
          encryptedSelfie,
        ]
      );
    }

    await conn.commit();
    res.status(201).json({ ok: true, id: result.insertId, status: 'pending', livenessStatus });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- wallet-to-wallet (QR) payment ----------

// Resolves a Wallet ID to the name a payer is about to pay, so the name can be
// shown BEFORE the PIN prompt. Without it the app can only display the Wallet
// ID itself, which is text whoever printed the QR chose, so a fake shop QR
// gives the payer nothing to check against.
//
// A Wallet ID is PCST- plus six digits, so the whole space is about a million
// values: this route is an enumeration target and is rate limited per user for
// that reason. Unknown, inactive and suspended accounts all answer with the
// same 404, so it cannot be used to discover which IDs exist or whether one is
// suspended. Only the two columns below are ever selected, and nothing is
// logged - not the Wallet ID, not the username.
//
// The caller's own Wallet ID answers 200 with their own name: requireAuth has
// already rejected a suspended caller, and the app blocks paying yourself
// separately, so treating it as unknown would only make the client's own check
// unreachable.
const walletLookupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.userId ? `u:${req.userId}` : ipKeyGenerator(req)),
  message: { error: 'Too many lookups in a short time. Please wait a minute and try again.' },
});

app.get('/api/wallet/lookup', requireAuth, walletLookupLimiter, asyncRoute(async (req, res) => {
  const walletId = String(req.query?.walletId || '').trim().toUpperCase();
  // Same shape the app's QR scanner accepts. Rejected before the query runs, so
  // a malformed value never reaches the database.
  if (!/^PCST-\d{6}$/.test(walletId)) {
    return res.status(400).json({ error: 'Enter a Wallet ID in the form PCST-123456' });
  }

  const [[row]] = await pool.execute(
    "SELECT wallet_id, username FROM users WHERE wallet_id = ? AND status = 'active' LIMIT 1",
    [walletId]
  );
  // One message for missing, inactive and suspended alike: distinguishing them
  // would turn this into a probe for which Wallet IDs exist.
  if (!row) {
    return res.status(404).json({ error: 'No account found for that Wallet ID' });
  }

  // Deliberately only the Wallet ID echoed back and the username. No balance,
  // no phone number, no user id, no status.
  res.json({ walletId: row.wallet_id, username: row.username });
}));

app.post('/api/wallet/pay', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const { amountCentavos } = req.body || {};
  const walletId = normalizePhone(req.body?.walletId) || req.body?.walletId;
  const amt = parseCentavos(amountCentavos);
  if (!walletId || amt === null) {
    return res.status(400).json({ error: 'walletId and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    // status = 'active' so a suspended account cannot be paid, matching what
    // POST /api/requests already requires. A suspended recipient simply does not
    // resolve, so it falls into the !recipient branch below and gets the SAME 404
    // and the same message as a Wallet ID that does not exist - the payment
    // route must not be usable to find out which Wallet IDs belong to suspended
    // accounts. No other check, the lock order, or the balance maths changes.
    const [[found]] = await conn.query("SELECT id FROM users WHERE wallet_id = ? AND status = 'active'", [walletId]);
    // Begin after the id lookup: its plain read must not pin the REPEATABLE
    // READ snapshot before the FOR UPDATE locks below.
    await conn.beginTransaction();
    const lockIds = [req.userId, ...(found ? [found.id] : [])].sort((a, b) => a - b);
    await conn.query(`SELECT id FROM users WHERE id IN (${lockIds.map(() => '?').join(',')}) ORDER BY id FOR UPDATE`, lockIds);
    // username is loaded here so the receiver's row can name the sender
    // instead of printing their numeric user id. Same row, same read - no
    // extra query, and the label below is the only thing that uses it.
    const [[sender]] = await conn.query('SELECT id, username, balance, verification_level FROM users WHERE id = ?', [req.userId]);
    const [[recipient]] = found
      ? await conn.query('SELECT id, username, balance, verification_level FROM users WHERE id = ?', [found.id])
      : [[undefined]];

    if (!recipient) {
      await conn.rollback();
      return res.status(404).json({ error: 'No account found for that Wallet ID' });
    }
    if (recipient.id === sender.id) {
      await conn.rollback();
      return res.status(400).json({ error: "You can't pay your own Wallet ID" });
    }

    const senderBalance = toCentavos(sender.balance);
    if (senderBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const senderLimits = limitsForUser(sender.verification_level);
    const recipientLimits = limitsForUser(recipient.verification_level);
    const limitError = (await outgoingLimitError(conn, sender.id, amt, senderLimits)) || recipientCapError(toCentavos(recipient.balance), amt, recipientLimits);
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }

    const transferRef = crypto.randomUUID();
    const ref = newReferenceNumber();
    const [debit] = await conn.execute(
      'UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?',
      [amt, sender.id, amt]
    );
    if (debit.affectedRows !== 1) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, recipient.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, details) VALUES (?,?,?,?,?,?,?,?)',
      ['user', sender.id, `QR Payment to ${recipient.username}`, 'QR Payment', amt, 0, transferRef, referenceDetails(ref)]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, details) VALUES (?,?,?,?,?,?,?,?)',
      ['user', recipient.id, `QR Payment from ${cleanText(sender.username, 60)}`, 'QR Payment', amt, 1, transferRef, referenceDetails(ref)]
    );

    const body = { ok: true, referenceNumber: ref, recipientName: recipient.username };
    await commitWithIdempotency(conn, req, 200, body);

    // Row is committed — now safe to refresh both cached users so the
    // hash-map indexes don't serve a stale balance (item #6 fix).
    await Promise.all([
      refreshUserInIndex(sender.id),
      refreshUserInIndex(recipient.id),
    ]);

    getUndoStack(sender.id).push({ ref: transferRef, at: Date.now() }); // NEW — item: mandatory "Stack"

    // recipientName matches what POST /api/send and POST /api/requests/:id/pay
    // already return. The username was already loaded into `recipient` above, so
    // this adds nothing to the query and exposes no new column - the payer needs
    // to see who they paid.
    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- personal-account actions (restored) ----------

// Lets the app check a PIN in its confirm dialog (and show "Incorrect PIN")
// before starting a payment. The payment routes still verify the PIN themselves.
app.post('/api/pin/check', requireAuth, moneyLimiter, requirePin, (req, res) => res.json({ ok: true }));

// ---------- request money ----------
pool.execute(
  `CREATE TABLE IF NOT EXISTS payment_requests (
     id INT AUTO_INCREMENT PRIMARY KEY,
     requester_id INT NOT NULL,
     payer_id INT NOT NULL,
     amount BIGINT NOT NULL,
     note VARCHAR(100) NULL,
     status ENUM('pending','paid','declined','cancelled') NOT NULL DEFAULT 'pending',
     reference VARCHAR(20) NULL,
     created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
     responded_at TIMESTAMP NULL,
     KEY idx_pr_payer (payer_id, status),
     KEY idx_pr_requester (requester_id, created_at)
   ) ENGINE=InnoDB`
).catch((err) => console.error('Could not create payment_requests table:', err.message));

function requestView(row, mine) {
  return {
    id: row.id,
    amountCentavos: toCentavos(row.amount),
    note: row.note || '',
    status: row.status,
    createdAt: row.created_at,
    incoming: !mine,
    otherName: row.other_name,
    otherWalletId: row.other_wallet_id,
  };
}

app.post('/api/requests', requireAuth, moneyLimiter, asyncRoute(async (req, res) => {
  const rawWalletId = String(req.body?.walletId || '').trim();
  const walletId = normalizePhone(rawWalletId) || rawWalletId;
  const amt = parseCentavos(req.body?.amountCentavos);
  // cleanText, like the split route below: it strips <, > and control
  // characters, so a note can never carry HTML into a client.
  const note = cleanText(req.body?.note, 100);
  if (!walletId || amt === null) {
    return res.status(400).json({ error: 'Enter who to ask and an amount' });
  }
  const limits = limitsForUser(req.verificationLevel);
  if (amt > limits.perTransactionCentavos) {
    return res.status(400).json({ error: `You can request at most ${pesoText(limits.perTransactionCentavos)} at a time` });
  }
  const [[payer]] = await pool.query("SELECT id, username, status FROM users WHERE wallet_id = ? OR phone_number = ?", [walletId, walletId]);
  if (!payer || payer.status !== 'active') return res.status(404).json({ error: 'No account found for that number' });
  if (payer.id === req.userId) return res.status(400).json({ error: "You can't request money from yourself" });
  const [[open]] = await pool.query(
    "SELECT COUNT(*) AS n FROM payment_requests WHERE requester_id = ? AND status = 'pending'",
    [req.userId]
  );
  if (open.n >= 10) return res.status(400).json({ error: 'You have 10 unpaid requests. Wait for replies or cancel some first.' });

  const [result] = await pool.execute(
    'INSERT INTO payment_requests (requester_id, payer_id, amount, note) VALUES (?,?,?,?)',
    [req.userId, payer.id, amt, note || null]
  );
  res.json({ ok: true, id: result.insertId, payerName: payer.username });
}));

app.get('/api/requests', requireAuth, asyncRoute(async (req, res) => {
  const [incoming] = await pool.query(
    `SELECT r.id, r.amount, r.note, r.status, r.created_at, u.username AS other_name, u.wallet_id AS other_wallet_id
       FROM payment_requests r JOIN users u ON u.id = r.requester_id
      WHERE r.payer_id = ? ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT 30`,
    [req.userId]
  );
  const [outgoing] = await pool.query(
    `SELECT r.id, r.amount, r.note, r.status, r.created_at, u.username AS other_name, u.wallet_id AS other_wallet_id
       FROM payment_requests r JOIN users u ON u.id = r.payer_id
      WHERE r.requester_id = ? ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT 30`,
    [req.userId]
  );
  res.json({
    incoming: incoming.map((r) => requestView(r, false)),
    outgoing: outgoing.map((r) => requestView(r, true)),
  });
}));

app.post('/api/requests/:id/pay', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[request]] = await conn.query('SELECT * FROM payment_requests WHERE id = ? AND payer_id = ? FOR UPDATE', [Number(req.params.id), req.userId]);
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Payment request not found' });
    }
    if (request.status !== 'pending') {
      await conn.rollback();
      return res.status(400).json({ error: `This request was already ${request.status}` });
    }
    const amt = toCentavos(request.amount);
    const lockIds = [request.payer_id, request.requester_id].sort((a, b) => a - b);
    await conn.query(`SELECT id FROM users WHERE id IN (?, ?) ORDER BY id FOR UPDATE`, lockIds);
    const [[payer]] = await conn.query('SELECT id, username, balance, verification_level FROM users WHERE id = ?', [request.payer_id]);
    const [[requester]] = await conn.query('SELECT id, username, balance, verification_level FROM users WHERE id = ?', [request.requester_id]);

    if (toCentavos(payer.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    const payerLimits = limitsForUser(payer.verification_level);
    const requesterLimits = limitsForUser(requester.verification_level);
    const limitError = (await outgoingLimitError(conn, payer.id, amt, payerLimits)) || recipientCapError(toCentavos(requester.balance), amt, requesterLimits);
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }

    const transferRef = crypto.randomUUID();
    const ref = newReferenceNumber();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, payer.id]);
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, requester.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, details) VALUES (?,?,?,?,?,?,?,?)',
      ['user', payer.id, `Paid request from ${requester.username}`, 'Send Money', amt, 0, transferRef, referenceDetails(ref)]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, details) VALUES (?,?,?,?,?,?,?,?)',
      ['user', requester.id, `Request paid by ${payer.username}`, 'Send Money', amt, 1, transferRef, referenceDetails(ref)]
    );
    await conn.execute("UPDATE payment_requests SET status = 'paid', reference = ?, responded_at = NOW() WHERE id = ?", [ref, request.id]);
    const body = { ok: true, referenceNumber: ref, recipientName: requester.username };
    await commitWithIdempotency(conn, req, 200, body);
    await Promise.all([refreshUserInIndex(payer.id), refreshUserInIndex(requester.id)]);
    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

async function closeRequest(req, res, who, newStatus) {
  const column = who === 'payer' ? 'payer_id' : 'requester_id';
  const [result] = await pool.execute(
    `UPDATE payment_requests SET status = ?, responded_at = NOW() WHERE id = ? AND ${column} = ? AND status = 'pending'`,
    [newStatus, Number(req.params.id), req.userId]
  );
  if (result.affectedRows === 0) return res.status(404).json({ error: 'That request is no longer pending' });
  res.json({ ok: true });
}
app.post('/api/requests/:id/decline', requireAuth, asyncRoute((req, res) => closeRequest(req, res, 'payer', 'declined')));
app.post('/api/requests/:id/cancel', requireAuth, asyncRoute((req, res) => closeRequest(req, res, 'requester', 'cancelled')));

// ---------- split a bill ----------
//
// One action, N independent payment_requests rows sharing this requester_id.
// Deliberately no parent table and no group column: the pay, decline, cancel
// and listing paths above already handle a single request correctly, and
// keeping the shares independent is what makes them so. It also means a payer
// receives exactly one row and still cannot learn who else is in the split -
// nothing here changes requestView or GET /api/requests.
//
// Moves no money, so there is no requirePin: a request cannot spend anything.
//
// idempotent IS applied, unlike POST /api/requests above. Each row is
// independently payable, so a retry after a dropped connection would leave the
// creator able to collect the same share twice. `requireAuth` sets
// req.userId, which is what idempotency_keys.user_id holds, so this needs no
// schema change and no change to the middleware.
const MAX_SPLIT_PARTICIPANTS = 10;
// Also what stops a share rounding down to zero: with total >= n * 100 the
// floor can never be below 100.
const MIN_SPLIT_SHARE_CENTAVOS = 100;

app.post('/api/requests/split', requireAuth, moneyLimiter, idempotent, asyncRoute(async (req, res) => {
  // ---- validation, all of it before a connection is taken ----
  const total = parseCentavos(req.body?.totalCentavos);
  if (total === null) {
    return res.status(400).json({ error: 'A positive total (integer centavos) is required' });
  }
  const limits = limitsForUser(req.verificationLevel);
  if (total > limits.perTransactionCentavos) {
    return res.status(400).json({ error: `You can split at most ${pesoText(limits.perTransactionCentavos)} at a time` });
  }

  const raw = req.body?.participants;
  if (!Array.isArray(raw) || raw.length === 0) {
    return res.status(400).json({ error: 'Add at least one person to split with' });
  }
  if (raw.length > MAX_SPLIT_PARTICIPANTS) {
    return res.status(400).json({ error: `A split can have at most ${MAX_SPLIT_PARTICIPANTS} people` });
  }
  const entries = raw.map((e) => {
    const entry = typeof e === 'string' ? e.trim() : '';
    return normalizePhone(entry) || entry;
  });
  if (entries.some((e) => !e)) {
    return res.status(400).json({ error: 'Every person in the split needs a Wallet ID or phone number' });
  }
  // cleanText, the same as the single-request route above: it strips <, > and
  // control characters so a note can never carry HTML into a client. A split
  // fans one note out to several people, so this matters twice as much here.
  const note = cleanText(req.body?.note, 100) || null;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // One round trip: the same wallet_id OR phone_number resolution the
    // single-request route does, for every entry at once. status = 'active'
    // here means a suspended account simply does not come back, which is why
    // the not-found message below deliberately does not say which it was.
    const [found] = await conn.query(
      `SELECT id, username, wallet_id, phone_number FROM users
        WHERE status = 'active'
          AND (wallet_id IN (${entries.map(() => '?').join(',')})
               OR phone_number IN (${entries.map(() => '?').join(',')}))`,
      [...entries, ...entries]
    );
    // Both of an account's identifiers point at the same row, so either entry
    // finds it. A plain Map - this is a lookup table for one request, not a
    // system of record, so it deliberately does not go in the AVL tree.
    const byKey = new Map();
    for (const row of found) {
      if (row.wallet_id) byKey.set(String(row.wallet_id), row);
      if (row.phone_number) byKey.set(String(row.phone_number), row);
    }

    // Resolve every entry before writing anything. Silently dropping someone
    // who does not resolve would change n and therefore change everybody's
    // share, so the whole split fails and says which entry was the problem.
    const picked = [];
    const seen = new Set();
    let duplicatesIgnored = 0;
    for (const entry of entries) {
      const user = byKey.get(entry);
      if (!user) {
        await conn.rollback();
        return res.status(400).json({ error: `No active account found for "${entry}"` });
      }
      if (user.id === req.userId) {
        await conn.rollback();
        return res.status(400).json({ error: "You can't request money from yourself" });
      }
      // Two different strings can resolve to one account (a phone number and a
      // wallet ID for the same person), so dedupe on the resolved id.
      if (seen.has(user.id)) {
        duplicatesIgnored++;
        continue;
      }
      seen.add(user.id);
      picked.push(user);
    }

    const n = picked.length;
    if (total < n * MIN_SPLIT_SHARE_CENTAVOS) {
      await conn.rollback();
      return res.status(400).json({ error: `Each person must owe at least ${pesoText(MIN_SPLIT_SHARE_CENTAVOS)} - raise the total` });
    }

    // The same 10-open-request ceiling POST /api/requests enforces, kept as a
    // literal so that route is untouched; change both together if it moves.
    const [[open]] = await conn.query(
      "SELECT COUNT(*) AS n FROM payment_requests WHERE requester_id = ? AND status = 'pending'",
      [req.userId]
    );
    const openCount = Number(open.n);
    if (openCount + n > 10) {
      await conn.rollback();
      return res.status(400).json({
        error: `You have ${openCount} unpaid request${openCount === 1 ? '' : 's'}; a split of ${n} would pass the limit of 10`,
      });
    }

    // Integer centavos only, never a float. Sorted by user id so the person who
    // ends up paying the extra centavo is the same on a retry and does not
    // depend on the order the client happened to send.
    picked.sort((a, b) => a.id - b.id);
    const base = Math.floor(total / n);
    const extra = total % n;
    const shares = picked.map((user, i) => ({
      user,
      requestId: 0,
      amountCentavos: base + (i < extra ? 1 : 0),
    }));

    // Defence in depth: if this ever stopped summing to the total the creator
    // would be short by a centavo nobody could see. Nothing is written either
    // way, and this surfaces as a 500 because it would mean the arithmetic is
    // broken rather than that the caller sent something wrong.
    const sum = shares.reduce((acc, s) => acc + s.amountCentavos, 0);
    if (sum !== total) {
      await conn.rollback();
      throw new Error('Split shares did not sum to the requested total');
    }

    // All N inserts on this one connection: either every share exists or none
    // of them does. A partial split would leave the creator asking some people
    // for money and not others, with no way to tell which.
    for (const share of shares) {
      const [result] = await conn.execute(
        'INSERT INTO payment_requests (requester_id, payer_id, amount, note) VALUES (?,?,?,?)',
        [req.userId, share.user.id, share.amountCentavos, note]
      );
      share.requestId = result.insertId;
    }

    const body = {
      ok: true,
      totalCentavos: total,
      duplicatesIgnored,
      shares: shares.map((s) => ({
        requestId: s.requestId,
        username: s.user.username,
        walletId: s.user.wallet_id,
        amountCentavos: s.amountCentavos,
      })),
    };
    await commitWithIdempotency(conn, req, 200, body);

    // The creator chose these people, so their names and wallet IDs come back
    // to them. This response is never returned to a payer.
    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- account limits (shown in the app) ----------
app.get('/api/limits', requireAuth, asyncRoute(async (req, res) => {
  const level = req.verificationLevel === 'fully_verified' ? 'fully_verified' : 'verified';
  const limits = limitsForUser(level);
  const used = await spentInLast24h(pool, req.userId);
  res.json({
    perTransactionCentavos: limits.perTransactionCentavos,
    dailyCentavos: limits.dailyCentavos,
    maxBalanceCentavos: limits.maxBalanceCentavos,
    usedCentavos: used,
    remainingCentavos: Math.max(0, limits.dailyCentavos - used),
    level,
  });
}));

// ---------- cash in (simulated) ----------
// Works like a real wallet: you ask to cash in, get a reference number and
// instructions, and the wallet is credited once the payment arrives. Nothing here
// touches real money, so the "payment arrives" step is a demo button that only
// works while DEMO_MODE is on. Demo mode is OFF unless DEMO_MODE is exactly
// 'true', so a fresh checkout gets admin-only confirmation by default.
const DEMO_MODE = process.env.DEMO_MODE === 'true';
const CASH_IN_CHANNELS = { bank: 'Online Banking', otc: 'Convenience Store', qrph: 'QR Ph' };
const CASH_IN_MIN = 10000; // PHP 100
const CASH_IN_TTL_HOURS = 24;

pool.execute(
  `CREATE TABLE IF NOT EXISTS cash_ins (
     id INT AUTO_INCREMENT PRIMARY KEY,
     user_id INT NOT NULL,
     channel VARCHAR(20) NOT NULL,
     amount BIGINT NOT NULL,
     reference VARCHAR(20) NOT NULL,
     status ENUM('pending','completed','expired','rejected') NOT NULL DEFAULT 'pending',
     created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
     expires_at DATETIME NOT NULL,
     completed_at TIMESTAMP NULL,
     KEY idx_cash_ins_user (user_id, created_at),
     UNIQUE KEY uniq_cash_in_ref (reference)
   ) ENGINE=InnoDB`
).catch((err) => console.error('Could not create cash_ins table:', err.message));

function cashInView(row) {
  const expired = row.status === 'pending' && new Date(row.expires_at).getTime() < Date.now();
  return {
    id: row.id,
    channel: row.channel,
    channelName: CASH_IN_CHANNELS[row.channel] || row.channel,
    amountCentavos: toCentavos(row.amount),
    referenceNumber: row.reference,
    status: expired ? 'expired' : row.status,
    expiresAt: row.expires_at,
    demoMode: DEMO_MODE,
  };
}

app.post('/api/cashin', requireAuth, moneyLimiter, asyncRoute(async (req, res) => {
  const channel = String(req.body?.channel || '');
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!CASH_IN_CHANNELS[channel]) return res.status(400).json({ error: 'Choose how you want to cash in' });
  if (amt === null || amt < CASH_IN_MIN) return res.status(400).json({ error: `The minimum cash in is ${pesoText(CASH_IN_MIN)}` });
  const limits = limitsForUser(req.verificationLevel);
  if (amt > limits.perTransactionCentavos) {
    return res.status(400).json({ error: `The most you can cash in at once is ${pesoText(limits.perTransactionCentavos)}` });
  }
  const [[open]] = await pool.query(
    "SELECT COUNT(*) AS n FROM cash_ins WHERE user_id = ? AND status = 'pending' AND expires_at > NOW()",
    [req.userId]
  );
  if (open.n >= 3) return res.status(400).json({ error: 'You already have 3 unpaid cash-in requests. Pay or wait for one to expire.' });

  const reference = newReferenceNumber();
  const [result] = await pool.execute(
    `INSERT INTO cash_ins (user_id, channel, amount, reference, expires_at)
     VALUES (?, ?, ?, ?, NOW() + INTERVAL ${CASH_IN_TTL_HOURS} HOUR)`,
    [req.userId, channel, amt, reference]
  );
  const [[row]] = await pool.query('SELECT * FROM cash_ins WHERE id = ?', [result.insertId]);
  res.json({ ok: true, cashIn: cashInView(row) });
}));

app.get('/api/cashin/:id', requireAuth, asyncRoute(async (req, res) => {
  const [[row]] = await pool.query('SELECT * FROM cash_ins WHERE id = ? AND user_id = ?', [Number(req.params.id), req.userId]);
  if (!row) return res.status(404).json({ error: 'Cash-in request not found' });
  res.json({ ok: true, cashIn: cashInView(row) });
}));

// Demo only: pretend the payment arrived at the bank / store.
app.post('/api/cashin/:id/simulate-paid', requireAuth, moneyLimiter, asyncRoute(async (req, res) => {
  if (!DEMO_MODE) return res.status(403).json({ error: 'Cash in is confirmed by an admin once your payment arrives.' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[row]] = await conn.query('SELECT * FROM cash_ins WHERE id = ? AND user_id = ? FOR UPDATE', [Number(req.params.id), req.userId]);
    if (!row) {
      await conn.rollback();
      return res.status(404).json({ error: 'Cash-in request not found' });
    }
    if (row.status === 'completed') {
      await conn.rollback();
      return res.status(400).json({ error: 'This cash in was already completed' });
    }
    if (cashInView(row).status === 'expired') {
      await conn.rollback();
      return res.status(400).json({ error: 'This cash-in request has expired. Please start a new one.' });
    }
    const [[user]] = await conn.query('SELECT id, balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const amt = toCentavos(row.amount);
    const limits = limitsForUser(user.verification_level);
    if (toCentavos(user.balance) + amt > limits.maxBalanceCentavos) {
      await conn.rollback();
      return res.status(400).json({ error: `Your wallet can hold at most ${pesoText(limits.maxBalanceCentavos)}.` });
    }
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
      ['user', req.userId, `Cash In via ${CASH_IN_CHANNELS[row.channel] || row.channel}`, 'Cash In', amt, 1, referenceDetails(row.reference)]
    );
    await conn.execute("UPDATE cash_ins SET status = 'completed', completed_at = NOW() WHERE id = ?", [row.id]);
    await conn.commit();
    await refreshUserInIndex(req.userId);
    res.json({ ok: true, referenceNumber: row.reference });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// Live "now showing" movies for the Store (see movies.js).
const moviesLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many requests. Please slow down.' },
});

app.get('/api/movies/now-showing', requireAuth, moviesLimiter, asyncRoute(async (req, res) => {
  try {
    res.json(await getNowShowing());
  } catch (err) {
    console.error('Movies feed failed:', err.message);
    res.status(err.status || 502).json({ error: 'Live movies are not available right now' });
  }
}));

app.get('/api/notifications', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT id, label AS title, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'user' AND account_id = ?
     ORDER BY created_at DESC
     LIMIT 20`,
    [req.userId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

// ---------- alerts: what is waiting for this user ----------
//
// A small read-only counter set for the client to poll. It returns COUNTS
// ONLY - never a name, an amount, an id or a label - and every query is
// scoped to the caller, so the response can never carry another person's
// data.
//
// The client must not use its own clock. It stores the serverTime it is given
// and sends it back as ?since=<serverTime>, and the counts are computed
// against that value here, in the database.

const alertsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.userId ? `u:${req.userId}` : ipKeyGenerator(req)),
  message: { error: 'Too many alert checks in a short time. Please wait a minute and try again.' },
});

// A well-formed ISO-8601 instant with a timezone. Anything else is ignored
// rather than rejected, so a stale or hand-edited value can never turn into
// an error page - and the value only ever reaches MySQL as a bound
// parameter, never as SQL text.
const ISO_INSTANT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/;

// How far back a cursor is honoured. A month of history is plenty for a
// badge, and it keeps one stale cursor from scanning the whole table.
const ALERTS_MAX_LOOKBACK_MS = 30 * 24 * 60 * 60 * 1000;

// Reads the ?since= cursor. Returns null when there is no usable baseline,
// which the route reads as "no count yet", never as a guess.
function parseSinceCursor(raw) {
  if (typeof raw !== 'string' || !ISO_INSTANT_RE.test(raw)) return null;
  const ms = Date.parse(raw);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms);
}

// Clamps the cursor against the server's own clock: one from the future is
// treated as now, and one older than 30 days is treated as 30 days ago.
function clampSinceCursor(since, serverNowMs) {
  if (since === null) return null;
  if (since.getTime() > serverNowMs) return new Date(serverNowMs);
  const oldest = serverNowMs - ALERTS_MAX_LOOKBACK_MS;
  if (since.getTime() < oldest) return new Date(oldest);
  return since;
}

// COUNT(*) comes back from MySQL as a BIGINT, which the driver hands over as
// a string. It is normalised to a plain integer before it leaves the server.
function countValue(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

app.get('/api/alerts', requireAuth, alertsLimiter, asyncRoute(async (req, res) => {
  // One query for the counts that are always needed. Every subquery is a
  // COUNT over rows the caller owns, so nothing about anyone else can come
  // back in the response.
  //   payment_requests - idx_pr_payer (payer_id, status) covers both parts
  //   group_withdraw_requests - idx_gwr_group (group_id, status), joined
  //     from group_members through idx_member_user (user_id); the NOT EXISTS
  //     probe hits uniq_member_request (request_id, member_id)
  // The group rules mirror the vote route exactly: the request must still be
  // pending, the user must be a member, the user must not be the requester
  // (they cannot vote on their own request), and the user must not have
  // voted already.
  const [[counts]] = await pool.execute(
    `SELECT NOW() AS serverTime,
            (SELECT COUNT(*) FROM payment_requests
              WHERE payer_id = ? AND status = 'pending') AS pendingIncomingRequests,
            (SELECT COUNT(*)
               FROM group_withdraw_requests r
               JOIN group_members m ON m.group_id = r.group_id AND m.user_id = ?
              WHERE r.status = 'pending'
                AND r.requester_id <> ?
                AND NOT EXISTS (
                  SELECT 1 FROM group_withdraw_approvals a
                   WHERE a.request_id = r.id AND a.member_id = ?
                )) AS pendingGroupVotes`,
    [req.userId, req.userId, req.userId, req.userId]
  );

  // The server's own clock, in UTC, so the client can hand it back instead
  // of trusting the clock on the phone.
  const serverNowMs = new Date(counts.serverTime).getTime();
  const serverTime = new Date(serverNowMs).toISOString();

  // Money that arrived from another person or a group since the client's last
  // call. The types are the ones where the money came from somebody else:
  //   Send Money       - a received send, or a request the other person paid
  //   QR Payment       - a QR payment received
  //   Group Withdrawal - the group paid the withdrawal out to the user
  // The user's own credits are left out on purpose: a cash in, a loan
  // disbursement and a savings withdrawal are things the user did, not
  // things that arrived. The credit an undo writes back is left out too,
  // through reversed_transfer_ref IS NULL - a reversal carries the type of
  // the row it reverses, so a reversed send would otherwise look like a
  // received one.
  const since = clampSinceCursor(parseSinceCursor(req.query.since), serverNowMs);
  let newMoneyIn = 0;
  if (since) {
    const [[money]] = await pool.execute(
      `SELECT COUNT(*) AS n
         FROM transactions
        WHERE account_type = 'user'
          AND account_id = ?
          AND is_credit = 1
          AND type IN ('Send Money', 'QR Payment', 'Group Withdrawal')
          AND reversed_transfer_ref IS NULL
          AND created_at > ?`,
      [req.userId, since]
    );
    newMoneyIn = countValue(money.n);
  }

  res.json({
    pendingIncomingRequests: countValue(counts.pendingIncomingRequests),
    pendingGroupVotes: countValue(counts.pendingGroupVotes),
    newMoneyIn,
    serverTime,
  });
}));

app.post('/api/send', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const rawRecipient = req.body?.recipient?.toString().trim();
  const recipient = normalizePhone(rawRecipient) || rawRecipient;
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!recipient || amt === null) {
    return res.status(400).json({ error: 'recipient and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    const [[found]] = await conn.query('SELECT id FROM users WHERE wallet_id = ?', [recipient]);
    // Begin after the id lookup: its plain read must not pin the REPEATABLE
    // READ snapshot before the FOR UPDATE locks below.
    await conn.beginTransaction();
    const lockIds = [req.userId, ...(found ? [found.id] : [])].sort((a, b) => a - b);
    await conn.query(`SELECT id FROM users WHERE id IN (${lockIds.map(() => '?').join(',')}) ORDER BY id FOR UPDATE`, lockIds);
    // username is loaded here so the receiver's row can name the sender
    // instead of printing their numeric user id. Same row, same read - no
    // extra query, and the label below is the only thing that uses it.
    const [[sender]] = await conn.query('SELECT id, username, balance, verification_level FROM users WHERE id = ?', [req.userId]);
    const [[recipientUser]] = found
      ? await conn.query('SELECT id, username, balance, verification_level FROM users WHERE id = ?', [found.id])
      : [[undefined]];

    // ---- unchanged ----
    if (!recipientUser) {
      await conn.rollback();
      return res.status(404).json({ error: 'No account found for that Wallet ID' });
    }
    if (recipientUser.id === sender.id) {
      await conn.rollback();
      return res.status(400).json({ error: "You can't send money to your own Wallet ID" });
    }

    const senderBalance = toCentavos(sender.balance);
    if (senderBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    // ---- end unchanged ----

    const senderLimits = limitsForUser(sender.verification_level);
    const recipientLimits = limitsForUser(recipientUser.verification_level);
    const limitError = (await outgoingLimitError(conn, sender.id, amt, senderLimits)) || recipientCapError(toCentavos(recipientUser.balance), amt, recipientLimits);
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }

    const transferRef = crypto.randomUUID();
    const ref = newReferenceNumber();
    const [debit] = await conn.execute(
      'UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?',
      [amt, sender.id, amt]
    );
    if (debit.affectedRows !== 1) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, recipientUser.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, details) VALUES (?,?,?,?,?,?,?,?)',
      ['user', sender.id, `Sent to ${recipientUser.username}`, 'Send Money', amt, 0, transferRef, referenceDetails(ref)]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, details) VALUES (?,?,?,?,?,?,?,?)',
      ['user', recipientUser.id, `Received from ${cleanText(sender.username, 60)}`, 'Send Money', amt, 1, transferRef, referenceDetails(ref)]
    );

    const body = { ok: true, referenceNumber: ref, recipientName: recipientUser.username };
    await commitWithIdempotency(conn, req, 200, body);

    // <-- NEW: only line added to this whole route
    await Promise.all([
      refreshUserInIndex(sender.id),
      refreshUserInIndex(recipientUser.id),
    ]);

    getUndoStack(sender.id).push({ ref: transferRef, at: Date.now() }); // NEW — item: mandatory "Stack"

    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/load', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const { number, network } = req.body || {};
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!number || !network || amt === null) {
    return res.status(400).json({ error: 'number, network, and a positive amount (integer centavos) are required' });
  }
  if (!/^09\d{9}$/.test(String(number))) {
    return res.status(400).json({ error: 'Enter a valid 11-digit mobile number starting with 09' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[user]] = await conn.query('SELECT id, balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const userBalance = toCentavos(user.balance);
    if (userBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const limitError = await outgoingLimitError(conn, req.userId, amt, limitsForUser(user.verification_level));
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }
    const ref = newReferenceNumber();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
      ['user', req.userId, `Mobile Load to ${number}`, 'Load', amt, 0, referenceDetails(ref)]
    );

    const body = { ok: true, referenceNumber: ref };
    await commitWithIdempotency(conn, req, 200, body);

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/bills/pay', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const biller = req.body?.biller?.toString().trim();
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!biller || amt === null) {
    return res.status(400).json({ error: 'biller and a positive amount (integer centavos) are required' });
  }
  if (biller.length > 185) {
    return res.status(400).json({ error: 'Biller name is too long' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[user]] = await conn.query('SELECT id, balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const userBalance = toCentavos(user.balance);
    if (userBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const limitError = await outgoingLimitError(conn, req.userId, amt, limitsForUser(user.verification_level));
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }
    const ref = newReferenceNumber();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
      ['user', req.userId, `Bill Pay to ${biller}`, 'Bill Payment', amt, 0, referenceDetails(ref)]
    );

    const body = { ok: true, referenceNumber: ref };
    await commitWithIdempotency(conn, req, 200, body);

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/transactions', requireAuth, asyncRoute(async (req, res) => {
  const [[me]] = await pool.query('SELECT username FROM users WHERE id = ?', [req.userId]);
  const [groupRows] = await pool.execute(
    'SELECT g.id, g.name FROM group_members gm JOIN `groups` g ON g.id = gm.group_id WHERE gm.user_id = ?',
    [req.userId]
  );
  const groupNameById = Object.fromEntries(groupRows.map((g) => [g.id, g.name]));
  const groupIds = groupRows.map((g) => g.id);

  let rows;
  if (groupIds.length > 0) {
    const placeholders = groupIds.map(() => '?').join(',');
    const [result] = await pool.query(
      `SELECT id, account_type, account_id, label, type, amount, is_credit AS isCredit, created_at AS createdAt, details
       FROM transactions
       WHERE (account_type = 'user' AND account_id = ?)
          OR (account_type = 'group' AND account_id IN (${placeholders}))`,
      [req.userId, ...groupIds]
    );
    rows = result;
  } else {
    const [result] = await pool.execute(
      `SELECT id, account_type, account_id, label, type, amount, is_credit AS isCredit, created_at AS createdAt, details
       FROM transactions WHERE account_type = 'user' AND account_id = ?`,
      [req.userId]
    );
    rows = result;
  }

  const normalized = rows.map((row) => ({
    ...row,
    amount: toCentavos(row.amount),
    accountName: row.account_type === 'user' ? me.username : groupNameById[row.account_id] || 'Group',
  }));

  const sorted = mergeSort(normalized, comparators.dateDesc);

  res.json(sorted);
}));

// Money in / money out for one period, for the Home spending summary.
// Direction is never re-derived from `type` here. Every insert above already
// wrote is_credit on the row, so savings deposits and withdrawals, loan
// disbursements and repayments, and cash-ins are classified at write time.
// That also means a reversed transfer needs no special case: undo inserts a
// compensating row with the opposite direction (see the reversal core), so an
// undone send contributes one debit and one equal credit and nets to zero.
// Group rows are excluded because the client ledger merges them into the same
// list; without account_type = 'user' a group contribution would be counted as
// this user's money in.
const SUMMARY_PERIOD_START_SQL = `CASE WHEN ? = 'week'
       THEN DATE_SUB(DATE(NOW()), INTERVAL WEEKDAY(NOW()) DAY)
       ELSE DATE_SUB(DATE(NOW()), INTERVAL DAYOFMONTH(NOW()) - 1 DAY)
     END`;

app.get('/api/transactions/summary', requireAuth, asyncRoute(async (req, res) => {
  // Unknown or missing values fall back to 'month' rather than 400, matching how
  // the other routes handle a small whitelist query param (sortBy, direction).
  const period = req.query.period === 'week' ? 'week' : 'month';

  // Boundaries come from MySQL's own clock, the same one that stamps created_at
  // and the one spentInLast24h() trusts, so a row can never land outside the
  // window this reports. Written once and wrapped in MIN/MAX because this is an
  // aggregate query with no GROUP BY, and selecting the bare columns instead
  // would be rejected under MySQL's default ONLY_FULL_GROUP_BY. The join runs
  // from that one-row subquery so a user with no matching transactions still
  // gets a row back with real boundaries instead of zeros with null dates.
  //
  // spendingOut is the same period and the same account_type = 'user' scope as
  // moneyOut, narrowed to the server's own definition of spending. It exists
  // because moneyOut also counts Savings Deposit and group contributions, so it
  // is the wrong figure to compare a budget against.
  //
  // Placeholder order is TEXTUAL: the SPENDING_TYPES list sits in the SELECT
  // list, so it binds before the period in the FROM subquery and the user id in
  // the JOIN condition. Read the array below against the SQL text, not the
  // other way round.
  const [[row]] = await pool.execute(
    `SELECT MIN(b.startAt) AS periodStart,
            MAX(b.endAt) AS periodEnd,
            COALESCE(SUM(CASE WHEN t.is_credit = 1 THEN t.amount ELSE 0 END), 0) AS moneyIn,
            COALESCE(SUM(CASE WHEN t.is_credit = 0 THEN t.amount ELSE 0 END), 0) AS moneyOut,
            COALESCE(SUM(CASE WHEN t.is_credit = 1 THEN 1 ELSE 0 END), 0) AS moneyInCount,
            COALESCE(SUM(CASE WHEN t.is_credit = 0 THEN 1 ELSE 0 END), 0) AS moneyOutCount,
            COALESCE(SUM(CASE WHEN t.is_credit = 0 AND t.type IN (${SPENDING_TYPES.map(() => '?').join(',')})
                              THEN t.amount ELSE 0 END), 0) AS spendingOut
     FROM (SELECT ${SUMMARY_PERIOD_START_SQL} AS startAt, NOW() AS endAt) b
     LEFT JOIN transactions t
       ON t.account_type = 'user' AND t.account_id = ?
        AND t.created_at >= b.startAt AND t.created_at <= b.endAt`,
    [...SPENDING_TYPES, period, req.userId]
  );

  // The budget is read with its own single-row lookup rather than folded into
  // the aggregate. It is not a function of the period and does not come from
  // transactions, so putting it beside the SUM() columns would either be
  // rejected under ONLY_FULL_GROUP_BY or force a MIN()/MAX() wrapper that makes
  // a plain column look like an aggregate. One primary-key lookup answers it,
  // scoped to the caller - no user id is ever taken from the request.
  const [[budgetRow]] = await pool.execute(
    'SELECT monthly_budget_centavos FROM users WHERE id = ?',
    [req.userId]
  );
  const budgetCentavos = budgetRow?.monthly_budget_centavos ?? null;

  // SUM() over a BIGINT column comes back as DECIMAL, which mysql2 hands over
  // as a string, so every figure goes through toCentavos: it parses, rejects
  // anything outside the safe-integer range, and turns a NULL into 0.
  //
  // The budget is the one field that must NOT go through that fallback: NULL
  // means "no budget set" and is a different answer from 0, so a null column
  // (or a missing row) is passed through as null and never collapses to zero.
  res.json({
    period,
    periodStart: row.periodStart,
    periodEnd: row.periodEnd,
    moneyInCentavos: toCentavos(row.moneyIn),
    moneyOutCentavos: toCentavos(row.moneyOut),
    moneyInCount: toCentavos(row.moneyInCount),
    moneyOutCount: toCentavos(row.moneyOutCount),
    spendingOutCentavos: toCentavos(row.spendingOut),
    monthlyBudgetCentavos: budgetCentavos === null ? null : toCentavos(budgetCentavos),
  });
}));

// ---------- monthly budget (advisory, never enforced) ----------
//
// The user sets a spending target for themselves and sees their progress
// against it. NOTHING HERE ENFORCES IT: no payment route reads this column, so
// a user is never blocked from spending and a modified client can ignore it
// completely. It is a reminder in the app, not a limit on the wallet.
//
// requirePin and idempotent are deliberately absent, unlike every money route.
// A PIN exists so a stolen login token alone cannot drain a wallet, and this
// writes no money - the worst a stolen token can do here is change an advisory
// number the user set for themselves. The outgoingLimitError() daily cap is a
// separate server-enforced limit and is untouched by this.
//
// Scoped to req.userId on every statement. No user id is accepted from the
// request, so one account can never set or read another account's budget.
app.post('/api/budget', requireAuth, asyncRoute(async (req, res) => {
  const raw = req.body?.monthlyBudgetCentavos;

  // Only an EXPLICIT null clears the budget. A missing key is a client bug, not
  // an instruction to delete the user's setting, so it is rejected rather than
  // silently treated as a clear.
  if (raw === undefined) {
    return res.status(400).json({ error: 'monthlyBudgetCentavos is required; send null to clear the budget' });
  }

  const clearing = raw === null;
  // parseCentavos is the single validator: it rejects a non-number, a
  // fractional amount, zero, a negative amount, and anything above
  // MAX_CENTAVOS, so those all become a clean 400 with nothing written.
  const centavos = clearing ? null : parseCentavos(raw);
  if (!clearing && centavos === null) {
    return res.status(400).json({ error: 'monthlyBudgetCentavos must be a positive whole number of centavos, or null to clear it' });
  }

  await pool.execute('UPDATE users SET monthly_budget_centavos = ? WHERE id = ?', [centavos, req.userId]);

  // walletAvl, accountList and usersByUsername/usersByWalletId all cache whole
  // user rows from SELECT *, so they are refreshed in the same request as the
  // write (item #6 fix). Without this the indexes serve the old budget until
  // the next boot.
  await refreshUserInIndex(req.userId);

  res.json({ ok: true, monthlyBudgetCentavos: centavos });
}));

app.get('/api/groups/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT g.id, g.name, g.balance,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS memberCount
     FROM \`groups\` g
     JOIN group_members gm ON gm.group_id = g.id
     WHERE gm.user_id = ?`,
    [req.userId]
  );
  res.json(rows.map((g) => ({ ...g, balance: toCentavos(g.balance) })));
}));

app.get('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT g.id, g.name, g.balance,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS memberCount
     FROM \`groups\` g
     ORDER BY g.name ASC`
  );
  res.json(rows.map((g) => ({ ...g, balance: toCentavos(g.balance) })));
}));

// Shared by every /api/groups/:id... route below: confirms req.userId is
// actually a member of groupId before any group-internal data (balance,
// transactions, member list w/ wallet IDs, requests) is returned. Without
// this, any authenticated user could read any group's data just by
// guessing/incrementing IDs — group membership, not just login, is the
// access boundary here.
async function requireGroupMembership(groupId, userId) {
  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, userId]
  );
  return !!membership;
}

app.get('/api/groups/:id', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!Number.isInteger(groupId)) {
    return res.status(400).json({ error: 'Invalid group ID' });
  }
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  const [[group]] = await pool.query('SELECT id, name, balance FROM `groups` WHERE id = ?', [groupId]);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const [members] = await pool.execute(
    `SELECT u.id, u.username, u.wallet_id AS walletId
     FROM group_members gm JOIN users u ON u.id = gm.user_id
     WHERE gm.group_id = ?`,
    [groupId]
  );
  res.json({ id: group.id, name: group.name, balance: toCentavos(group.balance), members });
}));

app.get('/api/groups/:id/transactions', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!Number.isInteger(groupId)) {
    return res.status(400).json({ error: 'Invalid group ID' });
  }
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  const [rows] = await pool.execute(
    `SELECT id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'group' AND account_id = ?
     ORDER BY created_at DESC`,
    [groupId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.get('/api/groups/:id/requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  const [rows] = await pool.execute(
    `SELECT id, requester_name AS requesterName, reason, amount, status, created_at AS createdAt
     FROM withdrawal_requests
     WHERE group_id = ?
     ORDER BY created_at DESC`,
    [groupId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.post('/api/groups/:id/withdraw-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  const reason = cleanText(req.body?.reason, 255) || '';
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [members] = await conn.query(
      'SELECT user_id FROM group_members WHERE group_id = ?',
      [groupId]
    );
    if (!members.some((m) => m.user_id === req.userId)) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ?', [groupId]);
    if (toCentavos(group.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient group balance' });
    }

    // Majority of the members OTHER than the requester, matching the threshold
    // the respond route enforces. The requester cannot vote on their own
    // request, so counting them here made this bar overstate progress.
    const approvalsNeeded = Math.floor(Math.max(0, members.length - 1) / 2) + 1;

    const [result] = await conn.execute(
      'INSERT INTO group_withdraw_requests (group_id, requester_id, amount, reason, approvals_needed) VALUES (?,?,?,?,?)',
      [groupId, req.userId, amt, reason, approvalsNeeded]
    );

    await conn.commit();
    res.json({ id: result.insertId, ok: true, approvalsNeeded });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/groups/:id/withdraw-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);

  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const [rows] = await pool.execute(
    `SELECT wr.id, wr.requester_id AS requesterId, u.username AS requesterName,
            wr.amount, wr.reason, wr.status, wr.approvals_needed AS approvalsNeeded,
            (SELECT COUNT(*)
               FROM group_withdraw_approvals wa
               JOIN group_members gm ON gm.user_id = wa.member_id AND gm.group_id = wr.group_id
              WHERE wa.request_id = wr.id AND wa.decision = 'approve') AS approvalsCount,
            EXISTS(SELECT 1 FROM group_withdraw_approvals wa WHERE wa.request_id = wr.id AND wa.member_id = ?) AS decidedByMe
     FROM group_withdraw_requests wr JOIN users u ON u.id = wr.requester_id
     WHERE wr.group_id = ? AND wr.status = 'pending'
     ORDER BY wr.created_at DESC`,
    [req.userId, groupId]
  );
  res.json(rows.map((r) => ({ ...r, amount: toCentavos(r.amount) })));
}));
// ---------- groups (capped at MAX_GROUP_MEMBERS) ----------

app.post('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const name = cleanText(req.body?.name, 100);
  if (!name) return res.status(400).json({ error: 'name is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [result] = await conn.execute('INSERT INTO `groups` (name) VALUES (?)', [name]);
    await conn.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [result.insertId, req.userId]);
    await conn.commit();
    res.json({ id: result.insertId, name });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/request-join', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);

  const [[already]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (already) return res.status(409).json({ error: 'Already a member' });

  const [[pending]] = await pool.query(
    "SELECT 1 FROM group_join_requests WHERE group_id = ? AND user_id = ? AND status = 'pending'",
    [groupId, req.userId]
  );
  if (pending) return res.status(409).json({ error: 'Request already pending' });

  await pool.execute(
    'INSERT INTO group_join_requests (group_id, user_id) VALUES (?, ?)',
    [groupId, req.userId]
  );
  res.json({ ok: true });
}));

app.get('/api/groups/:id/join-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const [rows] = await pool.execute(
    `SELECT jr.id, jr.user_id AS userId, u.username, jr.created_at AS createdAt
     FROM group_join_requests jr JOIN users u ON u.id = jr.user_id
     WHERE jr.group_id = ? AND jr.status = 'pending'`,
    [groupId]
  );
  res.json(rows);
}));

app.post('/api/groups/:groupId/join-requests/:reqId/respond', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[membership]] = await conn.query(
      'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
      [groupId, req.userId]
    );
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[request]] = await conn.query(
      "SELECT * FROM group_join_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }

    if (approve) {
      const [members] = await conn.query(
        'SELECT user_id FROM group_members WHERE group_id = ? FOR UPDATE',
        [groupId]
      );
      if (members.length >= MAX_GROUP_MEMBERS) {
        await conn.rollback();
        return res.status(409).json({ error: `Group is full (max ${MAX_GROUP_MEMBERS})` });
      }
      await conn.execute(
        'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
        [groupId, request.user_id]
      );
    }

    await conn.execute(
      'UPDATE group_join_requests SET status = ? WHERE id = ?',
      [approve ? 'approved' : 'declined', reqId]
    );

    await conn.commit();
    res.json({ ok: true, status: approve ? 'approved' : 'declined' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:groupId/withdraw-requests/:reqId/respond', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[membership]] = await conn.query(
      'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
      [groupId, req.userId]
    );
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[request]] = await conn.query(
      "SELECT * FROM group_withdraw_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }

    // The person who asked for the money never counts towards approving it, so
    // only the OTHER members vote. needed is a strict majority of those, and a
    // group with nobody else in it can never pay a withdrawal out. This is
    // computed here rather than read from request.approvals_needed, which was
    // frozen at creation time from the TOTAL member count and so still counts
    // the requester as one of the voters.
    const [[{ eligible }]] = await conn.query(
      'SELECT COUNT(*) AS eligible FROM group_members WHERE group_id = ? AND user_id <> ?',
      [groupId, request.requester_id]
    );
    if (eligible < 1) {
      await conn.rollback();
      return res.status(400).json({ error: 'A group needs at least two members before a withdrawal can be approved' });
    }
    const approvalsNeeded = Math.floor(eligible / 2) + 1;

    if (req.userId === request.requester_id) {
      await conn.rollback();
      return res.status(403).json({ error: 'You cannot vote on your own withdrawal request' });
    }

    const [[already]] = await conn.query(
      'SELECT 1 FROM group_withdraw_approvals WHERE request_id = ? AND member_id = ?',
      [reqId, req.userId]
    );
    if (already) {
      await conn.rollback();
      return res.status(409).json({ error: 'You already voted on this request' });
    }

    await conn.execute(
      'INSERT INTO group_withdraw_approvals (request_id, member_id, decision) VALUES (?,?,?)',
      [reqId, req.userId, approve ? 'approve' : 'decline']
    );

    if (!approve) {
      await conn.execute("UPDATE group_withdraw_requests SET status = 'declined' WHERE id = ?", [reqId]);
      const body = { ok: true, status: 'declined' };
      await commitWithIdempotency(conn, req, 200, body);
      return res.json(body);
    }

    const [[{ approvals }]] = await conn.query(
      `SELECT COUNT(*) AS approvals
         FROM group_withdraw_approvals wa
         JOIN group_members gm ON gm.user_id = wa.member_id AND gm.group_id = ?
        WHERE wa.request_id = ? AND wa.decision = 'approve' AND wa.member_id <> ?`,
      [groupId, reqId, request.requester_id]
    );

    if (approvals >= approvalsNeeded) {
      const amt = toCentavos(request.amount);

      // The requester row is locked first, then the locking membership read,
      // then the group row. That keeps this route's lock order user-then-group
      // and stops a removed or suspended requester from being paid.
      const [[requester]] = await conn.query(
        'SELECT username, balance, verification_level, status FROM users WHERE id = ? FOR UPDATE',
        [request.requester_id]
      );
      const [[requesterMembership]] = await conn.query(
        'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ? FOR SHARE',
        [groupId, request.requester_id]
      );
      if (!requester || !requesterMembership || requester.status !== 'active') {
        await conn.rollback();
        return res.status(400).json({ error: 'The requester is no longer an active member of this group' });
      }

      // The group name keeps the ledger label readable; the group row is
      // locked after the requester row, so the user-then-group order holds.
      const [[group]] = await conn.query('SELECT name, balance FROM `groups` WHERE id = ? FOR UPDATE', [groupId]);
      if (toCentavos(group.balance) < amt) {
        await conn.rollback();
        return res.status(400).json({ error: 'Group balance too low to complete this withdrawal now' });
      }

      const capError = recipientCapError(toCentavos(requester.balance), amt, limitsForUser(requester.verification_level));
      if (capError) {
        await conn.rollback();
        // Say whose wallet is full without naming them or exposing their balance.
        return res.status(400).json({ error: 'The member who requested this withdrawal cannot receive it right now because their wallet is close to its limit. Your vote was not recorded.' });
      }

      await conn.execute('UPDATE `groups` SET balance = balance - ? WHERE id = ?', [amt, groupId]);
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, request.requester_id]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['group', groupId, `Withdrawal to ${cleanText(requester.username, 60)} (approved)`, 'Group Withdrawal', amt, 0]
      );
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['user', request.requester_id, `Group withdrawal from ${cleanText(group.name, 100)}`, 'Group Withdrawal', amt, 1]
      );
      await conn.execute("UPDATE group_withdraw_requests SET status = 'approved' WHERE id = ?", [reqId]);

      const body = { ok: true, status: 'approved', executed: true };
      await commitWithIdempotency(conn, req, 200, body);
      try {
        await refreshUserInIndex(request.requester_id);
      } catch (err) {
        console.error('post-commit refresh failed:', err.message);
      }
      return res.json(body);
    }

    const body = { ok: true, status: 'pending', approvalsCount: approvals, approvalsNeeded };
    await commitWithIdempotency(conn, req, 200, body);
    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/contribute', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[membership]] = await conn.query('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [
      groupId,
      req.userId,
    ]);
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }
    // username is loaded here so the group-side row below can name the
    // contributor instead of printing their numeric user id. Same row, same
    // read - no extra query and no change to the lock order.
    const [[user]] = await conn.query('SELECT username, balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    const limitError = await outgoingLimitError(conn, req.userId, amt, limitsForUser(user.verification_level));
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute('UPDATE `groups` SET balance = balance + ? WHERE id = ?', [amt, groupId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['group', groupId, `Contribution from ${cleanText(user.username, 60)}`, 'Contribution', amt, 1]
    );
    // The user's own half of the same movement. Without this row the wallet is
    // debited with nothing in its own history, so Money out and
    // /transactions/summary both under-report. Mirrors the paired insert in the
    // withdrawal route. No transfer_ref, so /api/undo cannot reach it - group
    // flows are not undoable. The group name is not loaded here and is not
    // worth a query of its own for one label, so this row names the group by
    // id while the withdrawal route, which already has the name, uses it.
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Contribution to group #${groupId}`, 'Contribution', amt, 0]
    );
    const body = { ok: true };
    await commitWithIdempotency(conn, req, 200, body);

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    try {
      await refreshUserInIndex(req.userId);
    } catch (err) {
      console.error('post-commit refresh failed:', err.message);
    }

    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const requesterName = cleanText(req.body?.requesterName, 100);
  const reason = cleanText(req.body?.reason, 255);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!requesterName || !reason || amt === null) {
    return res.status(400).json({ error: 'requesterName, reason, and a positive amount (integer centavos) are required' });
  }
  // A member-only gate: approving one of these debits the group balance
  // directly (see /api/admin/groups/:groupId/requests/:reqId/respond),
  // with no recipient account tied to the request — so without this
  // check, anyone with a login (member or not) could plant a request
  // against an arbitrary group and rely on an admin approving it based
  // on the free-text requesterName/reason alone.
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  await pool.execute(
    'INSERT INTO withdrawal_requests (group_id, requester_name, reason, amount) VALUES (?,?,?,?)',
    [groupId, requesterName, reason, amt]
  );
  res.json({ ok: true });
}));

// ---------- savings goals (personal, locked sub-balance) ----------

app.post('/api/savings', requireAuth, asyncRoute(async (req, res) => {
  const name = cleanText(req.body?.name, 100);
  const target = parseCentavos(req.body?.targetAmountCentavos);
  if (!name) return res.status(400).json({ error: 'A goal name is required' });
  if (target === null) return res.status(400).json({ error: 'A positive target amount (integer centavos) is required' });

  const [result] = await pool.execute(
    'INSERT INTO savings_goals (user_id, name, target_amount) VALUES (?, ?, ?)',
    [req.userId, name, target]
  );
  res.json({ id: result.insertId, ok: true });
}));

app.get('/api/savings/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT id, name, target_amount, saved_amount, status, created_at FROM savings_goals WHERE user_id = ? ORDER BY created_at DESC',
    [req.userId]
  );
  res.json(rows.map((g) => ({
    ...g,
    targetAmount: toCentavos(g.target_amount),
    savedAmount: toCentavos(g.saved_amount),
  })));
}));

app.post('/api/savings/:id/deposit', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const goalId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[goal]] = await conn.query(
      'SELECT * FROM savings_goals WHERE id = ? AND user_id = ? FOR UPDATE',
      [goalId, req.userId]
    );
    if (!goal) {
      await conn.rollback();
      return res.status(404).json({ error: 'Goal not found' });
    }
    const [[user]] = await conn.query('SELECT balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const limitError = await outgoingLimitError(conn, req.userId, amt, limitsForUser(user.verification_level));
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }

    const newSaved = toCentavos(goal.saved_amount) + amt;
    const nowComplete = newSaved >= toCentavos(goal.target_amount);

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute('UPDATE savings_goals SET saved_amount = ?, status = ? WHERE id = ?', [
      newSaved, nowComplete ? 'completed' : 'active', goalId,
    ]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Savings: ${goal.name}`, 'Savings Deposit', amt, 0]
    );

    const body = { ok: true, savedAmount: newSaved, completed: nowComplete };
    await commitWithIdempotency(conn, req, 200, body);
    await refreshUserInIndex(req.userId);
    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/savings/:id/withdraw', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const goalId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[goal]] = await conn.query(
      'SELECT * FROM savings_goals WHERE id = ? AND user_id = ? FOR UPDATE',
      [goalId, req.userId]
    );
    if (!goal) {
      await conn.rollback();
      return res.status(404).json({ error: 'Goal not found' });
    }
    const saved = toCentavos(goal.saved_amount);
    if (saved < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Not enough saved in this goal' });
    }

    const [[user]] = await conn.query('SELECT balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const recipientLimits = limitsForUser(user.verification_level);
    const capError = recipientCapError(toCentavos(user.balance), amt, recipientLimits);
    if (capError) {
      await conn.rollback();
      return res.status(400).json({ error: `Your wallet can hold at most ${pesoText(recipientLimits.maxBalanceCentavos)}. Spend or send some money first, then try again. Your savings are still safe in this goal.` });
    }

    const newSaved = saved - amt;
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, req.userId]);
    await conn.execute('UPDATE savings_goals SET saved_amount = ?, status = ? WHERE id = ?', [
      newSaved, 'active', goalId,
    ]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Savings withdrawal: ${goal.name}`, 'Savings Withdrawal', amt, 1]
    );

    const body = { ok: true, savedAmount: newSaved };
    await commitWithIdempotency(conn, req, 200, body);
    await refreshUserInIndex(req.userId);
    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.delete('/api/savings/:id', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const goalId = Number(req.params.id);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[goal]] = await conn.query(
      'SELECT * FROM savings_goals WHERE id = ? AND user_id = ? FOR UPDATE',
      [goalId, req.userId]
    );
    if (!goal) {
      await conn.rollback();
      return res.status(404).json({ error: 'Goal not found' });
    }
    const saved = toCentavos(goal.saved_amount);
    if (saved > 0) {
      const [[user]] = await conn.query('SELECT balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
      const recipientLimits = limitsForUser(user.verification_level);
      const capError = recipientCapError(toCentavos(user.balance), saved, recipientLimits);
      if (capError) {
        await conn.rollback();
        return res.status(400).json({ error: `Your wallet can hold at most ${pesoText(recipientLimits.maxBalanceCentavos)}. Spend or send some money first, then try again. Your savings are still safe and this goal was not closed.` });
      }
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [saved, req.userId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['user', req.userId, `Closed goal: ${goal.name}`, 'Savings Withdrawal', saved, 1]
      );
    }
    await conn.execute('DELETE FROM savings_goals WHERE id = ?', [goalId]);
    const body = { ok: true, returnedCentavos: saved };
    await commitWithIdempotency(conn, req, 200, body);
    await refreshUserInIndex(req.userId);
    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- events and tickets ----------
//
// The catalog lives in the `events` table and purchased tickets in `tickets`
// (see schema.sql). Rows are added by hand in v1 - there is no admin route and
// no seed data.
//
// Payment deliberately does NOT reuse POST /bills/pay. That route debits the
// wallet and writes only a transactions row, so a ticket bought through it
// would leave the user charged with nothing to retrieve. Here the balance
// update, the transactions row and the tickets row are written inside ONE
// transaction, so a failure anywhere rolls all three back together.
const EVENT_LIST_LIMIT = 50;
const TICKET_LIST_LIMIT = 50;
const MAX_TICKETS_PER_ORDER = 10;

app.get('/api/events', requireAuth, asyncRoute(async (req, res) => {
  // Upcoming only, soonest first. starts_at is compared with MySQL's own clock,
  // never the client's, so a wrong device clock cannot buy a past event.
  const [rows] = await pool.query(
    `SELECT id, title, venue, starts_at AS startsAt, price_centavos AS priceCentavos
       FROM events
      WHERE starts_at > NOW()
      ORDER BY starts_at ASC
      LIMIT ?`,
    [EVENT_LIST_LIMIT]
  );
  res.json(rows.map((row) => ({ ...row, priceCentavos: toCentavos(row.priceCentavos) })));
}));

app.get('/api/tickets', requireAuth, asyncRoute(async (req, res) => {
  // Scoped to the caller on the server. No user id is accepted from the
  // request, so one account can never list another account's tickets.
  const [rows] = await pool.query(
    `SELECT t.id, t.ticket_code AS ticketCode, t.quantity,
            t.amount_paid_centavos AS amountPaidCentavos, t.status,
            t.created_at AS createdAt,
            e.id AS eventId, e.title, e.venue, e.starts_at AS startsAt
       FROM tickets t
       JOIN events e ON e.id = t.event_id
      WHERE t.user_id = ?
      ORDER BY t.created_at DESC, t.id DESC
      LIMIT ?`,
    [req.userId, TICKET_LIST_LIMIT]
  );
  res.json(rows.map((row) => ({ ...row, amountPaidCentavos: toCentavos(row.amountPaidCentavos) })));
}));

app.post('/api/events/:id/tickets', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const eventId = Number(req.params.id);
  if (!Number.isInteger(eventId) || eventId < 1) {
    return res.status(400).json({ error: 'Invalid event ID' });
  }
  const quantity = Number(req.body?.quantity);
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_TICKETS_PER_ORDER) {
    return res.status(400).json({ error: `quantity must be a whole number from 1 to ${MAX_TICKETS_PER_ORDER}` });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[user]] = await conn.query('SELECT id, balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (!user) {
      await conn.rollback();
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // The price is read from the locked event row, never from the request, so
    // a modified client cannot choose what it pays. FOR UPDATE also serialises
    // concurrent buys of the same event.
    const [[event]] = await conn.query(
      'SELECT id, title, venue, starts_at, price_centavos, (starts_at > NOW()) AS isUpcoming FROM events WHERE id = ? FOR UPDATE',
      [eventId]
    );
    if (!event) {
      await conn.rollback();
      return res.status(404).json({ error: 'Event not found' });
    }
    if (!event.isUpcoming) {
      await conn.rollback();
      return res.status(400).json({ error: 'This event has already started' });
    }

    const price = toCentavos(event.price_centavos);
    const amount = price * quantity;
    // Guards a mistyped catalogue row before it reaches the balance update: a
    // non-positive price, a product that leaves the safe-integer range, or a
    // total above the same ceiling parseCentavos() enforces elsewhere.
    if (!Number.isSafeInteger(price) || price <= 0 || !Number.isSafeInteger(amount) || amount <= 0 || amount > MAX_CENTAVOS) {
      await conn.rollback();
      return res.status(400).json({ error: 'This event has no valid price set' });
    }

    if (toCentavos(user.balance) < amount) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    const limitError = await outgoingLimitError(conn, req.userId, amount, limitsForUser(user.verification_level));
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }

    const ref = newReferenceNumber();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
      ['user', req.userId, `Event Ticket - ${cleanText(event.title, 150)}`, 'Event Ticket', amount, 0, referenceDetails(ref)]
    );
    // 128 bits of Node crypto, not newReferenceNumber() - the ticket code is a
    // bearer credential and must not be short or already printed on a receipt.
    // Nothing here is logged.
    const ticketCode = crypto.randomBytes(16).toString('hex');
    const [ticketResult] = await conn.execute(
      `INSERT INTO tickets (user_id, event_id, ticket_code, quantity, amount_paid_centavos)
       VALUES (?,?,?,?,?)`,
      [req.userId, eventId, ticketCode, quantity, amount]
    );

    const body = {
      ok: true,
      referenceNumber: ref,
      ticket: {
        id: ticketResult.insertId,
        ticketCode,
        quantity,
        amountPaidCentavos: amount,
        eventId,
        title: event.title,
        venue: event.venue,
        startsAt: event.starts_at,
      },
    };
    await commitWithIdempotency(conn, req, 200, body);

    // Both rows are committed - refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin: ticket lookup and redemption ----------
//
// Gate staff scan the e-ticket QR and mark the ticket used so the same code
// cannot be presented twice. This moves no money, so requirePin and the
// `idempotent` middleware do not apply: neither is needed to stop a double
// scan. What stops a double scan is the row lock plus a status transition that
// is re-checked in the UPDATE's own WHERE clause, all inside one transaction -
// the same shape POST /api/admin/cashins/:id/respond uses.
//
// requireAdmin sets req.adminId (not req.userId), so these routes are keyed on
// the admin principal and never accept a user id from the request.
//
// Nothing about the ticket holder is returned or logged: no user id, name,
// phone or balance. The only identity that crosses the boundary is the ticket
// id, which is needed so an admin can tell two admissions apart.

// A scanned code is the whole credential. The e-ticket QR carries
// 'paycst:ticket:<code>' (see Ticket.qrPayload in the app), but staff may also
// type the bare code, so both are accepted.
const TICKET_QR_PREFIX = 'paycst:ticket:';

// crypto.randomBytes(16).toString('hex') is always exactly 32 lowercase hex
// characters, so that is the only shape accepted. Returns null for anything
// else, which callers turn into a 400 before any query runs - an admin scanner
// must never be able to reach the database with an unvalidated value.
function parseTicketCode(value) {
  let code = typeof value === 'string' ? value.trim() : '';
  if (code.startsWith(TICKET_QR_PREFIX)) code = code.slice(TICKET_QR_PREFIX.length);
  return /^[0-9a-f]{32}$/.test(code) ? code : null;
}

// events has no ends_at column, so starts_at is the only anchor available.
// Redemption stays open for this long after it, which covers same-day scanning
// and late arrivals without inventing a schema change. Compared in MySQL, never
// against the Node clock, so a wrong server or device time cannot close or open
// the window. This is a server constant, not request input - the same pattern
// CASH_IN_TTL_HOURS already uses in an INTERVAL.
const TICKET_REDEEM_GRACE_HOURS = 24;

// A gate scanning a busy line is a legitimate burst, so adminLimiter's 10 per
// 15 minutes (tuned for guessing a login password) would lock staff out
// mid-queue. This is the same shape as moneyLimiter, keyed on the admin so one
// noisy admin cannot throttle another.
const ticketScanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.adminId ? `a:${req.adminId}` : ipKeyGenerator(req)),
  message: { error: 'Too many scans in a short time. Please wait a moment.' },
});

// Read only: tells the admin what they are holding before they redeem it.
// Deliberately not a status change, so it can be re-run freely.
app.post('/api/admin/tickets/lookup', requireAdmin, ticketScanLimiter, asyncRoute(async (req, res) => {
  const code = parseTicketCode(req.body?.code);
  if (!code) {
    return res.status(400).json({ error: 'Scan a ticket QR or enter a 32-character ticket code' });
  }

  const [[row]] = await pool.execute(
    `SELECT t.id, t.status, t.quantity, t.event_id, t.created_at,
            e.title, e.venue, e.starts_at,
            (e.starts_at > (NOW() - INTERVAL ${TICKET_REDEEM_GRACE_HOURS} HOUR)) AS redeemable
       FROM tickets t
       JOIN events e ON e.id = t.event_id
      WHERE t.ticket_code = ?`,
    [code]
  );
  // One generic message for "no such code" and "no such event" so the response
  // cannot be used to tell a valid code from an invalid one.
  if (!row) {
    return res.status(404).json({ error: 'No ticket matches that code' });
  }

  res.json({
    ticket: {
      id: row.id,
      status: row.status,
      quantity: row.quantity,
      eventId: row.event_id,
      title: row.title,
      venue: row.venue,
      startsAt: row.starts_at,
      createdAt: row.created_at,
      redeemable: !!row.redeemable,
    },
  });
}));

app.post('/api/admin/tickets/redeem', requireAdmin, ticketScanLimiter, asyncRoute(async (req, res) => {
  const code = parseTicketCode(req.body?.code);
  if (!code) {
    return res.status(400).json({ error: 'Scan a ticket QR or enter a 32-character ticket code' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // FOR UPDATE locks the ticket row, so a second admin scanning the same code
    // blocks here until this transaction finishes and then reads the committed
    // status. The lock also covers the event row it joins; the transaction is a
    // single UPDATE and INSERT, so the hold is short enough not to matter.
    const [[row]] = await conn.query(
      `SELECT t.id, t.status, t.quantity, t.event_id,
              e.title, e.venue,
              (e.starts_at > (NOW() - INTERVAL ${TICKET_REDEEM_GRACE_HOURS} HOUR)) AS redeemable
         FROM tickets t
         JOIN events e ON e.id = t.event_id
        WHERE t.ticket_code = ?
        FOR UPDATE`,
      [code]
    );
    if (!row) {
      await conn.rollback();
      return res.status(404).json({ error: 'No ticket matches that code' });
    }
    if (row.status === 'used') {
      await conn.rollback();
      // tickets has no used_at column and none is added here: the admin_audit_log
      // row written at redemption time already records who and when, so a
      // separate timestamp would only duplicate it.
      return res.status(409).json({ error: 'This ticket has already been used' });
    }
    if (row.status === 'cancelled') {
      await conn.rollback();
      return res.status(409).json({ error: 'This ticket was cancelled' });
    }
    if (!row.redeemable) {
      await conn.rollback();
      return res.status(409).json({ error: 'The redemption window for this event has closed' });
    }

    // status is re-checked in the UPDATE's own WHERE, so this is the authority
    // rather than the read above: if anything changed the row between the lock
    // and here, affectedRows is 0 and the ticket is not marked used.
    const [result] = await conn.execute(
      "UPDATE tickets SET status = 'used' WHERE id = ? AND status = 'valid'",
      [row.id]
    );
    if (result.affectedRows !== 1) {
      await conn.rollback();
      return res.status(409).json({ error: 'This ticket has already been used' });
    }

    // Written on the transaction's own connection so the audit row commits with
    // the status change or not at all. Neither logAdmin nor logAdminEvent can do
    // this: both use the pool, and logAdminEvent hardcodes target_type
    // 'admin_login', which is the wrong record type for a redemption.
    // No ticket code, user id or other personal detail is recorded.
    await conn.execute(
      'INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, details, ip) VALUES (?,?,?,?,?,?)',
      [
        req.adminId,
        'ticket_redeem',
        'ticket',
        String(row.id),
        JSON.stringify({ eventId: row.event_id, quantity: row.quantity }),
        (req.ip || '').toString().slice(0, 64),
      ]
    );

    await conn.commit();

    res.json({ ok: true, quantity: row.quantity, title: row.title, venue: row.venue });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin: login + final say on groups (item #13) ----------

// Step 1: password only.
app.post('/api/admin/login', adminLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username is required' });

  const identifier = `admin:${username.toString().trim().toLowerCase()}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    await logAdminEvent(req, 'admin_login_locked', null, username);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, password_hash, pin_hash FROM admins WHERE username = ?', [username]);
  const admin = rows[0];
  const ok = await bcrypt.compare(password || '', admin ? admin.password_hash : DUMMY_BCRYPT_HASH);
  if (!admin || !ok) {
    await recordFailedAttempt(identifier);
    await logAdminEvent(req, 'admin_login_failed', admin ? admin.id : null, username);
    return res.status(401).json({ error: 'Incorrect admin credentials' });
  }
  if (!admin.pin_hash) {
    return res.status(403).json({
      error: 'This admin account has no PIN set yet. Run `npm run create-admin -- <username> <password> <pin>` to set one before logging in.',
    });
  }
  await clearAttempts(identifier);

  const pendingToken = sign({ uid: admin.id, stage: 'pending', role: 'admin' }, '5m');
  res.json({ pendingToken });
}));

// Step 2: the PIN.
app.post('/api/admin/login/verify-pin', adminPinLimiter, asyncRoute(async (req, res) => {
  const { pendingToken, pin } = req.body || {};
  const payload = pendingToken && verify(pendingToken);
  if (!payload || payload.stage !== 'pending' || payload.role !== 'admin') {
    return res.status(401).json({ error: 'Login session expired, please log in again' });
  }

  const identifier = `adminpin:${payload.uid}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    await logAdminEvent(req, 'admin_pin_locked', payload.uid, `admin ${payload.uid}`);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, pin_hash FROM admins WHERE id = ?', [payload.uid]);
  const admin = rows[0];
  const ok = await bcrypt.compare(pin || '', admin ? admin.pin_hash : DUMMY_BCRYPT_HASH);
  if (!admin || !ok) {
    await recordFailedAttempt(identifier);
    await logAdminEvent(req, 'admin_pin_failed', payload.uid, `admin ${payload.uid}`);
    return res.status(401).json({ error: 'Incorrect PIN' });
  }
  await clearAttempts(identifier);
  await logAdminEvent(req, 'admin_login', admin.id, `admin ${admin.id}`);

  const token = sign({ uid: admin.id, stage: 'full', role: 'admin' }, '4h');
  res.json({ token });
}));

// Full oversight view: every registered user, their balance/wallet, and
// how many groups they belong to.
app.get('/api/admin/users', requireAdmin, asyncRoute(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 50));
  const offset = (page - 1) * pageSize;
    const search = req.query.search ? `%${req.query.search.toString().trim()}%` : null;
  const sortBy = req.query.sortBy === 'balance' ? 'balance' : 'username';

  // Matches on username OR the numeric ID (cast to text so a partial-ID
  // search like "12" also matches id 12, 120, 1123, etc.) OR the wallet ID.
  const whereClause = search ? 'WHERE (u.username LIKE ? OR CAST(u.id AS CHAR) LIKE ? OR u.wallet_id LIKE ?)' : '';
  const params = search ? [search, search, search] : [];

  const [[{ total }]] = await pool.query(
    `SELECT COUNT(*) AS total FROM users u ${whereClause}`,
    params
  );

  // DB does the heavy lifting (only pulls the rows for this page) — merge
  // sort still runs, just on the bounded page instead of the whole table,
  // so it stays fast at any scale while keeping the mandatory sort step.
      const [rawUsers] = await pool.query(
    `SELECT u.id, u.username, u.wallet_id AS walletId, u.balance, u.status,
            (SELECT COUNT(*) FROM group_members gm WHERE gm.user_id = u.id) AS groupCount
     FROM users u
     ${whereClause}
     LIMIT ? OFFSET ?`,
    [...params, pageSize, offset]
  );

  const normalized = rawUsers.map((u) => ({ ...u, balance: toCentavos(u.balance) }));
  const sorted =
    sortBy === 'balance'
      ? mergeSort(normalized, comparators.balanceDesc)
      : mergeSort(normalized, comparators.usernameAsc);

  res.json({
    users: sorted,
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  });
}));

// Admin suspends or reactivates a user's account. Suspension blocks login
// at the password step (before a session token can even be issued) but
// doesn't touch existing data — balance, groups, and loan history stay
// intact so reactivating just picks back up where things left off.
app.post('/api/admin/users/:id/status', requireAdmin, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  const suspend = !!req.body?.suspend;
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const [result] = await pool.execute('UPDATE users SET status = ? WHERE id = ?', [
    suspend ? 'suspended' : 'active',
    userId,
  ]);
  if (result.affectedRows === 0) {
    return res.status(404).json({ error: 'User not found' });
  }

  await refreshUserInIndex(userId);
  await logAdmin(req, suspend ? 'suspend_user' : 'unsuspend_user', 'user', userId);
  res.json({ ok: true, status: suspend ? 'suspended' : 'active' });
}));

// Admin-assisted password recovery. The code is returned ONLY in this
// authenticated-admin response; it is never logged or written to the audit
// trail (the task forbids logging ids, and the code is a credential).
app.post('/api/admin/users/:id/password-reset', requireAdmin, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const [[user]] = await pool.query(
    'SELECT id, username, phone_number, wallet_id FROM users WHERE id = ?',
    [userId]
  );
  if (!user) return res.status(404).json({ error: 'User not found' });

  const code = await issueResetCode(user);
  await deliverResetCode(user, code);
  res.json({ ok: true, code, expiresInSeconds: RESET_CODE_TTL_SECONDS });
}));


// Purchase/transaction history for one specific user — powers the
// "View Purchases" button next to each row in the admin Users tab.
app.get('/api/admin/users/:id/transactions', requireAdmin, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 20));
  const offset = (page - 1) * pageSize;

  const [[user]] = await pool.query('SELECT id, username FROM users WHERE id = ?', [userId]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const [[{ total }]] = await pool.query(
    "SELECT COUNT(*) AS total FROM transactions WHERE account_type = 'user' AND account_id = ?",
    [userId]
  );

  const [rows] = await pool.query(
    `SELECT id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'user' AND account_id = ?
     ORDER BY created_at DESC
     LIMIT ? OFFSET ?`,
    [userId, pageSize, offset]
  );

  const transactions = rows.map((t) => ({ ...t, amount: toCentavos(t.amount) }));

  res.json({
    username: user.username,
    transactions,
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  });
}));

// Full oversight view: every group with its members and pending requests.
app.get('/api/admin/groups', requireAdmin, asyncRoute(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 50));
  const offset = (page - 1) * pageSize;
  const search = req.query.search ? `%${req.query.search.toString().trim()}%` : null;
  const whereClause = search ? 'WHERE name LIKE ?' : '';
  const params = search ? [search] : [];

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM \`groups\` ${whereClause}`, params);

  const [groups] = await pool.query(
    `SELECT id, name, balance FROM \`groups\` ${whereClause} ORDER BY name ASC LIMIT ? OFFSET ?`,
    [...params, pageSize, offset]
  );

  for (const g of groups) {
    g.balance = toCentavos(g.balance);
    const [members] = await pool.execute(
      `SELECT u.id, u.username, u.wallet_id AS walletId
       FROM group_members gm JOIN users u ON u.id = gm.user_id
       WHERE gm.group_id = ?`,
      [g.id]
    );
    const [requests] = await pool.execute(
      `SELECT id, requester_name AS requesterName, reason, amount, status
       FROM withdrawal_requests WHERE group_id = ? AND status = 'pending'`,
      [g.id]
    );
    g.members = members;
    g.pendingRequests = requests.map((r) => ({ ...r, amount: toCentavos(r.amount) }));
  }

  res.json({ groups, total, page, pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
}));

// Admin removes a member from a group.
app.delete('/api/admin/groups/:id/members/:userId', requireAdmin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const userId = Number(req.params.userId);
  const [result] = await pool.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', [
    groupId,
    userId,
  ]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'That user is not in this group' });
  await logAdmin(req, 'remove_group_member', 'group', groupId, { userId });
  res.json({ ok: true });
}));

// Admin is the final decider on a group's withdrawal/support request.
app.post('/api/admin/groups/:groupId/requests/:reqId/respond', requireAdmin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[request]] = await conn.query(
      "SELECT * FROM withdrawal_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }
    const requestAmount = toCentavos(request.amount);

    if (approve) {
      const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ? FOR UPDATE', [groupId]);
      if (toCentavos(group.balance) < requestAmount) {
        await conn.rollback();
        return res.status(400).json({ error: 'Not enough funds in the group to approve this request' });
      }
      await conn.execute('UPDATE `groups` SET balance = balance - ? WHERE id = ?', [requestAmount, groupId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'group',
          groupId,
          `Sent to ${cleanText(request.requester_name, 100)} (Support)`,
          'Withdrawal',
          requestAmount,
          0,
          JSON.stringify({ reason: request.reason }),
        ]
      );
    }

    await conn.execute(
      'UPDATE withdrawal_requests SET status = ?, decided_by_admin_id = ?, decided_at = NOW() WHERE id = ?',
      [approve ? 'approved' : 'declined', req.adminId, reqId]
    );

    await conn.commit();
    await logAdmin(req, approve ? 'approve_group_withdrawal' : 'decline_group_withdrawal', 'withdrawal_request', reqId);
    res.json({ ok: true, status: approve ? 'approved' : 'declined' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin transfer reversal ----------

// ---------- shared reversal core ----------
// Used by BOTH the admin reversal route and the user-facing /api/undo
// route, so there's one place that enforces the safety checks — no
// double-reversal, no letting a recipient's balance go negative.
async function reverseTransferByRef(conn, transferRef) {
  const [rows] = await conn.query(
    'SELECT id, account_type, account_id, label, type, amount, is_credit FROM transactions WHERE transfer_ref = ? FOR UPDATE',
    [transferRef]
  );

  if (rows.length === 0) {
    return { ok: false, status: 404, error: 'Transfer not found' };
  }

  const [[already]] = await conn.query('SELECT 1 FROM transactions WHERE reversed_transfer_ref = ?', [transferRef]);
  if (already) {
    return { ok: false, status: 409, error: 'This transfer has already been reversed' };
  }

  for (const row of rows) {
    if (row.account_type === 'user' && row.is_credit) {
      const [[recipientRow]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [row.account_id]);
      const amount = toCentavos(row.amount);
      if (toCentavos(recipientRow.balance) < amount) {
        return {
          ok: false,
          status: 409,
          error: 'Cannot reverse — the recipient no longer has sufficient balance to return the funds',
        };
      }
    }
  }

  const reversalTransferRef = crypto.randomUUID();
  const affectedUserIds = new Set();

  for (const row of rows) {
    const amount = toCentavos(row.amount);
    const reversalIsCredit = row.is_credit ? 0 : 1;
    const balanceDelta = row.is_credit ? -amount : amount;

    if (row.account_type === 'user') {
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [balanceDelta, row.account_id]);
      affectedUserIds.add(row.account_id);
    }

    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, reversed_transfer_ref) VALUES (?,?,?,?,?,?,?,?)',
      [
        'user',
        row.account_id,
        `Reversal: ${row.label}`,
        row.type || 'Transfer Reversal',
        amount,
        reversalIsCredit,
        reversalTransferRef,
        transferRef,
      ]
    );
  }

  return { ok: true, reversalTransferRef, affectedUserIds };
}
app.get('/api/admin/transfers/:transferRef', requireAdmin, asyncRoute(async (req, res) => {
  const transferRef = req.params.transferRef;
  const [rows] = await pool.execute(
    `SELECT id, account_type AS accountType, account_id AS accountId, label, type, amount, is_credit AS isCredit, transfer_ref AS transferRef, created_at AS createdAt
     FROM transactions
     WHERE transfer_ref = ?
     ORDER BY created_at ASC`,
    [transferRef]
  );

  if (rows.length === 0) {
    return res.status(404).json({ error: 'Transfer not found' });
  }

  res.json({ transferRef, entries: rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })) });
}));

app.post('/api/admin/transfers/:transferRef/reverse', requireAdmin, asyncRoute(async (req, res) => {
  const transferRef = req.params.transferRef;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await reverseTransferByRef(conn, transferRef);
    if (!result.ok) {
      await conn.rollback();
      return res.status(result.status).json({ error: result.error });
    }
    await conn.commit();
    await Promise.all([...result.affectedUserIds].map(refreshUserInIndex));
    await logAdmin(req, 'reverse_transfer', 'transfer', transferRef, { reversalTransferRef: result.reversalTransferRef });
    res.json({ ok: true, transferRef, reversalTransferRef: result.reversalTransferRef });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));
const UNDO_WINDOW_MS = 60 * 1000;

app.post('/api/undo', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const stack = getUndoStack(req.userId);
  if (stack.isEmpty()) {
    return res.status(400).json({ error: 'Nothing to undo' });
  }

  const entry = stack.pop(); // LIFO — most recent transfer undone first
  // Undo is only for "oops" moments. After the window closes the money can only
  // be reversed by an admin, so a payment can't be taken back later.
  if (Date.now() - entry.at > UNDO_WINDOW_MS) {
    while (!stack.isEmpty()) stack.pop(); // everything older is expired too
    return res.status(400).json({ error: 'Undo is only available for 60 seconds after a payment' });
  }
  const transferRef = entry.ref;
  let committed = false; // only after commitWithIdempotency returns

  const conn = await pool.getConnection().catch((err) => {
    stack.push(entry);
    throw err;
  });
  try {
    await conn.beginTransaction();
    const result = await reverseTransferByRef(conn, transferRef);
    if (!result.ok) {
      await conn.rollback();
      stack.push(entry); // undo failed — put it back so the user can see why / retry later
      return res.status(result.status).json({ error: result.error });
    }
    const body = { ok: true, undone: transferRef, reversalTransferRef: result.reversalTransferRef };
    await commitWithIdempotency(conn, req, 200, body);
    committed = true;
    await Promise.all([...result.affectedUserIds].map(refreshUserInIndex));
    res.json(body);
  } catch (err) {
    await conn.rollback();
    if (!committed) stack.push(entry);
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- loans (multi-admin verified, like a real loan) ----------
//
// Applying for a loan does NOT touch the user's balance. It creates a
// `pending` row. Each admin can cast exactly one decision on it (enforced
// by the loan_approvals UNIQUE(loan_id, admin_id) constraint, not just a
// UI check). Once the loan's approvals_needed distinct admins have
// approved, it flips to `approved` and the principal is disbursed in the
// same transaction. A single decline closes the loan immediately, no
// further voting possible.
//
// What makes this closer to a real loan instead of "ask for money":
//
// 1. LEGAL / ELIGIBILITY GATE — mirrors what an actual lender checks before
//    accepting an application at all:
//      - applicant must self-declare as 18+ (MIN_AGE)
//      - a government-issued ID number must be provided
//      - the applicant must explicitly acknowledge the loan terms
//      - the account must be at least MIN_ACCOUNT_AGE_DAYS old
//      - no other loan already pending/approved (one active loan at a time)
//      - first-time borrowers are capped at MAX_FIRST_LOAN_AMOUNT_CENTAVOS —
//        real lenders don't require you to already have money in the bank
//        to get a loan, so this is NOT tied to current balance.
//
// 2. TIERED APPROVAL — bigger asks need more sign-offs, i.e. it escalates
//    to more "higher-ups" the larger the loan, via approvalsNeededFor().
//    The number of approvals a given loan needs is decided ONCE at
//    application time and stored on the row (loans.approvals_needed), so
//    it can't drift if the tier thresholds change later.

const MIN_ACCOUNT_AGE_DAYS = 3;
const MIN_AGE = 18;
const MAX_FIRST_LOAN_AMOUNT_CENTAVOS = 1_000_000; // ₱10,000.00
const LOAN_TIER_1_CENTAVOS = 500_000; // ₱5,000.00
const LOAN_TIER_2_CENTAVOS = 2_000_000; // ₱20,000.00

function approvalsNeededFor(amountCentavos) {
  if (amountCentavos <= LOAN_TIER_1_CENTAVOS) return 1;
  if (amountCentavos <= LOAN_TIER_2_CENTAVOS) return 2;
  return 3;
}

app.post('/api/loans', requireAuth, asyncRoute(async (req, res) => {
  const { loanType, amountCentavos, purpose, termMonths, age, governmentId, legalAck } = req.body || {};
  const amt = parseCentavos(amountCentavos);
  const term = Number(termMonths);
  const applicantAge = Number(age);

  if (!loanType || !loanType.toString().trim()) return res.status(400).json({ error: 'A loan platform/type is required' });
  if (amt === null) return res.status(400).json({ error: 'A positive loan amount (integer centavos) is required' });
  if (!purpose || !purpose.toString().trim()) return res.status(400).json({ error: 'A purpose is required' });
  if (!Number.isInteger(term) || term <= 0) return res.status(400).json({ error: 'A valid term (in months) is required' });
  if (!Number.isInteger(applicantAge) || applicantAge <= 0) return res.status(400).json({ error: 'A valid age is required' });
  if (applicantAge < MIN_AGE) return res.status(400).json({ error: `You must be at least ${MIN_AGE} years old to apply for a loan` });
  if (!governmentId || !governmentId.toString().trim()) return res.status(400).json({ error: 'A government-issued ID number is required' });
  if (!legalAck) return res.status(400).json({ error: 'You must acknowledge the loan terms and conditions to proceed' });
  if (amt > MAX_FIRST_LOAN_AMOUNT_CENTAVOS) {
    return res.status(400).json({
      error: `First-time borrowers are capped at ₱${centavosToPesosLabel(MAX_FIRST_LOAN_AMOUNT_CENTAVOS)} — try a smaller amount`,
    });
  }

  const [[user]] = await pool.query('SELECT created_at FROM users WHERE id = ?', [req.userId]);

  const accountAgeDays = (Date.now() - new Date(user.created_at).getTime()) / (1000 * 60 * 60 * 24);
  if (accountAgeDays < MIN_ACCOUNT_AGE_DAYS) {
    return res.status(400).json({
      error: `Your account needs to be at least ${MIN_ACCOUNT_AGE_DAYS} day(s) old before you're eligible for a loan`,
    });
  }

  const [[{ activeCount }]] = await pool.query(
    "SELECT COUNT(*) AS activeCount FROM loans WHERE user_id = ? AND status IN ('pending','approved')",
    [req.userId]
  );
  if (activeCount > 0) {
    return res.status(400).json({ error: 'You already have a pending or active loan — repay or resolve it before applying again' });
  }

 const approvalsNeeded = approvalsNeededFor(amt);
  const [result] = await pool.execute(
    `INSERT INTO loans (user_id, loan_type, amount, purpose, term_months, applicant_age, government_id, legal_ack, approvals_needed)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [
      req.userId,
      cleanText(loanType, 50),
      amt,
      cleanText(purpose, 255),
      term,
      applicantAge,
      governmentId.toString().trim(),
      legalAck ? 1 : 0,
      approvalsNeeded,
    ]
  );

  loanQueue.enqueue({ loanId: result.insertId, userId: req.userId }); // NEW — item: mandatory "Queue"

  res.json({ id: result.insertId, ok: true, approvalsNeeded });
}));

app.get('/api/loans/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.applicant_age AS applicantAge, l.government_id AS governmentId,
            l.amount_repaid AS amountRepaid, l.created_at, l.approvals_needed AS approvalsNeeded,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount
     FROM loans l WHERE l.user_id = ? ORDER BY l.created_at DESC`,
    [req.userId]
  );
  res.json(rows.map((l) => ({ ...l, amount: toCentavos(l.amount), amountRepaid: toCentavos(l.amountRepaid) })));
}));

app.post('/api/loans/:id/repay', requireAuth, moneyLimiter, idempotent, requirePin, asyncRoute(async (req, res) => {
  const loanId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive repayment amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[loan]] = await conn.query('SELECT * FROM loans WHERE id = ? AND user_id = ? FOR UPDATE', [
      loanId,
      req.userId,
    ]);
    if (!loan) {
      await conn.rollback();
      return res.status(404).json({ error: 'Loan not found' });
    }
    if (loan.status !== 'approved') {
      await conn.rollback();
      return res.status(400).json({ error: 'This loan is not active' });
    }

    const [[user]] = await conn.query('SELECT balance, verification_level FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const loanAmount = toCentavos(loan.amount);
    const loanRepaid = toCentavos(loan.amount_repaid);
    const remaining = loanAmount - loanRepaid;
    const applied = Math.min(amt, remaining);
    const limitError = await outgoingLimitError(conn, req.userId, applied, limitsForUser(user.verification_level));
    if (limitError) {
      await conn.rollback();
      return res.status(400).json({ error: limitError });
    }
    const newRepaid = loanRepaid + applied;
    const nowRepaid = newRepaid >= loanAmount;

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [applied, req.userId]);
    await conn.execute('UPDATE loans SET amount_repaid = ?, status = ? WHERE id = ?', [
      newRepaid,
      nowRepaid ? 'repaid' : 'approved',
      loanId,
    ]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Loan Repayment (${cleanText(loan.loan_type, 40)})`, 'Loan Repayment', applied, 0]
    );

    const body = { ok: true, remaining: loanAmount - newRepaid };
    await commitWithIdempotency(conn, req, 200, body);

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json(body);
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// Admin oversight: every loan with how many approvals it has and needs, and
// whether THIS admin has already decided on it (so the UI can hide the
// buttons instead of letting them try to vote twice and get a 409).
app.get('/api/admin/loans', requireAdmin, asyncRoute(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 50));
  const offset = (page - 1) * pageSize;
  const search = req.query.search ? `%${req.query.search.toString().trim()}%` : null;
  const status = ['pending', 'approved', 'declined', 'repaid'].includes(req.query.status) ? req.query.status : null;

  const conditions = [];
  const params = [];
  if (search) { conditions.push('u.username LIKE ?'); params.push(search); }
  if (status) { conditions.push('l.status = ?'); params.push(status); }
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const [[{ total }]] = await pool.query(
    `SELECT COUNT(*) AS total FROM loans l JOIN users u ON u.id = l.user_id ${whereClause}`,
    params
  );

  const [rows] = await pool.query(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.applicant_age AS applicantAge, l.government_id AS governmentId,
            l.amount_repaid AS amountRepaid, l.created_at, l.approvals_needed AS approvalsNeeded, u.username,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount,
            EXISTS(SELECT 1 FROM loan_approvals la WHERE la.loan_id = l.id AND la.admin_id = ?) AS decidedByMe,
            EXISTS(SELECT 1 FROM loan_approvals la WHERE la.loan_id = l.id AND la.admin_id = ? AND la.decision = 'approve') AS approvedByMe
     FROM loans l JOIN users u ON u.id = l.user_id
     ${whereClause}
     ORDER BY (l.status = 'pending') DESC, l.created_at DESC
     LIMIT ? OFFSET ?`,
    [req.adminId, req.adminId, ...params, pageSize, offset]
  );

  const loans = rows.map((l) => ({ ...l, amount: toCentavos(l.amount), amountRepaid: toCentavos(l.amountRepaid) }));

  res.json({ loans, total, page, pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
}));

app.post('/api/admin/loans/:id/respond', requireAdmin, asyncRoute(async (req, res) => {
  const loanId = Number(req.params.id);
  const approve = !!req.body?.approve;

  // Oldest-first is enforced as a *display* priority (see GET /api/admin/loans'
  // ORDER BY and /api/admin/loans/queue/next), not as a hard gate here —
  // with more than one admin online, forcing everyone through a single
  // front-of-queue loan serializes all approval work through one door
  // regardless of admin count. The actual safety against two admins
  // colliding on the *same* loan comes from the row lock + already-voted
  // check just below, not from queue order.

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[loan]] = await conn.query("SELECT * FROM loans WHERE id = ? AND status = 'pending' FOR UPDATE", [
      loanId,
    ]);
    if (!loan) {
      await conn.rollback();
      return res.status(404).json({ error: 'Loan not found or already decided' });
    }

    const [[already]] = await conn.query('SELECT 1 FROM loan_approvals WHERE loan_id = ? AND admin_id = ?', [
      loanId,
      req.adminId,
    ]);
    if (already) {
      await conn.rollback();
      return res.status(409).json({ error: 'You already voted on this loan' });
    }

    await conn.execute('INSERT INTO loan_approvals (loan_id, admin_id, decision) VALUES (?,?,?)', [
      loanId,
      req.adminId,
      approve ? 'approve' : 'decline',
    ]);

    if (!approve) {
      await conn.execute("UPDATE loans SET status = 'declined', decided_at = NOW() WHERE id = ?", [loanId]);
      await conn.commit();
      loanQueue.remove(loanId); // finalized — remove wherever it sits in the queue, not just the front
      await logAdmin(req, 'decline_loan', 'loan', loanId);
      return res.json({ ok: true, status: 'declined' });
    }

    const [[{ approvals }]] = await conn.query(
      "SELECT COUNT(*) AS approvals FROM loan_approvals WHERE loan_id = ? AND decision = 'approve'",
      [loanId]
    );

    if (approvals >= loan.approvals_needed) {
      const loanAmount = toCentavos(loan.amount);
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [loanAmount, loan.user_id]);
      await conn.execute("UPDATE loans SET status = 'approved', decided_at = NOW() WHERE id = ?", [loanId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'user',
          loan.user_id,
          `Loan Disbursed (${loan.term_months}-month term)`,
          'Loan Disbursement',
          loanAmount,
          1,
          JSON.stringify({ purpose: loan.purpose }),
        ]
      );
      await conn.commit();

      await refreshUserInIndex(loan.user_id);
      loanQueue.remove(loanId); // finalized — remove wherever it sits in the queue, not just the front

      await logAdmin(req, 'approve_loan', 'loan', loanId, { amount: loan.amount });
      return res.json({ ok: true, status: 'approved' });
    }

    // Still needs more admin approvals — stays in the queue, since it's
    // not finalized yet.
    await conn.commit();
    await logAdmin(req, 'vote_approve_loan', 'loan', loanId, { approvals });
    res.json({ ok: true, status: 'pending', approvalsCount: approvals, approvalsNeeded: loan.approvals_needed });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/admin/loans/queue/next', requireAdmin, asyncRoute(async (req, res) => {
  const front = loanQueue.peek();
  if (!front) {
    return res.json({ empty: true });
  }

  const [[loan]] = await pool.query(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.approvals_needed AS approvalsNeeded, u.username,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount
     FROM loans l JOIN users u ON u.id = l.user_id
     WHERE l.id = ?`,
    [front.loanId]
  );

  res.json({ empty: false, loan: { ...loan, amount: toCentavos(loan.amount) } });
}));

app.get('/api/admin/accounts/traverse', requireAdmin, (req, res) => {
  const direction = req.query.direction === 'backward' ? 'backward' : 'forward';
  const rows = direction === 'backward' ? accountList.traverseBackward() : accountList.traverseForward();
  res.json({
    direction,
    count: rows.length,
    accounts: rows.map((u) => ({
      id: u.id,
      username: u.username,
      walletId: u.wallet_id,
      balance: toCentavos(u.balance),
    })),
  });
});

app.get('/api/admin/accounts/avl-search/:walletId', requireAdmin, (req, res) => {
  const walletId = normalizePhone(req.params.walletId) || req.params.walletId;
  const account = walletAvl.search(walletId);

  if (!account) {
    return res.status(404).json({ error: 'No account found for that Wallet ID' });
  }

  res.json({
    foundVia: 'AVL tree search',
    treeHeight: walletAvl.height(),
    treeSize: walletAvl.size,
    account: {
      id: account.id,
      username: account.username,
      walletId: account.wallet_id,
      balance: toCentavos(account.balance),
    },
  });
});

// ---------- provider network simulation (item #4 redesign) ----------
//
// This is a SIMULATION only — no real bank/provider API is called. It
// finds the lowest-fee simulated path across a small, static provider
// graph (see graph.js). Every response is explicitly marked
// `simulated: true` so it's never mistaken for a live routing quote.

app.get('/api/routes/providers', requireAuth, (req, res) => {
  res.json(PROVIDERS);
});

app.get('/api/routes/compare', requireAuth, (req, res) => {
  const { source, destination } = req.query;
  if (!source || !destination) {
    return res.status(400).json({ error: 'source and destination provider ids are required' });
  }

  const result = findCheapestRoute(source, destination);
  if (!result) {
    return res.status(404).json({ error: 'No simulated route found between those providers' });
  }

  res.json({ simulated: true, source, destination, ...result });
});

// ---------- admin: identity verification review ----------

app.get('/api/admin/verifications/pending', requireAdmin, asyncRoute(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT id, username, phone_number AS phoneNumber, government_id_number AS governmentIdNumber,
            government_id_photo AS governmentIdPhotoFront, government_id_photo_back AS governmentIdPhotoBack,
            selfie_photo AS selfiePhoto, face_match_confidence AS faceMatchConfidence, created_at AS createdAt
     FROM users
     WHERE verification_status = 'pending'
     ORDER BY created_at ASC`
  );
  res.json(
    rows.map((r) => ({
      ...r,
      governmentIdPhotoFront: decryptPhoto(r.governmentIdPhotoFront),
      governmentIdPhotoBack: decryptPhoto(r.governmentIdPhotoBack),
      selfiePhoto: decryptPhoto(r.selfiePhoto),
    }))
  );
}));

app.post('/api/admin/verifications/:id/respond', requireAdmin, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  const approve = !!req.body?.approve;
  if (!Number.isInteger(userId)) return res.status(400).json({ error: 'Invalid user ID' });

  const [[user]] = await pool.query(
    "SELECT id, verification_status FROM users WHERE id = ?",
    [userId]
  );
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.verification_status !== 'pending') {
    return res.status(409).json({ error: 'This account has already been decided' });
  }

  // The 'pending' check lives in the WHERE clause, so the DATABASE decides
  // which admin wins. Two admins deciding the same account at the same time
  // both run this UPDATE, but only the first one finds a row still in
  // 'pending' and changes it. The second one gets 0 affected rows and is
  // turned away below instead of overwriting the first decision.
  const [decision] = await pool.execute(
    "UPDATE users SET verification_status = ? WHERE id = ? AND verification_status = 'pending'",
    [approve ? 'approved' : 'rejected', userId]
  );
  if (decision.affectedRows === 0) {
    return res.status(409).json({ error: 'This account has already been decided' });
  }
  // The photos were only needed for this review. Delete them once decided.
  if (!KEEP_ID_PHOTOS) {
    await pool.execute(
      "UPDATE users SET government_id_photo = '', government_id_photo_back = '', selfie_photo = '' WHERE id = ?",
      [userId]
    );
  }

  await refreshUserInIndex(userId);
  await logAdmin(req, approve ? 'approve_verification' : 'reject_verification', 'user', userId);
  res.json({ ok: true, status: approve ? 'approved' : 'rejected' });
}));

// Admin review for post-login upgrades. These are separate from the sign-up
// review above: the account is already approved and can log in; only its
// verification_level changes on approval.
app.get('/api/admin/verification-upgrades/pending', requireAdmin, asyncRoute(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT v.id, v.user_id AS userId, u.username, u.wallet_id AS walletId,
            v.upgrade_method AS upgradeMethod,
            v.liveness_status AS livenessStatus,
            v.face_match_confidence AS faceMatchConfidence,
            v.guardian_name AS guardianName,
            v.guardian_relationship AS guardianRelationship,
            v.guardian_face_match_confidence AS guardianFaceMatchConfidence,
            v.government_id_photo AS governmentIdPhotoFront,
            v.government_id_photo_back AS governmentIdPhotoBack,
            v.selfie_photo AS selfiePhoto,
            v.guardian_photo AS guardianPhoto,
            v.guardian_id_photo AS guardianIdPhotoFront,
            v.guardian_id_photo_back AS guardianIdPhotoBack,
            v.birth_certificate_photo AS birthCertificatePhoto,
            v.created_at AS createdAt
       FROM verification_upgrades v
       JOIN users u ON u.id = v.user_id
      WHERE v.status = 'pending'
      ORDER BY v.created_at ASC
      LIMIT 5`
  );
  res.json(
    rows.map((r) => ({
      ...r,
      governmentIdPhotoFront: decryptPhoto(r.governmentIdPhotoFront),
      governmentIdPhotoBack: decryptPhoto(r.governmentIdPhotoBack),
      selfiePhoto: decryptPhoto(r.selfiePhoto),
      guardianPhoto: decryptPhoto(r.guardianPhoto),
      guardianIdPhotoFront: decryptPhoto(r.guardianIdPhotoFront),
      guardianIdPhotoBack: decryptPhoto(r.guardianIdPhotoBack),
      birthCertificatePhoto: decryptPhoto(r.birthCertificatePhoto),
    }))
  );
}));

app.post('/api/admin/verification-upgrades/:id/respond', requireAdmin, asyncRoute(async (req, res) => {
  const upgradeId = Number(req.params.id);
  const approve = !!req.body?.approve;
  if (!Number.isInteger(upgradeId)) return res.status(400).json({ error: 'Invalid upgrade ID' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[upgrade]] = await conn.query(
      'SELECT id, user_id, status, liveness_status, upgrade_method FROM verification_upgrades WHERE id = ? FOR UPDATE',
      [upgradeId]
    );
    if (!upgrade) {
      await conn.rollback();
      return res.status(404).json({ error: 'Verification upgrade not found' });
    }
    if (upgrade.status !== 'pending') {
      await conn.rollback();
      return res.status(409).json({ error: 'This upgrade has already been decided' });
    }

    const [[user]] = await conn.query(
      'SELECT id, verification_level, verification_status FROM users WHERE id = ? FOR UPDATE',
      [upgrade.user_id]
    );
    if (!user) {
      await conn.rollback();
      return res.status(404).json({ error: 'The account for this upgrade no longer exists' });
    }
    if (approve && user.verification_status !== 'approved') {
      await conn.rollback();
      return res.status(409).json({ error: 'This account is not approved, so it cannot become fully verified' });
    }
    if (approve && user.verification_level === 'fully_verified') {
      await conn.rollback();
      return res.status(409).json({ error: 'This account is already fully verified' });
    }

    // The pending predicate is in the WHERE clause as well as the locked row,
    // so two admins racing on the same request cannot both decide it.
    const [decision] = await conn.execute(
      "UPDATE verification_upgrades SET status = ?, reviewed_at = NOW(), reviewed_by = ? WHERE id = ? AND status = 'pending'",
      [approve ? 'approved' : 'rejected', req.adminId, upgradeId]
    );
    if (decision.affectedRows === 0) {
      await conn.rollback();
      return res.status(409).json({ error: 'This upgrade has already been decided' });
    }

    if (approve) {
      await conn.execute(
        "UPDATE users SET verification_level = 'fully_verified', liveness_status = ? WHERE id = ?",
        [upgrade.liveness_status, upgrade.user_id]
      );
    }

    // Photos are only needed for this review. Delete them once decided, exactly
    // like the sign-up review, unless the operator opted to keep them.
    if (!KEEP_ID_PHOTOS) {
      await conn.execute(
        "UPDATE verification_upgrades SET government_id_photo = '', government_id_photo_back = '', selfie_photo = '', guardian_photo = '', guardian_id_photo = '', guardian_id_photo_back = '', birth_certificate_photo = '' WHERE id = ?",
        [upgradeId]
      );
    }

    await conn.commit();
    await refreshUserInIndex(upgrade.user_id);
    await logAdmin(
      req,
      approve ? 'approve_verification_upgrade' : 'reject_verification_upgrade',
      'verification_upgrade',
      upgradeId,
      { userId: upgrade.user_id, upgradeMethod: upgrade.upgrade_method }
    );
    res.json({ ok: true, status: approve ? 'approved' : 'rejected' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin: cash-in review ----------
//
// While demo mode is off (the default), POST /api/cashin/:id/simulate-paid is
// disabled and this route is the only way to move a cash_ins row off 'pending'.
// Without it a cash-in would sit pending until its 24h expiry, so an admin
// confirms real payments here instead.
//
// The amount and the account it credits are read from the locked cash_ins row,
// never from the request body, so a caller cannot choose what gets credited.
// Only a 'pending' row can change state, and the row is locked FOR UPDATE for
// the whole transaction, so two admins racing on the same request cannot both
// succeed and the balance can never be credited twice.
//
// idempotent is deliberately NOT used here: it keys on req.userId, which
// requireAdmin never sets (it sets req.adminId). The FOR UPDATE lock plus the
// pending check is the real double-credit guard for an admin route.

app.get('/api/admin/cashins', requireAdmin, asyncRoute(async (req, res) => {
  const status = String(req.query.status || 'pending');
  const allowed = ['pending', 'completed', 'expired', 'rejected'];
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: 'status must be one of: ' + allowed.join(', ') });
  }

  const [rows] = await pool.query(
    `SELECT c.id, c.user_id AS userId, u.username, c.channel, c.amount, c.reference,
            c.status, c.created_at AS createdAt, c.expires_at AS expiresAt, c.completed_at AS completedAt
       FROM cash_ins c JOIN users u ON u.id = c.user_id
      WHERE c.status = ?
      ORDER BY c.created_at ASC
      LIMIT 200`,
    [status]
  );

  res.json(
    rows.map((r) => ({
      ...r,
      amount: toCentavos(r.amount),
      channelName: CASH_IN_CHANNELS[r.channel] || r.channel,
    }))
  );
}));

app.post('/api/admin/cashins/:id/respond', requireAdmin, asyncRoute(async (req, res) => {
  const cashInId = Number(req.params.id);
  const approve = !!req.body?.approve;
  if (!Number.isInteger(cashInId)) return res.status(400).json({ error: 'Invalid cash-in ID' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[row]] = await conn.query("SELECT * FROM cash_ins WHERE id = ? AND status = 'pending' FOR UPDATE", [
      cashInId,
    ]);
    if (!row) {
      await conn.rollback();
      return res.status(404).json({ error: 'Cash-in request not found or already decided' });
    }
    if (cashInView(row).status === 'expired') {
      await conn.rollback();
      return res.status(400).json({ error: 'This cash-in request has expired and can no longer be approved' });
    }

    if (!approve) {
      await conn.execute("UPDATE cash_ins SET status = 'rejected' WHERE id = ?", [cashInId]);
      await conn.commit();
      await logAdmin(req, 'reject_cash_in', 'cash_in', cashInId, { amount: toCentavos(row.amount) });
      return res.json({ ok: true, status: 'rejected' });
    }

    const [[user]] = await conn.query('SELECT id, balance, verification_level FROM users WHERE id = ? FOR UPDATE', [row.user_id]);
    if (!user) {
      await conn.rollback();
      return res.status(404).json({ error: 'The account for this cash-in no longer exists' });
    }
    const amt = toCentavos(row.amount);
    const limits = limitsForUser(user.verification_level);
    if (toCentavos(user.balance) + amt > limits.maxBalanceCentavos) {
      await conn.rollback();
      return res.status(400).json({ error: `Your wallet can hold at most ${pesoText(limits.maxBalanceCentavos)}.` });
    }

    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, row.user_id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
      ['user', row.user_id, `Cash In via ${CASH_IN_CHANNELS[row.channel] || row.channel}`, 'Cash In', amt, 1, referenceDetails(row.reference)]
    );
    await conn.execute("UPDATE cash_ins SET status = 'completed', completed_at = NOW() WHERE id = ?", [cashInId]);
    await conn.commit();

    await refreshUserInIndex(row.user_id);
    await logAdmin(req, 'approve_cash_in', 'cash_in', cashInId, {
      amount: amt,
      userId: row.user_id,
      reference: row.reference,
    });
    res.json({ ok: true, status: 'completed', creditedCentavos: amt, userId: row.user_id });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin audit log (read only) ----------
//
// Reads the rows logAdmin/logAdminEvent write. Deliberately does NOT call
// logAdmin itself: reading the log must not add a row to it, or every page
// view would produce another entry and the log would grow without bound.
//
// LEFT JOIN, not JOIN: logAdminEvent writes admin_id = NULL for
// 'admin_login_locked', so an inner join would silently drop those rows.
app.get('/api/admin/audit-log', requireAdmin, asyncRoute(async (req, res) => {
  // Garbage gets a clear 400; a valid number out of range is clamped instead.
  let limit = 50;
  if (req.query.limit !== undefined && String(req.query.limit).trim() !== '') {
    const n = Number(String(req.query.limit).trim());
    if (!Number.isInteger(n)) return res.status(400).json({ error: 'limit must be an integer' });
    limit = Math.min(Math.max(n, 1), 200);
  }

  let before = null;
  if (req.query.before !== undefined && String(req.query.before).trim() !== '') {
    const n = Number(String(req.query.before).trim());
    if (!Number.isInteger(n) || n < 1) {
      return res.status(400).json({ error: 'before must be a positive integer id' });
    }
    before = n;
  }

  // Exact match against action VARCHAR(50). Bounded here so a huge value
  // cannot be sent to the database just to match nothing.
  const action = req.query.action === undefined ? '' : String(req.query.action).trim();
  if (action.length > 50) return res.status(400).json({ error: 'action must be at most 50 characters' });

  // Every fragment below is a fixed string; only values are parameterized.
  const where = ['1=1'];
  const params = [];
  if (before !== null) {
    where.push('l.id < ?');
    params.push(before);
  }
  if (action) {
    where.push('l.action = ?');
    params.push(action);
  }
  // One extra row tells us whether another page exists without a COUNT(*).
  params.push(limit + 1);

  const [rows] = await pool.query(
    `SELECT l.id, a.username AS adminUsername, l.action,
            l.target_type AS targetType, l.target_id AS targetId,
            l.details, l.ip, l.created_at AS createdAt
       FROM admin_audit_log l
       LEFT JOIN admins a ON a.id = l.admin_id
      WHERE ${where.join(' AND ')}
      ORDER BY l.id DESC
      LIMIT ?`,
    params
  );

  const hasMore = rows.length > limit;
  const entries = hasMore ? rows.slice(0, limit) : rows;
  // details is passed through untouched. It is JSON written by logAdmin, and
  // the admin panel must escape it before rendering; see esc() there.
  res.json({
    entries,
    hasMore,
    nextBefore: hasMore && entries.length ? entries[entries.length - 1].id : null,
  });
}));

// This must be registered AFTER every route above it — Express matches
// error-handling middleware (4-arg signature) only for errors that occur
// during/after routes already registered before it in the file.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------- WebSocket server: live balance updates ----------
// Wrapping the Express app in a plain http.Server lets the same port
// serve both the REST API and the WebSocket upgrade at /ws — no second
// port/process to deploy or configure.
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 4096 });

// The session token is NOT taken from the URL (web addresses end up in proxy
// and server logs). The client connects, then must send
//   {"type":"auth","token":"<jwt>"}
// as its first message within 5 seconds, or it is disconnected. The token is
// checked with the same rules as requireAuth: full stage, user role, an
// unsuspended account, and a current session version.
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  const authTimer = setTimeout(() => ws.close(4001, 'Not authenticated'), 5000);
  ws.on('close', () => clearTimeout(authTimer));
  ws.on('error', () => clearTimeout(authTimer));

  ws.once('message', async (data) => {
    clearTimeout(authTimer);
    let userId;
    try {
      const msg = JSON.parse(data.toString());
      const payload = msg && msg.type === 'auth' ? verify(msg.token) : null;
      if (!payload || payload.stage !== 'full' || payload.role !== 'user') {
        ws.close(4001, 'Not authenticated');
        return;
      }
      // Same revocation rule as requireAuth: the token's session version must
      // still match the account, and a suspended account is refused. Every
      // rejection reuses the close code above, so the client has one failure
      // path and nothing about account status is exposed.
      const [[row]] = await pool.query('SELECT status, session_version FROM users WHERE id = ?', [payload.uid]);
      if (!row || row.status === 'suspended' || (payload.sv ?? 0) !== row.session_version) {
        ws.close(4001, 'Not authenticated');
        return;
      }
      userId = payload.uid;
    } catch {
      ws.close(4001, 'Not authenticated');
      return;
    }

    registerSocket(userId, ws);
    ws.on('close', () => unregisterSocket(userId, ws));
    ws.on('error', () => unregisterSocket(userId, ws));

    // Send the current balance immediately, so the client has a correct
    // number even if it connects between polls/actions.
    pool
      .query('SELECT balance FROM users WHERE id = ?', [userId])
      .then(([[row]]) => {
        if (row) pushToUser(userId, { type: 'balance', balanceCentavos: toCentavos(row.balance) });
      })
      .catch(() => {});
  });
});

// Phones and flaky networks often drop a WebSocket without a clean close
// frame. Ping every 30s and terminate anything that didn't pong back
// since the last check, so userSockets doesn't accumulate dead entries.
const wsHeartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);
wss.on('close', () => clearInterval(wsHeartbeat));

const port = process.env.PORT || 3000;
(async () => {
  // First deploy on a new, empty database: set AUTO_SETUP_DB=true once and the
  // tables are created before anything tries to read them.
  if (process.env.AUTO_SETUP_DB === 'true') {
    await require('./setup-db').setupDatabase();
  }
  await Promise.all([
    loadIndexesFromDatabase(),
    loadLoanQueueFromDatabase(),
    loadAccountListFromDatabase(),
    loadWalletAvlFromDatabase(),
  ]);
  server.listen(port, () => console.log(`PayCST backend listening on port ${port} (HTTP + WebSocket /ws)`));
})().catch((err) => {
  console.error('Startup failed:', err.message);
  process.exit(1);
});

// ---------- provider network simulation and DB migration notes below are unchanged ----------