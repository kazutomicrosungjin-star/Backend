# PayCST Backend — Agent Guide

Node + Express 4 + MySQL. CommonJS. One process, deployed to Railway.

## Layout

| Path | Role |
|---|---|
| `server.js` | 3,600 lines. All 71 `/api/*` routes, middleware, auth, helpers. |
| `db.js` | Exports the `mysql2/promise` pool. The only place a connection is made. |
| `schema.sql` | Source of truth for tables. Read before writing any query. |
| `avl.js` `dll.js` `mergeSort.js` `stack.js` `queue.js` | Hand-written data structures. Required by the spec — do not replace with plain arrays. |
| `graph.js` `movies.js` `sms.js` | Providers, TMDB lookup, Semaphore SMS. |
| `setup-db.js` `create-admin.js` `clear-faces.js` | Ops scripts. |
| `env.example` | Every env var the server reads. Copy to `.env`. |

### Where to find things in `server.js`

Marker → line number, measured 2026-10-16. **Line numbers drift** — re-run the
command below instead of trusting a copied number:

```bash
grep -n "^// ---------" server.js
```

Route mix: 29 `app.get`, 40 `app.post`, 2 `app.delete`, no `put`/`patch` — 71
`/api/*` routes in total. There are no non-`/api` routes; the only `app.use`
calls are `helmet`, `cors`, the JSON body parsers, and the error handler.

| Line | Section | Line | Section |
|---|---|---|---|
| 27 | pending-loan queue (FIFO) | 1436 | request money |
| 43 | account doubly linked list | 1576 | account limits |
| 57 | wallet-ID AVL tree | 1588 | cash in (simulated) |
| 69 | per-user undo stacks (LIFO) | 1750 | `// ---- unchanged ----` band |
| 101 | security middleware | 1765 | `// ---- end unchanged ----` |
| 214 | in-memory indexes | 2091 | groups (MAX_GROUP_MEMBERS cap) |
| 232 | live balance push (WebSocket) | 2374 | savings goals |
| 298 | money handling: integer centavos | 2541 | admin: login + final say on groups |
| 336 | wallet limits + reference numbers | 2821 | admin transfer reversal |
| 378 | double-charge protection | 2823 | shared reversal core |
| 510 | extra hardening helpers | 2962 | loans (multi-admin verified) |
| 631 | database-backed login lockout | 3324 | provider network simulation |
| 680 | Face++ face-matching | 3349 | admin: identity verification review |
| 743 | Face++ duplicate-face check | 3401 | admin: cash-in review |
| 810 | phone verification (SMS code) | 3514 | WebSocket server: live balance updates |
| 950 | registration / login (password, THEN pin) | 3600 | trailing notes (end of file) |
| 1261 | fingerprint / device login | | |
| 1355 | wallet-to-wallet (QR) payment | | |
| 1430 | personal-account actions | | |

The four in-memory structures (L27, L43, L57, L69) are the ones that must stay
in sync with the database on every write — see the table in "In-memory indexes"
below. `AUTO_SETUP_DB` bootstraps the schema from L3585 via `require('./setup-db')`,
which is why `schema.sql` must stay next to `setup-db.js`.

## Commands

```bash
npm install
npm start                # node server.js
npm run setup-db         # create tables from schema.sql
npm run create-admin     # node create-admin.js <username> <password> <4-digit-pin>
```

**There is no test runner and no linter configured.** Verify changes by running
`npm start` and exercising the endpoint with `curl` against a local MySQL.

## Rules that must not be broken

1. **Every SQL query is parameterized.** Use `?` placeholders with an array:
   `pool.query('SELECT * FROM users WHERE id = ?', [id])`.
   Never interpolate user input into SQL text — not with template literals, not
   with `.replace()`.

2. **Never commit `.env`.** It is gitignored. `JWT_SECRET` must be 32+ random
   chars. `PHOTO_ENCRYPTION_KEY` must be 64 hex chars, set **before the first
   sign-up**, and never changed — changing it makes every stored ID photo
   permanently unreadable.

3. **Never log or return secrets, PIN hashes, ID photos, or JWTs** in a response
   body or error message.

4. **Money is an integer number of centavos** everywhere in transit and storage
   (`parseCentavos` / `toCentavos`). Never use a float for a balance.

## Route conventions

Mount new routes under `/api/`. Compose middleware in this order:

```js
app.post('/api/wallet/pay', requireAuth, moneyLimiter, idempotent, requirePin,
  asyncRoute(async (req, res) => { ... }));
```

- `requireAuth` — JWT must verify. Sets `req.userId`.
- `requireAdmin` — JWT must be `role: 'admin'` **and** `stage: 'full'`. Sets `req.adminId`.
- `moneyLimiter` — rate limit for balance-touching routes.
- `idempotent` — accepts an `Idempotency-Key` header so a retry cannot double-charge.
- `requirePin` — re-checks the 4-digit PIN. **Required on every money movement**,
  so a stolen login token alone cannot drain a wallet.
- `asyncRoute(fn)` — wraps an async handler so rejections reach the error middleware.

Wrap the handler body in `asyncRoute` rather than hand-writing try/catch.

## Input handling

- Free text admins will read (group names, reasons, loan purpose) goes through
  `cleanText(value, max)` — trims, length-caps, and strips `<`, `>`, and control
  characters so nothing can carry HTML into the admin panel.
- IDs and numbers must be validated explicitly; do not assume a value is present
  because a client sent it.

## Auth model

Login is deliberately two-stage: **password, then PIN**, before a usable token is
issued. The token's `stage` reflects how far the user got (`password` vs `full`).
Brute force is stopped in two places: `express-rate-limit` in memory (resets on
redeploy) and `login_attempts` in MySQL (durable), with escalating `LOCKOUT_TIERS`.
When changing lockout behaviour, change both and keep the durable one authoritative.

## Cash-in lifecycle

`POST /api/cashin` inserts a `cash_ins` row with a reference number and a
24-hour expiry (`NOW() + INTERVAL ${CASH_IN_TTL_HOURS} HOUR`, server.js L1597).
It does not pass `status`, so the row takes the column default `'pending'`
(L1606). There is **no payment gateway wired up**, so the row does not complete
on its own:

- `POST /api/cashin/:id/simulate-paid` pretends the payment arrived, but it is
  gated on `DEMO_MODE`, which is **off unless the env var is exactly `true`**
  (server.js L1594). With demo mode off it returns `403`.
- In that state the only way off `pending` is an admin calling
  `POST /api/admin/cashins/:id/respond` (server.js L3444), or the row expiring
  after 24 hours. `GET /api/admin/cashins` lists what is waiting.

The admin route reads the amount and the credited account from the locked
`cash_ins` row, never from the request body, so a caller cannot choose what gets
credited. Do not "simplify" the 403 on `simulate-paid` into a success path — it is
the guard that stops a logged-in user crediting themselves.

## In-memory indexes

These are loaded from the DB on boot and mutated alongside the database:

| Structure | Purpose |
|---|---|
| `walletAvl` | AVLTree keyed by `wallet_id` for O(log n) wallet lookup |
| `accountList` | DoublyLinkedList of all accounts |
| `loanQueue` | FIFO of pending loans, admin processes oldest-first |
| `undoStacks` | Per-user LIFO stack of `transferRef`s for `/api/undo` |

**Any code that mutates `users` or `loans` must update the matching structure in
the same request**, or the indexes silently diverge from the database. This is the
single most common bug class in this codebase — check it on every write path.

## WebSocket

`ws` is mounted at `/ws` with `maxPayload: 4096` and a heartbeat that drops dead
sockets. Send only small JSON notifications; anything large belongs in a
`GET /api/...` poll.

## Client contract

`flutter_ewalletdemo_app/lib/main.dart` calls this server. `apiBase` in that file
is a `const` pointing at the deployed host — changing a request shape here means
changing `_post`/`_get` in `BankState` there too. Keep the two in step.