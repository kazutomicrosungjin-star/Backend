# PayCST backend

Node + Express + MySQL. Start with `npm install` then `npm start`.

## Set up a new copy
1. Create an empty MySQL database (Railway: **+ New > Database > MySQL**).
2. Set `AUTO_SETUP_DB=true` on the service for the first deploy: the server then creates all tables itself from `schema.sql`. (Or run `npm run setup-db`.)
3. Copy `env.example` to `.env` (local) or add the same names as variables on your host:
   `DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME JWT_SECRET FACEPP_API_KEY FACEPP_API_SECRET`
   - `JWT_SECRET` must be 32+ random characters and kept private:
     `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
   - `PHOTO_ENCRYPTION_KEY`: 64 random hex characters (same generator command). Encrypts ID photos waiting for review. Set it BEFORE the first sign-up and never change it afterwards, or old photos can't be shown.
   - Optional: `CORS_ORIGIN`, `DB_SSL=true` (if the DB is on another network), `KEEP_ID_PHOTOS=true`.
   - `DEMO_MODE` is off unless it is exactly `true`. Leave it unset or `false` on
     any real deployment: it gates a demo button that would let a logged-in user
     credit themselves. With it off, an admin confirms each cash in via
     `POST /api/admin/cashins/:id/respond`.
4. Create the first admin: `node create-admin.js <username> <password> <4-digit-pin>`
5. Point the Flutter app's `apiBase` (and the admin panel) at `https://<your-domain>/api`.

Never commit `.env`.
