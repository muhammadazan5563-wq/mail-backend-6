# Equinox Mail — Backend (Railway)

Express API for Equinox Mail. Handles Google OAuth (Gmail), contacts/campaigns/
accounts storage, an offline email-validation engine (DNS/MX + heuristics, **no
external AI / Gemini**), and a background poller that sends queued campaign
emails.

This service is fully self-contained. Pair it with the `equinox-mail-frontend`
package (deployed on Vercel).

## Run locally

```bash
npm install
npm run dev        # API on http://localhost:3000
```

## Build & start (production)

```bash
npm install
npm run build      # bundles to dist/server.cjs
npm run start      # NODE_ENV=production node dist/server.cjs
```

## Deploy to Railway

1. Create a new Railway project and deploy this folder (push it to a Git repo or
   use `railway up`). `railway.json` already sets build (`npm run build`) and
   start (`npm run start`).
2. Add a **Volume** mounted at `/data` and set `DATA_DIR=/data` so connected
   accounts, campaigns, and logs persist across restarts/redeploys.
3. Set environment variables (see `.env.example`):
   - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
   - `APP_URL` = your Railway public URL (e.g. `https://your-app.up.railway.app`)
   - `CORS_ORIGIN` = your Vercel frontend URL
4. Railway provides `PORT` automatically.

## Google OAuth

In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
add this to the OAuth client's **Authorized redirect URIs**:

```
https://your-app.up.railway.app/api/auth/callback
```

The exact URI is also shown in the frontend's **Accounts** tab.

## Environment variables

See [`.env.example`](./.env.example).
