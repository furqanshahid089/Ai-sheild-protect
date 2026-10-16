# AI Shield Protector

A defensive cybersecurity web app that analyzes **suspicious URLs** and **scam messages** for
common phishing and fraud warning signs, explains *why* something looks risky, and suggests safe
next steps.

Built with a **Node.js / Express** backend (JavaScript) and a **plain HTML + CSS + vanilla JS**
frontend. No Python, no frontend framework, no build step.

> **What it is NOT.** This tool highlights warning signs using heuristics and transparent rules.
> It **cannot detect every threat** and **cannot guarantee** that any link or message is safe or
> malicious. It never opens links, fetches pages, runs scripts, or downloads files. Always use your
> own judgment and verify through trusted channels.

---

## Features

- **URL Scanner** – inspects the link *text only* for: invalid syntax, HTTP vs HTTPS, raw IP hosts,
  `@` obfuscation, punycode/IDN, excessive subdomains, brand-in-subdomain impersonation, unusual
  ports, suspicious TLDs, URL shorteners, heavy encoding, and credential keywords.
- **Message Scanner** – rule-based detection of urgency, account threats, credential/OTP requests,
  unusual payments, prize bait, impersonation, and risky embedded links.
- **Dashboard** – real statistics from your own scans (never fabricated), risk distribution, recent
  activity, and quick actions.
- **Scan History** – paginated, with per-record delete and "clear all".
- **Privacy controls** – message content is **not stored by default**; configurable retention.
- **Threat Education Center** – plain-language guidance on common scams.
- **Optional AI explanations** and **threat-intel hooks** – off by default, degrade gracefully.
- **Accessible, responsive UI** – keyboard navigation, focus states, dark/light themes, risk shown
  with text + icons (never color alone), reduced-motion support.

---

## Architecture

```
Ai sheild protect/
├─ package.json            # scripts + dependencies
├─ .env.example            # configuration template (copy to .env)
├─ src/                    # backend (Express)
│  ├─ server.js            # app entry: security headers, CORS, rate limit, static + API
│  ├─ config.js            # env-driven config + risk categories
│  ├─ db.js                # SQLite (better-sqlite3): scans + settings, privacy-aware
│  ├─ routes/api.js        # versioned REST API (/api/v1)
│  ├─ analysis/
│  │  ├─ scoring.js        # severity weights -> 0-100 score + category
│  │  ├─ urlAnalyzer.js    # deterministic URL heuristics (text only)
│  │  └─ messageAnalyzer.js# rule-based scam message analysis
│  └─ services/
│     ├─ aiExplainer.js    # optional, provider-independent AI explanation
│     └─ threatIntel.js    # optional reputation lookup (allowlisted, no SSRF)
├─ public/                 # frontend (static)
│  ├─ index.html           # app shell + sidebar nav
│  ├─ styles.css           # design system
│  ├─ lib.js               # API client, escaping, result rendering
│  └─ app.js               # hash router + all views
└─ test/                   # Node built-in test runner
   ├─ urlAnalyzer.test.js
   ├─ messageAnalyzer.test.js
   └─ api.test.js
```

---

## Prerequisites

- **Node.js 20 or newer** (uses built-in `node --test`, `fetch`, and `--watch`).
  Download from <https://nodejs.org/> (LTS). Verify with:

  ```powershell
  node --version
  npm --version
  ```

> If `node` is "not recognized", Node.js is not installed or not on your PATH. Install the LTS
> build and reopen your terminal.

---

## Local setup

```powershell
# 1. Install dependencies
npm install

# 2. (optional) create your env file
copy .env.example .env     # Windows PowerShell
# cp .env.example .env     # macOS/Linux

# 3. Start the app
npm start
```

Then open <http://localhost:3000>.

For auto-reload during development:

```powershell
npm run dev
```

---

## Environment variables

See `.env.example` for the full list. Highlights:

| Variable                 | Default        | Purpose                                             |
|--------------------------|----------------|-----------------------------------------------------|
| `PORT`                   | `3000`         | HTTP port                                           |
| `DATABASE_FILE`          | `ai_shield.db` | SQLite file path                                    |
| `CORS_ORIGINS`           | *(empty)*      | Comma-separated allowed origins (else same-origin)  |
| `STORE_MESSAGE_CONTENT`  | `false`        | Store scanned message text (off = data minimization)|
| `HISTORY_RETENTION_DAYS` | `0`            | Auto-purge records older than N days (0 = keep)     |
| `RATE_LIMIT_MAX`         | `60`           | Requests per window per client                      |
| `AI_ENABLED` / `AI_API_KEY` | `false` / —  | Optional AI explanations (server-side only)         |
| `THREAT_INTEL_*`         | off            | Optional reputation provider (allowlisted)          |

**Secrets** (`AI_API_KEY`, `THREAT_INTEL_API_KEY`) are read on the server only and are never sent to
the browser or returned in API responses.

---

## Database

SQLite is created automatically on first run (`better-sqlite3`). Schema: `scans` and `settings`
tables with indexes on `created_at` and `type`.

**Migration path to PostgreSQL:** the data layer is isolated in `src/db.js`. To migrate, swap
`better-sqlite3` for a Postgres client (e.g. `pg`), keep the same exported functions
(`saveScan`, `listScans`, `getScan`, `deleteScan`, `getStats`, `getSetting`, `setSetting`), and
adjust the SQL (parameter placeholders and `RETURNING`). Callers do not change.

---

## Development commands

| Command         | What it does                      |
|-----------------|-----------------------------------|
| `npm start`     | Run the server                    |
| `npm run dev`   | Run with auto-reload (`--watch`)  |
| `npm test`      | Run the test suite (`node --test`)|

---

## Testing

```powershell
npm test
```

Covers valid/invalid/malformed URLs, suspicious indicators, ordinary URLs that must *not* be flagged
malicious, scam-message indicators, harmless messages, data-minimization (content not stored),
list/get/delete, stats, settings validation, input-size limits, and API response shapes. Tests use
synthetic examples and example/authorized domains only — they never contact real targets.

---

## API endpoints

Base path: `/api/v1`

| Method & path                | Description                          |
|------------------------------|--------------------------------------|
| `GET /health`                | Service + integration status         |
| `POST /scans/url`            | Analyze a URL                        |
| `POST /scans/message`        | Analyze a message                    |
| `GET /scans`                 | List scans (paginated)               |
| `GET /scans/:id`             | Get one scan                         |
| `DELETE /scans/:id`          | Delete one scan                      |
| `DELETE /scans`              | Clear all scans                      |
| `GET /stats`                 | Dashboard statistics                 |
| `GET /settings`              | Read settings                        |
| `PATCH /settings`            | Update allowed settings              |

Errors use a consistent shape: `{ "error": { "message": "..." } }`.

---

## Privacy practices

- Scans run on your own instance; data is stored locally in SQLite.
- **Message content is not stored by default.** Only risk metadata (category, score, findings) is
  kept unless you enable `STORE_MESSAGE_CONTENT`.
- Disabling content storage also purges previously stored content.
- Submitted URLs are inspected as text and are never opened or fetched.
- The server avoids logging message contents or secrets.

---

## Security notes & limitations

- Security headers via Helmet (incl. a restrictive Content-Security-Policy), restrictive CORS, JSON
  body size cap, rate limiting, and consistent error handling (no stack traces to clients).
- Input is validated on the backend; output is HTML-escaped on the frontend to prevent XSS.
- SQL uses parameterized statements (no string concatenation).
- The threat-intel layer uses a strict provider allowlist and never fetches user-controlled URLs
  (SSRF-safe). No live threat feed is simulated.
- **No authentication in this release.** It runs in local/anonymous mode by design, so no
  credentials or personal profiles are collected until auth can be built to a production standard.
- This is a heuristic helper, not a malware scanner or a guarantee of safety.

---

## Deployment

The app is a single Node process serving both API and static assets, so it runs on most Node hosts
(Replit, Render, Railway, a VM, etc.):

1. Set environment variables (at minimum `PORT`; configure optional keys if used).
2. `npm install`
3. `npm start`

On Replit: set the run command to `npm start` and expose the web port. Add any API keys via Replit
Secrets (not in code).

---

## Troubleshooting

- **`node` / `npm` not recognized** – install Node.js LTS and reopen the terminal.
- **`better-sqlite3` install fails** – it ships prebuilt binaries for common platforms; ensure you
  are on Node 20+. On some systems you may need build tools; see the package docs.
- **Port in use** – set a different `PORT` in `.env`.
- **AI explanation never appears** – it is off unless `AI_ENABLED=true` and a valid `AI_API_KEY`
  are set. The core scanners work without it.

---

## License

MIT.
