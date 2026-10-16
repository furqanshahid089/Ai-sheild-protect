// AI Shield Protector - Express server entry point.
// Serves the static frontend and the versioned JSON API.

import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config } from './config.js';
import { api } from './routes/api.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, '..', 'public');

const app = express();
app.disable('x-powered-by');

// --- Security headers (CSP tuned for same-origin assets) ---
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
  }),
);

// --- CORS (restrictive; only configured origins, else same-origin) ---
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && config.corsOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- Body parsing with a strict size cap ---
app.use(express.json({ limit: config.maxRequestBytes }));

// --- Rate limiting on the API ---
const limiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many requests. Please slow down.' } },
});
app.use('/api/', limiter);

// --- API routes ---
app.use('/api/v1', api);

// --- Static frontend ---
app.use(express.static(publicDir, { extensions: ['html'] }));

// SPA-ish fallback: serve index.html for non-API, non-file GET routes.
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(publicDir, 'index.html'));
});

// --- JSON body parse / payload-too-large error handler ---
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: { message: 'Request body too large.' } });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { message: 'Invalid JSON body.' } });
  }
  // Do not leak stack traces to clients.
  if (config.environment !== 'production') console.error(err);
  res.status(500).json({ error: { message: 'Internal server error.' } });
});

export { app };

// Start the server unless imported by tests.
if (process.env.NODE_ENV !== 'test') {
  app.listen(config.port, () => {
    // eslint-disable-next-line no-console
    console.log(`${config.appName} running on http://localhost:${config.port}`);
  });
}
