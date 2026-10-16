import process from 'node:process';

function bool(value, fallback) {
  if (value === undefined) return fallback;
  return String(value).toLowerCase() === 'true' || value === '1';
}

function int(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

export const config = {
  appName: 'AI Shield Protector',
  version: '1.0.0',
  environment: process.env.NODE_ENV || 'development',
  port: int(process.env.PORT, 3000),

  // Database
  databaseFile: process.env.DATABASE_FILE || 'ai_shield.db',

  // CORS - comma separated allowed origins. Empty = same-origin only.
  corsOrigins: (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  // Request limits
  maxRequestBytes: int(process.env.MAX_REQUEST_BYTES, 64_000),
  maxUrlLength: int(process.env.MAX_URL_LENGTH, 2048),
  maxMessageLength: int(process.env.MAX_MESSAGE_LENGTH, 20_000),

  // Privacy - message content is NOT stored by default (data minimization)
  storeMessageContent: bool(process.env.STORE_MESSAGE_CONTENT, false),
  historyRetentionDays: int(process.env.HISTORY_RETENTION_DAYS, 0),

  // Rate limiting
  rateLimitWindowMs: int(process.env.RATE_LIMIT_WINDOW_MS, 60_000),
  rateLimitMax: int(process.env.RATE_LIMIT_MAX, 60),

  // Optional AI explanation provider (server-side only)
  ai: {
    enabled: bool(process.env.AI_ENABLED, false),
    provider: process.env.AI_PROVIDER || 'openai',
    apiKey: process.env.AI_API_KEY || '',
    model: process.env.AI_MODEL || 'gpt-4o-mini',
    timeoutMs: int(process.env.AI_TIMEOUT_MS, 12_000),
  },

  // Optional threat-intelligence provider (strict allowlist of provider ids)
  threatIntel: {
    enabled: bool(process.env.THREAT_INTEL_ENABLED, false),
    provider: process.env.THREAT_INTEL_PROVIDER || '',
    apiKey: process.env.THREAT_INTEL_API_KEY || '',
    timeoutMs: int(process.env.THREAT_INTEL_TIMEOUT_MS, 8_000),
  },
};

// Risk categories used across the app. These describe indicators found,
// NOT a guarantee that a site/message is safe or malicious.
export const RISK_CATEGORIES = {
  LOW: 'Low Risk Indicators',
  SUSPICIOUS: 'Suspicious',
  HIGH: 'High Risk Indicators',
  UNKNOWN: 'Unknown / Insufficient Evidence',
};
