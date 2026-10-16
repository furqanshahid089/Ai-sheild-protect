// Versioned REST API: /api/v1/*
// Consistent JSON error responses, typed-ish validation, no secrets leaked.

import express from 'express';
import { config } from '../config.js';
import { analyzeUrl } from '../analysis/urlAnalyzer.js';
import { analyzeMessage } from '../analysis/messageAnalyzer.js';
import { explainAnalysis, isAiAvailable } from '../services/aiExplainer.js';
import {
  lookupReputation,
  isThreatIntelAvailable,
} from '../services/threatIntel.js';
import {
  saveScan,
  listScans,
  getScan,
  deleteScan,
  clearScans,
  getStats,
  getAllSettings,
  setSetting,
} from '../db.js';

export const api = express.Router();

function fail(res, status, message, details) {
  return res.status(status).json({
    error: { message, ...(details ? { details } : {}) },
  });
}

// --- Health ---
api.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    app: config.appName,
    version: config.version,
    time: new Date().toISOString(),
    integrations: {
      ai: isAiAvailable(),
      threatIntel: isThreatIntelAvailable(),
    },
  });
});

// --- URL scan ---
api.post('/scans/url', async (req, res) => {
  const { url, explain } = req.body || {};
  if (typeof url !== 'string' || !url.trim()) {
    return fail(res, 400, 'A non-empty "url" string is required.');
  }
  if (url.length > config.maxUrlLength) {
    return fail(res, 413, `URL exceeds ${config.maxUrlLength} characters.`);
  }

  const analysis = analyzeUrl(url, { maxUrlLength: config.maxUrlLength });

  if (analysis.valid && analysis.host) {
    analysis.reputation = await lookupReputation(analysis.host);
  }
  if (explain === true) {
    analysis.aiExplanation = await explainAnalysis(analysis);
  }

  let saved = null;
  if (analysis.valid) {
    // URLs are low-PII; store the normalized URL as summary only.
    saved = saveScan(analysis, { content: null });
  }

  res.json({ scan: { id: saved?.id ?? null, createdAt: saved?.createdAt ?? null }, analysis });
});

// --- Message scan ---
api.post('/scans/message', async (req, res) => {
  const { message, explain } = req.body || {};
  if (typeof message !== 'string' || !message.trim()) {
    return fail(res, 400, 'A non-empty "message" string is required.');
  }
  if (message.length > config.maxMessageLength) {
    return fail(res, 413, `Message exceeds ${config.maxMessageLength} characters.`);
  }

  const analysis = analyzeMessage(message, {
    maxMessageLength: config.maxMessageLength,
  });

  if (explain === true) {
    analysis.aiExplanation = await explainAnalysis(analysis);
  }

  let saved = null;
  if (analysis.valid) {
    // Content is only persisted if the privacy setting explicitly allows it.
    saved = saveScan(analysis, { content: message });
  }

  res.json({ scan: { id: saved?.id ?? null, createdAt: saved?.createdAt ?? null }, analysis });
});

// --- List scans (paginated) ---
api.get('/scans', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const type = req.query.type === 'url' || req.query.type === 'message'
    ? req.query.type
    : undefined;
  res.json(listScans({ limit, offset, type }));
});

// --- Get one scan ---
api.get('/scans/:id', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return fail(res, 404, 'Scan not found.');
  res.json(scan);
});

// --- Delete one scan ---
api.delete('/scans/:id', (req, res) => {
  const ok = deleteScan(req.params.id);
  if (!ok) return fail(res, 404, 'Scan not found.');
  res.json({ deleted: true, id: req.params.id });
});

// --- Clear all history ---
api.delete('/scans', (req, res) => {
  const count = clearScans();
  res.json({ cleared: count });
});

// --- Stats for dashboard ---
api.get('/stats', (req, res) => {
  res.json(getStats());
});

// --- Settings ---
api.get('/settings', (req, res) => {
  res.json(getAllSettings());
});

const ALLOWED_SETTINGS = new Set([
  'store_message_content',
  'history_retention_days',
  'theme',
]);

api.patch('/settings', (req, res) => {
  const body = req.body || {};
  const updates = {};
  for (const [key, value] of Object.entries(body)) {
    if (!ALLOWED_SETTINGS.has(key)) {
      return fail(res, 400, `Unknown setting "${key}".`);
    }
    updates[key] = setSetting(key, value);
  }
  res.json(getAllSettings());
});

// 404 for unknown API routes
api.use((req, res) => fail(res, 404, 'API endpoint not found.'));
