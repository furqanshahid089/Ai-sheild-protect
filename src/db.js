// Lightweight, dependency-free persistence layer (pure JavaScript).
//
// Stores scan history and settings in a local JSON file. This avoids any
// native build step (no compiler / Visual Studio required) while keeping the
// exact same exported API, so the rest of the app does not change. The data
// layer is isolated here, so swapping to SQLite/PostgreSQL later only touches
// this file.
//
// Privacy by design:
// - Message CONTENT is never stored unless STORE_MESSAGE_CONTENT=true.
// - Only risk metadata (category, score, findings summary) is kept by default.
// - Retention can be enforced via HISTORY_RETENTION_DAYS.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from './config.js';

let state = null;
let filePath = null;

function resolveFile() {
  // Reuse DATABASE_FILE but store JSON; normalize a .db suffix to .json.
  const base = config.databaseFile || 'ai_shield.db';
  return path.resolve(base.replace(/\.db$/i, '') + '.json');
}

function defaultState() {
  return {
    scans: [],
    settings: {
      store_message_content: String(config.storeMessageContent),
      history_retention_days: String(config.historyRetentionDays),
      theme: 'dark',
    },
  };
}

function load() {
  if (state) return state;
  filePath = resolveFile();
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      state = {
        scans: Array.isArray(parsed.scans) ? parsed.scans : [],
        settings: { ...defaultState().settings, ...(parsed.settings || {}) },
      };
    } else {
      state = defaultState();
      persist();
    }
  } catch {
    // Corrupt or unreadable file: start fresh rather than crash.
    state = defaultState();
  }
  return state;
}

function persist() {
  if (!filePath) filePath = resolveFile();
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state), 'utf8');
  fs.renameSync(tmp, filePath); // atomic-ish write
}

// Exposed so tests can reset between runs if needed.
export function _resetForTests() {
  state = null;
  filePath = null;
}

export function saveScan(analysis, { content } = {}) {
  const s = load();
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  const storeContent = getSetting('store_message_content') === 'true';
  const storedContent = storeContent && content ? content : null;

  const summary =
    analysis.type === 'url'
      ? analysis.normalizedUrl || analysis.reason || ''
      : `${analysis.findings.length} indicator(s)`;

  s.scans.push({
    id,
    type: analysis.type,
    category: analysis.category,
    score: analysis.score,
    summary,
    findings: analysis.findings,
    content: storedContent,
    created_at: createdAt,
  });

  enforceRetention();
  persist();
  return { id, createdAt };
}

function sortedDesc(scans) {
  return [...scans].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
}

export function listScans({ limit = 20, offset = 0, type } = {}) {
  const s = load();
  let items = sortedDesc(s.scans);
  if (type) items = items.filter((x) => x.type === type);
  const total = items.length;
  const page = items.slice(offset, offset + limit).map((x) => ({
    id: x.id,
    type: x.type,
    category: x.category,
    score: x.score,
    summary: x.summary,
    created_at: x.created_at,
  }));
  return { items: page, total, limit, offset };
}

export function getScan(id) {
  const s = load();
  const row = s.scans.find((x) => x.id === id);
  return row ? { ...row } : null;
}

export function deleteScan(id) {
  const s = load();
  const before = s.scans.length;
  s.scans = s.scans.filter((x) => x.id !== id);
  const changed = s.scans.length < before;
  if (changed) persist();
  return changed;
}

export function clearScans() {
  const s = load();
  const count = s.scans.length;
  s.scans = [];
  persist();
  return count;
}

export function getStats() {
  const s = load();
  const total = s.scans.length;

  const distribution = { total };
  const typeCounts = {};
  for (const x of s.scans) {
    distribution[x.category] = (distribution[x.category] || 0) + 1;
    typeCounts[x.type] = (typeCounts[x.type] || 0) + 1;
  }

  const recent = listScans({ limit: 5 }).items;
  return { total, distribution, typeCounts, recent };
}

export function getSetting(key) {
  const s = load();
  return key in s.settings ? s.settings[key] : null;
}

export function getAllSettings() {
  const s = load();
  return { ...s.settings };
}

export function setSetting(key, value) {
  const s = load();
  s.settings[key] = String(value);

  // If the user disables storage, purge any previously stored content.
  if (key === 'store_message_content' && String(value) !== 'true') {
    for (const scan of s.scans) scan.content = null;
  }
  persist();
  return s.settings[key];
}

function enforceRetention() {
  const s = load();
  const days = parseInt(s.settings.history_retention_days || '0', 10);
  if (!days || days <= 0) return;
  const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
  s.scans = s.scans.filter((x) => x.created_at >= cutoff);
}
