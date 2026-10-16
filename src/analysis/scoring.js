// Shared scoring helpers for the analysis engines.
// Score scale: 0 (no concerning indicators) to 100 (many strong indicators).
// The score reflects HOW MANY and HOW STRONG the detected indicators are.
// It is NOT a probability and NOT proof of malice or safety.

import { RISK_CATEGORIES } from '../config.js';

export const SEVERITY_WEIGHTS = {
  info: 0,
  low: 8,
  medium: 18,
  // A single strong indicator (e.g. "@" obfuscation, raw-IP host) is enough
  // to reach the High threshold on its own.
  high: 55,
};

/**
 * Convert a list of findings into a 0-100 score and a risk category.
 * @param {Array<{severity: string}>} findings
 * @param {{hadInput: boolean}} [opts]
 */
export function scoreFindings(findings, opts = {}) {
  const { hadInput = true } = opts;

  const raw = findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0),
    0,
  );
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  let category;
  if (!hadInput) {
    category = RISK_CATEGORIES.UNKNOWN;
  } else if (score >= 55) {
    category = RISK_CATEGORIES.HIGH;
  } else if (score >= 25) {
    category = RISK_CATEGORIES.SUSPICIOUS;
  } else {
    category = RISK_CATEGORIES.LOW;
  }

  return { score, category };
}

export function makeFinding(id, severity, title, explanation) {
  return { id, severity, title, explanation };
}
