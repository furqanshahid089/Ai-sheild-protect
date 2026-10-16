// Optional threat-intelligence integration layer.
//
// Design goals:
// - Only documented, authorized providers from a strict allowlist.
// - Credentials read from server-side config only.
// - Clearly labels source and timestamp; distinct from local heuristics.
// - Never fetches arbitrary user-controlled destinations (no SSRF).
// - Handles unavailable/stale intelligence gracefully.
//
// NOTE: No live provider is wired up by default. This returns a clearly
// labeled "not configured" result rather than fabricating a threat feed.

import { config } from '../config.js';

// Strict allowlist of supported provider identifiers.
const SUPPORTED_PROVIDERS = new Set(['none']);

export function isThreatIntelAvailable() {
  return Boolean(
    config.threatIntel.enabled &&
      config.threatIntel.apiKey &&
      SUPPORTED_PROVIDERS.has(config.threatIntel.provider),
  );
}

/**
 * Look up reputation for a host. Returns a clearly-sourced result.
 * @param {string} host
 */
export async function lookupReputation(host) {
  if (!isThreatIntelAvailable()) {
    return {
      source: 'none',
      available: false,
      checkedAt: new Date().toISOString(),
      note:
        'No external threat-intelligence provider is configured. ' +
        'Results are based on local heuristics only.',
      host,
    };
  }

  // Placeholder: a real, authorized provider integration would go here,
  // constrained to the allowlisted provider and never to a user-controlled URL.
  return {
    source: config.threatIntel.provider,
    available: false,
    checkedAt: new Date().toISOString(),
    note: 'Provider configured but no live integration is implemented in this build.',
    host,
  };
}
