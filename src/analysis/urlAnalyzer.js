// Deterministic, defensive URL risk analysis.
//
// IMPORTANT SAFETY NOTES:
// - This engine NEVER opens the submitted URL, fetches it, follows redirects,
//   downloads files, or executes any content. It only inspects the URL string.
// - It reports *indicators*, not a verdict of "safe" or "malicious".
// - A URL is NOT flagged as high risk merely for using HTTP or a long path.

import { scoreFindings, makeFinding } from './scoring.js';
import { RISK_CATEGORIES } from '../config.js';

// Common URL shortener hosts (heuristic list, not exhaustive).
const SHORTENERS = new Set([
  'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'bit.do', 'shorturl.at', 't.ly', 'rb.gy',
]);

// Suspicious TLDs frequently abused in phishing (heuristic only).
const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'gq', 'ml', 'cf', 'tk', 'work', 'click',
  'country', 'kim', 'science', 'party', 'review',
]);

// Words often used in impersonation / credential-harvesting URLs.
const IMPERSONATION_WORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
  'banking', 'password', 'wallet', 'webscr', 'recover', 'unlock', 'billing',
];

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpv4Host(host) {
  const m = host.match(IPV4_RE);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) >= 0 && Number(o) <= 255);
}

function isIpv6Host(host) {
  return host.startsWith('[') && host.endsWith(']');
}

/**
 * Analyze a URL string for risk indicators.
 * @param {string} rawInput
 * @param {{maxUrlLength?: number}} [opts]
 * @returns {object} structured analysis result
 */
export function analyzeUrl(rawInput, opts = {}) {
  const maxUrlLength = opts.maxUrlLength ?? 2048;
  const findings = [];
  const analyzedAt = new Date().toISOString();

  const input = typeof rawInput === 'string' ? rawInput.trim() : '';

  // --- Input validation ---
  if (!input) {
    return result(RISK_CATEGORIES.UNKNOWN, 0, findings, {
      normalizedUrl: null,
      analyzedAt,
      valid: false,
      reason: 'No URL was provided.',
    });
  }

  if (input.length > maxUrlLength) {
    return result(RISK_CATEGORIES.UNKNOWN, 0, findings, {
      normalizedUrl: null,
      analyzedAt,
      valid: false,
      reason: `URL exceeds the maximum allowed length of ${maxUrlLength} characters.`,
    });
  }

  // Add a scheme for parsing if the user omitted one, but record that we did.
  let candidate = input;
  let schemeAssumed = false;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
    candidate = `http://${candidate}`;
    schemeAssumed = true;
  }

  let url;
  try {
    url = new URL(candidate);
  } catch {
    return result(RISK_CATEGORIES.UNKNOWN, 0, findings, {
      normalizedUrl: null,
      analyzedAt,
      valid: false,
      reason: 'The input is not a syntactically valid URL.',
    });
  }

  const host = url.hostname.toLowerCase();
  const scheme = url.protocol.replace(':', '').toLowerCase();

  // --- Scheme checks ---
  if (scheme !== 'http' && scheme !== 'https') {
    findings.push(makeFinding(
      'non_web_scheme', 'medium',
      `Non-web scheme "${scheme}"`,
      `This link uses the "${scheme}" scheme rather than http/https. Links that are not standard web links can behave in unexpected ways.`,
    ));
  } else if (scheme === 'http') {
    findings.push(makeFinding(
      'no_https', 'low',
      'Connection is not encrypted (HTTP)',
      'This link uses HTTP instead of HTTPS, so traffic is not encrypted. On its own this is common and not proof of a scam, but avoid entering sensitive information.',
    ));
  }

  // --- "@" in authority (credential/obfuscation trick) ---
  if (url.username || url.password || /@/.test(url.host)) {
    findings.push(makeFinding(
      'at_symbol', 'high',
      'Uses "@" in the address',
      'An "@" before the host can hide the real destination. Everything before the "@" is ignored by browsers, which scammers use to make a link look like a trusted site.',
    ));
  }

  // --- Host is a raw IP address ---
  if (isIpv4Host(host) || isIpv6Host(host)) {
    findings.push(makeFinding(
      'ip_host', 'high',
      'Address points to a raw IP, not a domain name',
      'Legitimate services almost always use a domain name. A bare IP address is a common sign of a hastily set-up phishing or malware host.',
    ));
  }

  const labels = host.split('.').filter(Boolean);
  const tld = labels.length > 1 ? labels[labels.length - 1] : '';

  // --- Excessive subdomains ---
  if (labels.length >= 5) {
    findings.push(makeFinding(
      'many_subdomains', 'medium',
      'Unusually many subdomains',
      `The host has ${labels.length} parts. Long chains of subdomains are often used to make a link look like it belongs to a trusted brand (e.g. "paypal.com.secure-login.example").`,
    ));
  }

  // --- Misleading brand-in-subdomain pattern ---
  if (labels.length >= 3) {
    const brandish = ['paypal', 'apple', 'google', 'microsoft', 'amazon',
      'facebook', 'instagram', 'netflix', 'bank', 'whatsapp'];
    const earlyLabels = labels.slice(0, -2).join('.');
    for (const brand of brandish) {
      if (earlyLabels.includes(brand)) {
        findings.push(makeFinding(
          'brand_in_subdomain', 'high',
          `Trusted brand name "${brand}" placed in a subdomain`,
          `The real registered domain is "${labels.slice(-2).join('.')}", not "${brand}". Placing a brand in a subdomain is a classic impersonation trick.`,
        ));
        break;
      }
    }
  }

  // --- Punycode / IDN homograph ---
  if (host.includes('xn--')) {
    findings.push(makeFinding(
      'punycode', 'high',
      'Internationalized (punycode) domain',
      'This domain uses punycode ("xn--"), which can render as letters that look identical to normal ones (e.g. a Cyrillic "a"). This is used to imitate well-known domains.',
    ));
  }

  // --- Unusual / non-standard port ---
  if (url.port && !['80', '443', ''].includes(url.port)) {
    findings.push(makeFinding(
      'unusual_port', 'medium',
      `Non-standard port ${url.port}`,
      `Normal websites use port 80 or 443. The explicit port ${url.port} is unusual for a public website.`,
    ));
  }

  // --- Suspicious TLD ---
  if (SUSPICIOUS_TLDS.has(tld)) {
    findings.push(makeFinding(
      'suspicious_tld', 'medium',
      `Top-level domain ".${tld}" is frequently abused`,
      `The ".${tld}" extension is cheap/free and commonly used in scams. It is not proof of anything by itself, but warrants extra caution.`,
    ));
  }

  // --- URL shortener ---
  if (SHORTENERS.has(host)) {
    findings.push(makeFinding(
      'shortener', 'low',
      'Link shortener hides the real destination',
      'Shortened links conceal where they actually lead. Preview the expanded link before trusting it.',
    ));
  }

  // --- Overall length (informational, low weight) ---
  if (input.length > 120) {
    findings.push(makeFinding(
      'long_url', 'low',
      'Unusually long link',
      'Very long links can hide the true destination or stuff in extra parameters. This alone is not a strong signal.',
    ));
  }

  // --- Impersonation keywords in path/query ---
  const pathAndQuery = (url.pathname + url.search).toLowerCase();
  const matchedWords = IMPERSONATION_WORDS.filter((w) => pathAndQuery.includes(w));
  if (matchedWords.length >= 2) {
    findings.push(makeFinding(
      'credential_keywords', 'medium',
      'Login/verification keywords in the link',
      `The link contains terms like "${matchedWords.slice(0, 3).join('", "')}" that are typical of pages asking for credentials. Be cautious about entering passwords.`,
    ));
  }

  // --- Excessive percent-encoding ---
  const encodedCount = (input.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (encodedCount >= 6) {
    findings.push(makeFinding(
      'heavy_encoding', 'medium',
      'Heavy use of encoded characters',
      `The link contains ${encodedCount} percent-encoded characters, which can be used to obscure its real content.`,
    ));
  }

  if (schemeAssumed) {
    findings.push(makeFinding(
      'scheme_assumed', 'info',
      'No scheme supplied',
      'The link was submitted without http:// or https://, so http:// was assumed for analysis only.',
    ));
  }

  const { score, category } = scoreFindings(findings, { hadInput: true });

  return result(category, score, findings, {
    normalizedUrl: safeNormalized(url),
    analyzedAt,
    valid: true,
    reason: null,
    host,
    scheme,
  });
}

function safeNormalized(url) {
  // Reconstruct without credentials so we never echo embedded user:pass.
  const u = new URL(url.href);
  u.username = '';
  u.password = '';
  return u.href;
}

function recommendations(category) {
  const base = [
    'Do not enter passwords or one-time codes unless you are certain of the site.',
    'When in doubt, type the official address into your browser yourself instead of clicking.',
  ];
  if (category === RISK_CATEGORIES.HIGH) {
    return [
      'Avoid opening this link.',
      'Do not enter any personal, login, or payment details.',
      ...base,
    ];
  }
  if (category === RISK_CATEGORIES.SUSPICIOUS) {
    return [
      'Treat this link with caution and verify the sender through a trusted channel.',
      ...base,
    ];
  }
  if (category === RISK_CATEGORIES.UNKNOWN) {
    return ['Could not analyze the input. Double-check the link and try again.'];
  }
  return [
    'No strong risk indicators were found, but this is not a guarantee of safety.',
    ...base,
  ];
}

function result(category, score, findings, meta) {
  return {
    type: 'url',
    category,
    score,
    scoreMeaning:
      '0 = no concerning indicators found; 100 = many strong indicators. This is a measure of detected warning signs, not a probability or a verdict.',
    findings,
    recommendations: recommendations(category),
    confidenceNote:
      'This is an automated heuristic analysis of the link text only. It does not visit the site and cannot guarantee safety or detect every threat.',
    ...meta,
  };
}
