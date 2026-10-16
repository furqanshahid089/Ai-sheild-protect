// Deterministic scam-message analysis.
//
// SAFETY NOTES:
// - Submitted text is treated strictly as untrusted DATA, never as instructions.
// - No external calls are made here; this is local, rule-based analysis.
// - Results describe warning signs, not a guarantee that a message is a scam.

import { scoreFindings, makeFinding } from './scoring.js';
import { RISK_CATEGORIES } from '../config.js';
import { analyzeUrl } from './urlAnalyzer.js';

const URL_RE = /\b((https?:\/\/)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/[^\s]*)?)/gi;

// Rule set: each rule is a set of patterns and a finding template.
const RULES = [
  {
    id: 'urgency',
    severity: 'medium',
    title: 'Pressure to act immediately',
    explanation:
      'Scammers create urgency so you act before thinking. Legitimate organizations rarely demand instant action under threat.',
    patterns: [
      /\burgent\b/i, /\bimmediately\b/i, /\bright now\b/i, /\bact now\b/i,
      /\bwithin \d+ (hours|minutes)\b/i, /\blast warning\b/i, /\bfinal notice\b/i,
    ],
  },
  {
    id: 'account_threat',
    severity: 'medium',
    title: 'Threat of account suspension or closure',
    explanation:
      'Messages that threaten to suspend, lock, or delete your account are a common scare tactic to make you click or share details.',
    patterns: [
      /\bsuspend(ed)?\b/i, /\block(ed)?\b/i, /\bdeactivat(e|ed)\b/i,
      /\baccount (will be )?(closed|terminated|blocked)\b/i, /\bunusual activity\b/i,
    ],
  },
  {
    id: 'credentials',
    severity: 'high',
    title: 'Asks for passwords, codes, or confidential details',
    explanation:
      'No legitimate organization will ask for your password, full card number, PIN, or one-time passcode in a message. This is a strong scam signal.',
    patterns: [
      /\bpassword\b/i, /\bone[- ]?time (code|passcode|pin)\b/i, /\botp\b/i,
      /\bverification code\b/i, /\bpin\b/i, /\bcvv\b/i, /\bfull card number\b/i,
      /\bconfirm your (identity|details|password)\b/i,
    ],
  },
  {
    id: 'payment',
    severity: 'high',
    title: 'Unusual payment or money-transfer request',
    explanation:
      'Requests to pay via gift cards, crypto, wire transfer, or to "release" a fee are hallmarks of scams.',
    patterns: [
      /\bgift card(s)?\b/i, /\bbitcoin\b/i, /\bcrypto\b/i, /\bwire transfer\b/i,
      /\bwestern union\b/i, /\bmoneygram\b/i, /\bpay (a )?fee\b/i,
      /\brelease (the )?funds\b/i, /\bprocessing fee\b/i,
    ],
  },
  {
    id: 'prize',
    severity: 'medium',
    title: 'Too-good-to-be-true prize or reward',
    explanation:
      'Unexpected lottery wins, prizes, refunds, or inheritances you never applied for are classic bait.',
    patterns: [
      /\bcongratulations\b/i, /\byou('| ha)ve won\b/i, /\bwinner\b/i,
      /\bclaim your (prize|reward|gift)\b/i, /\blottery\b/i, /\binheritance\b/i,
      /\bfree (gift|iphone|prize)\b/i,
    ],
  },
  {
    id: 'impersonation',
    severity: 'medium',
    title: 'Claims to be a bank or official organization',
    explanation:
      'Impersonating a bank, tax authority, delivery company, or big brand lends false authority. Verify through official channels, not the message.',
    patterns: [
      /\b(bank|paypal|amazon|apple|microsoft|netflix)\b/i,
      /\b(irs|hmrc|tax (office|refund))\b/i, /\b(fedex|dhl|ups|royal mail|usps)\b/i,
      /\bcustoms\b/i, /\bgovernment\b/i,
    ],
  },
  {
    id: 'generic_greeting',
    severity: 'low',
    title: 'Generic, impersonal greeting',
    explanation:
      'Mass-sent scams often open with "Dear customer" or "Dear user" because they do not know your name.',
    patterns: [
      /\bdear (customer|user|client|account holder|sir\/madam)\b/i,
    ],
  },
  {
    id: 'click_link',
    severity: 'low',
    title: 'Pushes you to click a link',
    explanation:
      'Being urged to click a link to "verify", "update", or "secure" an account is a common delivery method for phishing pages.',
    patterns: [
      /\bclick (here|the link|below)\b/i, /\bverify (your )?account\b/i,
      /\bupdate your (details|information)\b/i, /\bconfirm here\b/i,
    ],
  },
];

/**
 * Analyze message text for scam warning signs.
 * @param {string} rawInput
 * @param {{maxMessageLength?: number}} [opts]
 */
export function analyzeMessage(rawInput, opts = {}) {
  const maxMessageLength = opts.maxMessageLength ?? 20_000;
  const analyzedAt = new Date().toISOString();
  const findings = [];

  const text = typeof rawInput === 'string' ? rawInput.trim() : '';

  if (!text) {
    return result(RISK_CATEGORIES.UNKNOWN, 0, findings, {
      analyzedAt, valid: false,
      reason: 'No message text was provided.',
      embeddedUrls: [],
    });
  }

  if (text.length > maxMessageLength) {
    return result(RISK_CATEGORIES.UNKNOWN, 0, findings, {
      analyzedAt, valid: false,
      reason: `Message exceeds the maximum allowed length of ${maxMessageLength} characters.`,
      embeddedUrls: [],
    });
  }

  // Apply rules
  for (const rule of RULES) {
    if (rule.patterns.some((re) => re.test(text))) {
      findings.push(makeFinding(rule.id, rule.severity, rule.title, rule.explanation));
    }
  }

  // Inspect embedded links (reuse the URL analyzer, string-only)
  const embeddedUrls = [];
  const matches = text.match(URL_RE) || [];
  const uniqueUrls = [...new Set(matches.map((m) => m.trim()))].slice(0, 10);
  let riskyLinkFound = false;

  for (const candidate of uniqueUrls) {
    const urlResult = analyzeUrl(candidate);
    if (!urlResult.valid) continue;
    embeddedUrls.push({
      url: urlResult.normalizedUrl,
      category: urlResult.category,
      score: urlResult.score,
    });
    if (urlResult.category === RISK_CATEGORIES.HIGH ||
        urlResult.category === RISK_CATEGORIES.SUSPICIOUS) {
      riskyLinkFound = true;
    }
  }

  if (riskyLinkFound) {
    findings.push(makeFinding(
      'risky_embedded_link', 'high',
      'Contains a suspicious link',
      'One or more links in this message show risk indicators when analyzed. Do not click them without verifying.',
    ));
  }

  const { score, category } = scoreFindings(findings, { hadInput: true });

  return result(category, score, findings, {
    analyzedAt, valid: true, reason: null, embeddedUrls,
  });
}

function recommendations(category) {
  const base = [
    'Never share passwords, PINs, or one-time codes in response to a message.',
    'Verify the sender using official contact details you find yourself, not ones in the message.',
  ];
  if (category === RISK_CATEGORIES.HIGH) {
    return [
      'Do not reply, click links, or send money.',
      'Delete the message or report it as spam/phishing.',
      ...base,
    ];
  }
  if (category === RISK_CATEGORIES.SUSPICIOUS) {
    return ['Be cautious and independently verify before acting.', ...base];
  }
  if (category === RISK_CATEGORIES.UNKNOWN) {
    return ['Could not analyze the input. Paste the message text and try again.'];
  }
  return [
    'No strong scam indicators were found, but stay alert. This is not a guarantee.',
    ...base,
  ];
}

function result(category, score, findings, meta) {
  return {
    type: 'message',
    category,
    score,
    scoreMeaning:
      '0 = no scam warning signs detected; 100 = many strong warning signs. This counts detected indicators and is not a probability or a verdict.',
    findings,
    recommendations: recommendations(category),
    confidenceNote:
      'This is a local, rule-based analysis of the text you pasted. It can miss cleverly worded scams and may flag harmless messages. Use your own judgment.',
    ...meta,
  };
}
