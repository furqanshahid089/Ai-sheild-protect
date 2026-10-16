import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl } from '../src/analysis/urlAnalyzer.js';

const RISK = {
  LOW: 'Low Risk Indicators',
  SUSPICIOUS: 'Suspicious',
  HIGH: 'High Risk Indicators',
  UNKNOWN: 'Unknown / Insufficient Evidence',
};

function hasFinding(result, id) {
  return result.findings.some((f) => f.id === id);
}

test('empty input is Unknown and invalid', () => {
  const r = analyzeUrl('   ');
  assert.equal(r.valid, false);
  assert.equal(r.category, RISK.UNKNOWN);
});

test('malformed URL is Unknown', () => {
  // A string with no valid host cannot be parsed into a URL.
  const r = analyzeUrl('http://');
  assert.equal(r.valid, false);
  assert.equal(r.category, RISK.UNKNOWN);
});

test('ordinary HTTPS site is not flagged as malicious', () => {
  const r = analyzeUrl('https://example.com/about');
  assert.equal(r.valid, true);
  assert.equal(r.category, RISK.LOW);
  assert.ok(r.score < 25);
});

test('plain HTTP alone is only a low-severity note, not high risk', () => {
  const r = analyzeUrl('http://example.com');
  assert.ok(hasFinding(r, 'no_https'));
  assert.notEqual(r.category, RISK.HIGH);
});

test('long path alone does not make a URL malicious', () => {
  const r = analyzeUrl('https://example.com/' + 'a'.repeat(200));
  assert.notEqual(r.category, RISK.HIGH);
});

test('raw IP host is flagged high severity', () => {
  const r = analyzeUrl('http://192.168.0.1/login');
  assert.ok(hasFinding(r, 'ip_host'));
  assert.ok(r.score >= 25);
});

test('"@" in authority is flagged', () => {
  const r = analyzeUrl('http://trusted.com@evil.example/');
  assert.ok(hasFinding(r, 'at_symbol'));
  assert.equal(r.category, RISK.HIGH);
});

test('punycode domain is flagged', () => {
  const r = analyzeUrl('https://xn--pple-43d.com/');
  assert.ok(hasFinding(r, 'punycode'));
});

test('brand buried in subdomain is flagged', () => {
  const r = analyzeUrl('https://paypal.com.secure-login.example.net/');
  assert.ok(hasFinding(r, 'brand_in_subdomain'));
});

test('unusual port is flagged', () => {
  const r = analyzeUrl('http://example.com:8081/');
  assert.ok(hasFinding(r, 'unusual_port'));
});

test('url shortener is flagged low', () => {
  const r = analyzeUrl('https://bit.ly/abcd');
  assert.ok(hasFinding(r, 'shortener'));
});

test('scheme is assumed when omitted', () => {
  const r = analyzeUrl('example.com');
  assert.ok(hasFinding(r, 'scheme_assumed'));
  assert.equal(r.valid, true);
});

test('normalized URL strips embedded credentials', () => {
  const r = analyzeUrl('http://user:pass@example.com/');
  assert.ok(!r.normalizedUrl.includes('pass'));
});

test('overly long input is rejected', () => {
  const r = analyzeUrl('https://example.com/' + 'a'.repeat(5000), { maxUrlLength: 2048 });
  assert.equal(r.valid, false);
  assert.equal(r.category, RISK.UNKNOWN);
});
