import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Use an isolated temp DB and test mode so the server does not auto-listen.
process.env.NODE_ENV = 'test';
const tmpDb = path.join(os.tmpdir(), `ai_shield_test_${Date.now()}.db`);
process.env.DATABASE_FILE = tmpDb;

const { app } = await import('../src/server.js');

let server;
let base;

before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      base = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  const jsonFile = tmpDb.replace(/\.db$/i, '') + '.json';
  for (const f of [tmpDb, jsonFile, `${jsonFile}.tmp`]) {
    try { fs.unlinkSync(f); } catch { /* ignore */ }
  }
});

async function req(method, p, body) {
  const res = await fetch(base + p, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}

test('health endpoint responds ok', async () => {
  const { status, data } = await req('GET', '/api/v1/health');
  assert.equal(status, 200);
  assert.equal(data.status, 'ok');
  assert.ok('ai' in data.integrations);
});

test('URL scan validates empty input', async () => {
  const { status } = await req('POST', '/api/v1/scans/url', { url: '' });
  assert.equal(status, 400);
});

test('URL scan returns structured analysis and persists', async () => {
  const { status, data } = await req('POST', '/api/v1/scans/url', { url: 'http://192.168.0.1/login' });
  assert.equal(status, 200);
  assert.equal(data.analysis.type, 'url');
  assert.ok(Array.isArray(data.analysis.findings));
  assert.ok(data.scan.id, 'scan should be persisted with an id');
});

test('message scan returns analysis', async () => {
  const { status, data } = await req('POST', '/api/v1/scans/message', {
    message: 'Urgent: verify your account or it will be suspended.',
  });
  assert.equal(status, 200);
  assert.equal(data.analysis.type, 'message');
});

test('message content is not stored by default (data minimization)', async () => {
  const secret = 'please-do-not-store-this-text-12345';
  const { data } = await req('POST', '/api/v1/scans/message', { message: secret });
  const id = data.scan.id;
  const { data: scan } = await req('GET', `/api/v1/scans/${id}`);
  assert.equal(scan.content, null);
});

test('list, get, and delete scans work', async () => {
  const { data: list } = await req('GET', '/api/v1/scans?limit=5');
  assert.ok(list.total >= 1);
  const id = list.items[0].id;

  const { status: getStatus } = await req('GET', `/api/v1/scans/${id}`);
  assert.equal(getStatus, 200);

  const { status: delStatus, data: delData } = await req('DELETE', `/api/v1/scans/${id}`);
  assert.equal(delStatus, 200);
  assert.equal(delData.deleted, true);

  const { status: gone } = await req('GET', `/api/v1/scans/${id}`);
  assert.equal(gone, 404);
});

test('stats endpoint returns real counts', async () => {
  const { status, data } = await req('GET', '/api/v1/stats');
  assert.equal(status, 200);
  assert.equal(typeof data.total, 'number');
});

test('settings can be read and updated with validation', async () => {
  const { data: before } = await req('GET', '/api/v1/settings');
  assert.ok('store_message_content' in before);

  const { status } = await req('PATCH', '/api/v1/settings', { store_message_content: 'true' });
  assert.equal(status, 200);

  const { status: bad } = await req('PATCH', '/api/v1/settings', { not_allowed: 'x' });
  assert.equal(bad, 400);
});

test('unknown API route returns 404 JSON', async () => {
  const { status, data } = await req('GET', '/api/v1/nope');
  assert.equal(status, 404);
  assert.ok(data.error);
});
