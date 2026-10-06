'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http   = require('node:http');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');
const WebSocket = require('ws');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-relay-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;

const { serve } = require('../src/relay');
const tokens    = require('../src/tokens');

let relayServer;
let relayPort;
let globalToken;
let scopedToken;

function freePort() {
  return new Promise((resolve, reject) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

function httpGet(port, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, ...opts }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(opts.body ?? undefined);
  });
}

// Connect a WS tunnel client that responds to requests with a static handler.
function openTunnel(path, raw, handler) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}${path}`, {
      headers: { authorization: `Bearer ${raw}` },
    });
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
    ws.on('message', async msg => {
      const req = JSON.parse(msg);
      const reply = await handler(req);
      ws.send(JSON.stringify({ id: req.id, ...reply }));
    });
  });
}

before(async () => {
  relayPort   = await freePort();
  relayServer = serve(relayPort, '127.0.0.1');
  await new Promise((resolve, reject) => {
    relayServer.once('listening', resolve);
    relayServer.once('error', reject);
  });
  globalToken = tokens.issue('*');
  scopedToken = tokens.issue('preview');
});

after(() => {
  relayServer.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('/_sig3/ping returns ok', async () => {
  const r = await httpGet(relayPort, { path: '/_sig3/ping' });
  assert.equal(r.status, 200);
  assert.equal(r.body, 'ok');
});

test('request to unconnected tunnel returns 503', async () => {
  const r = await httpGet(relayPort, { path: '/anything', headers: { host: '127.0.0.1' } });
  assert.equal(r.status, 503);
});

test('GET / on root domain with no default tunnel returns splash page', async () => {
  const r = await httpGet(relayPort, { path: '/', headers: { host: 'tunnel.example.com' } });
  assert.equal(r.status, 200);
  assert.ok(r.headers['content-type'].includes('text/html'));
  assert.ok(r.body.includes('sig3tunnel'));
  assert.ok(r.body.includes('relay running'));
});

test('relay rejects connection with invalid token', async () => {
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3`, {
      headers: { authorization: 'Bearer bf_invalid' },
    });
    ws.once('close', (code) => {
      assert.equal(code, 1008);
      resolve();
    });
    ws.once('error', reject);
  });
});

test('relay rejects connection with mismatched scope', async () => {
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3/staging`, {
      headers: { authorization: `Bearer ${scopedToken.raw}` },
    });
    ws.once('close', (code) => {
      assert.equal(code, 1008);
      resolve();
    });
    ws.once('error', reject);
  });
});

test('relay forwards HTTP request to connected client and returns response', async () => {
  const ws = await openTunnel('/_sig3', globalToken.raw, req => ({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: Buffer.from('hello from tunnel').toString('base64'),
  }));

  try {
    const r = await httpGet(relayPort, { path: '/some/path', headers: { host: '127.0.0.1' } });
    assert.equal(r.status, 200);
    assert.equal(r.body, 'hello from tunnel');
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('relay echoes request method and URL to client', async () => {
  let received;
  const ws = await openTunnel('/_sig3', globalToken.raw, req => {
    received = req;
    return { status: 204, headers: {}, body: '' };
  });

  try {
    await httpGet(relayPort, { method: 'POST', path: '/echo-test', headers: { host: '127.0.0.1' } });
    assert.equal(received.method, 'POST');
    assert.equal(received.url, '/echo-test');
    assert.ok(received.id);
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('relay responds 502 to in-flight requests when client disconnects', async () => {
  const ws = await openTunnel('/_sig3', globalToken.raw, () =>
    new Promise(() => { /* never responds */ }),
  );

  const pending = httpGet(relayPort, { path: '/slow', headers: { host: '127.0.0.1' } });

  // Give relay time to enqueue the request, then disconnect.
  await new Promise(r => setTimeout(r, 50));
  ws.terminate();

  const r = await pending;
  assert.equal(r.status, 502);
});

test('scoped token connects to matching path', async () => {
  const ws = await openTunnel('/_sig3/preview', scopedToken.raw, req => ({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: Buffer.from('scoped').toString('base64'),
  }));

  try {
    // Route to "preview" tunnel via subdomain-style host header
    const r = await httpGet(relayPort, {
      path: '/test',
      headers: { host: 'preview.tunnel.example.com' },
    });
    assert.equal(r.status, 200);
    assert.equal(r.body, 'scoped');
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('relay rejects duplicate tunnel name', async () => {
  const ws1 = await openTunnel('/_sig3', globalToken.raw, () => ({ status: 200, headers: {}, body: '' }));

  try {
    await new Promise((resolve, reject) => {
      const ws2 = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3`, {
        headers: { authorization: `Bearer ${globalToken.raw}` },
      });
      ws2.once('close', (code) => {
        assert.equal(code, 1008);
        resolve();
      });
      ws2.once('error', reject);
    });
  } finally {
    ws1.close();
    await new Promise(r => ws1.once('close', r));
  }
});

test('relay adds X-Forwarded headers for reverse proxy compat (Next.js hydration)', async () => {
  let receivedHeaders;
  const ws = await openTunnel('/_sig3/myapp', globalToken.raw, req => {
    receivedHeaders = req.headers;
    return { status: 200, headers: {}, body: '' };
  });

  try {
    await httpGet(relayPort, {
      path: '/test-page',
      headers: { host: 'myapp.tunnel.example.com' },
    });
    // SIG3.Tunnel should preserve the original host in x-forwarded-host
    assert.equal(receivedHeaders['x-forwarded-host'], 'myapp.tunnel.example.com');
    // SIG3.Tunnel should set x-forwarded-proto (defaults to https for security)
    assert.equal(receivedHeaders['x-forwarded-proto'], 'https');
    // Client will later change Host to localhost:PORT, but these headers persist
    // so Next.js can determine the real origin without code changes
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});
