'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http   = require('node:http');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');
const WebSocket = require('ws');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-upgrade-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;

const { serve }        = require('../src/relay');
const { openUpgrade }  = require('../src/client');
const tokens           = require('../src/tokens');

let relayServer;
let relayPort;
let echoServer;
let echoPort;
let peer;
let token;

function freePort() {
  return new Promise((resolve, reject) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

// Local app: a WebSocket echo server, standing in for Blazor's /_blazor.
function startEcho() {
  const server = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  const wss = new WebSocket.Server({ server });
  wss.on('connection', ws => ws.on('message', (data, isBinary) => ws.send(data, { binary: isBinary })));
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// Tunnel client (what `sig3tunnel connect` runs), pointed at the echo server.
function openPeer(relayTok) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3/echo`, {
      headers: { authorization: `Bearer ${relayTok}` },
    });
    const sockets = new Map();
    const send = obj => ws.send(JSON.stringify(obj));
    ws.on('message', (raw, isBinary) => {
      // Bytes do navegador chegam como frame binário: 36 bytes de id + dados.
      if (isBinary) return sockets.get(raw.subarray(0, 36).toString('ascii'))?.write(raw.subarray(36));
      const msg = JSON.parse(raw);
      if (msg.type === 'upgrade') return openUpgrade(echoPort, msg, send, sockets);
      if (msg.type === 'up-data') return sockets.get(msg.id)?.write(Buffer.from(msg.data, 'base64'));
      if (msg.type === 'up-close') { sockets.get(msg.id)?.end(); sockets.delete(msg.id); }
    });
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
  });
}

// Browser side: connects to the public host, the way Chrome would through the tunnel.
function openBrowser(host, p = '/_blazor?id=abc') {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}${p}`, { headers: { host } });
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
    ws.once('unexpected-response', (req, res) => {
      ws.terminate();
      reject(new Error(`status ${res.statusCode}`));
    });
  });
}

function nextMessage(ws) {
  return new Promise(resolve => ws.once('message', (data, isBinary) => resolve({ data: data.toString(), isBinary })));
}

before(async () => {
  relayPort  = await freePort();
  relayServer = serve(relayPort, '127.0.0.1');
  await new Promise((resolve, reject) => {
    relayServer.once('listening', resolve);
    relayServer.once('error', reject);
  });

  echoServer = await startEcho();
  echoPort   = echoServer.address().port;

  token = tokens.issue('*').raw;
  peer  = await openPeer(token);
});

after(() => {
  peer?.terminate();
  relayServer.closeAllConnections();
  echoServer.closeAllConnections();
  relayServer.close();
  echoServer.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('WebSocket upgrade on a tunnel host reaches the local app and echoes both ways', async () => {
  const browser = await openBrowser('echo.tunnel.test');

  const reply = nextMessage(browser);
  browser.send('hello from browser');
  const got = await reply;
  assert.equal(got.data, 'hello from browser');

  const back = nextMessage(browser);
  browser.send(Buffer.from([1, 2, 3]));
  assert.deepEqual(await back.then(m => m.isBinary), true);

  browser.close();
});

test('upgrade to a tunnel with no connected peer is refused with 503', async () => {
  await assert.rejects(openBrowser('nobody.tunnel.test'), /status 503/);
});

test('closing the browser socket closes the local socket too', async () => {
  const browser = await openBrowser('echo.tunnel.test');
  const closed = new Promise(resolve => browser.once('close', resolve));
  browser.close();
  await closed;

  // The tunnel still works for the next browser after the previous one left.
  const again = await openBrowser('echo.tunnel.test');
  const reply = nextMessage(again);
  again.send('still alive');
  assert.equal((await reply).data, 'still alive');
  again.close();
});
