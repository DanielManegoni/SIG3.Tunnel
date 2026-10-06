'use strict';

const http           = require('http');
const net            = require('net');
const { spawn }      = require('child_process');
const WebSocket      = require('ws');
const { fatal, G, W, GR, Y, R, Z } = require('./fmt');

const MAX_RETRY_DELAY = 30_000;

function waitForPort(port, timeout = 30_000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeout;
    function attempt() {
      const req = http.request({ hostname: '127.0.0.1', port, method: 'HEAD', path: '/' }, () => resolve());
      req.on('error', () => {
        if (Date.now() >= deadline) return reject(new Error(`port ${port} not ready after ${timeout}ms`));
        setTimeout(attempt, 500);
      });
      req.end();
    }
    attempt();
  });
}

function forwardRequest(port, msg) {
  return new Promise(resolve => {
    const body    = msg.body ? Buffer.from(msg.body, 'base64') : null;
    const headers = { ...msg.headers, host: `localhost:${port}` };
    delete headers['transfer-encoding'];
    if (body) headers['content-length'] = String(body.length);

    const req = http.request(
      { hostname: 'localhost', port, method: msg.method, path: msg.url, headers },
      res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve({
          id:      msg.id,
          status:  res.statusCode,
          headers: res.headers,
          body:    Buffer.concat(chunks).toString('base64'),
        }));
      },
    );

    req.on('error', () => resolve({
      id:      msg.id,
      status:  502,
      headers: { 'content-type': 'text/plain' },
      body:    Buffer.from('local server error').toString('base64'),
    }));

    if (body) req.write(body);
    req.end();
  });
}

// Opens a raw TCP connection to localhost:<port> for one relayed WebSocket
// upgrade, replays the original handshake request, and pipes bytes both ways.
// `send` takes a message object; `sockets` is this tunnel connection's map.
function openUpgrade(port, msg, send, sockets) {
  const headers = { ...msg.headers, host: `localhost:${port}` };
  delete headers['transfer-encoding'];

  const sock = net.connect(port, '127.0.0.1');
  sockets.set(msg.id, sock);

  // net buffers writes until the connection opens, so the handshake goes first
  // even when relayed bytes arrive before the local socket is connected.
  const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`);
  sock.write(`${msg.method} ${msg.url} HTTP/1.1\r\n${lines.join('\r\n')}\r\n\r\n`);
  if (msg.head) sock.write(Buffer.from(msg.head, 'base64'));

  sock.on('data', chunk => send({ type: 'up-data', id: msg.id, data: chunk.toString('base64') }));

  sock.on('close', () => {
    if (!sockets.delete(msg.id)) return;
    send({ type: 'up-close', id: msg.id });
  });

  sock.on('error', () => sock.destroy());
}

function buildPublicUrl(relayBase, name) {
  const base = relayBase.replace(/^wss?:\/\//, match => match === 'wss://' ? 'https://' : 'http://');
  try {
    const url = new URL(base);
    if (name) url.hostname = `${name.toLowerCase()}.${url.hostname}`;
    return url.toString().replace(/\/$/, '');
  } catch {
    return base;
  }
}

async function connect(cfg, rawPort, args) {
  if (!rawPort) fatal('usage: sig3tunnel connect <port> [--name <name>] [--run "command"]');

  const port = parseInt(rawPort, 10);
  if (isNaN(port) || port < 1 || port > 65535) fatal('invalid port: ' + rawPort);

  const { endpoint, token } = cfg;
  const relayBase = endpoint.replace(/\/_sig3$/, '');

  const nameIdx = args.indexOf('--name');
  const name    = nameIdx !== -1 ? args[nameIdx + 1] : null;
  if (name !== null && !/^[a-z0-9][a-z0-9-]{0,62}$/i.test(name)) {
    fatal('invalid name: only letters, numbers and hyphens (max 63 chars)');
  }

  const relayUrl = name
    ? `${relayBase}/_sig3/${name.toLowerCase()}`
    : `${relayBase}/_sig3`;

  const runIdx = args.indexOf('--run');
  const runCmd = runIdx !== -1 ? args[runIdx + 1] : null;

  let child = null;

  if (runCmd) {
    process.stdout.write(G + '→ ' + Z + 'running: ' + W + runCmd + Z + '\n');
    child = spawn(runCmd, { shell: true, stdio: 'inherit' });
    child.on('error', err => fatal('could not start process: ' + err.message));

    process.stdout.write(G + '→ ' + Z + `waiting for port ${port}...\n`);
    try {
      await waitForPort(port);
    } catch (e) {
      child.kill();
      fatal(e.message);
    }
  }

  let intentionalClose = false;
  let currentWs        = null;
  let retries          = 0;

  const cleanup = (code = 0) => {
    intentionalClose = true;
    if (currentWs) currentWs.close();
    if (child) child.kill();
    process.exit(code);
  };

  process.on('SIGINT',  () => cleanup(0));
  process.on('SIGTERM', () => cleanup(0));

  function scheduleReconnect() {
    const delay = Math.min(1_000 * 2 ** retries, MAX_RETRY_DELAY);
    retries++;
    process.stderr.write(Y + `reconnecting in ${Math.round(delay / 1000)}s...\n` + Z);
    setTimeout(createWs, delay);
  }

  function createWs() {
    const ws = new WebSocket(relayUrl, { headers: { authorization: `Bearer ${token}` } });
    currentWs = ws;

    const upgradeSockets = new Map(); // upgradeId → local net.Socket
    const send = obj => ws.send(JSON.stringify(obj));

    ws.on('open', () => {
      retries = 0;
      const publicUrl = buildPublicUrl(relayBase, name);
      process.stdout.write('\n' + GR + '✓ ' + Z + 'tunnel active → ' + W + publicUrl + Z + '\n\n');
    });

    ws.on('message', async raw => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      if (msg.type === 'upgrade') {
        process.stdout.write(G + new Date().toLocaleTimeString('en-US', { hour12: false }) + Z + '  ' + W + 'WS    ' + Z + ' ' + msg.url + '\n');
        openUpgrade(port, msg, send, upgradeSockets);
        return;
      }
      if (msg.type === 'up-data') {
        upgradeSockets.get(msg.id)?.write(Buffer.from(msg.data, 'base64'));
        return;
      }
      if (msg.type === 'up-close') {
        // The browser is already gone, so tear the local socket down fully.
        upgradeSockets.get(msg.id)?.destroy();
        upgradeSockets.delete(msg.id);
        return;
      }

      const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
      process.stdout.write(G + ts + Z + '  ' + W + msg.method.padEnd(6) + Z + ' ' + msg.url + '\n');

      const response = await forwardRequest(port, msg);

      const color = response.status < 400 ? GR : Y;
      process.stdout.write(' '.repeat(10) + color + response.status + Z + '\n');

      ws.send(JSON.stringify(response));
    });

    ws.on('error', err => {
      process.stderr.write(R + 'error: ' + Z + err.message + '\n');
    });

    ws.on('close', (code, reason) => {
      for (const sock of upgradeSockets.values()) sock.destroy();
      upgradeSockets.clear();

      if (intentionalClose) return;

      // Policy violation means the server rejected us — no point retrying.
      if (code === 1008) {
        process.stderr.write(R + 'rejected: ' + Z + (reason?.toString() || 'unauthorized') + '\n');
        cleanup(1);
        return;
      }

      if (code !== 1000 && code !== 1005) {
        process.stderr.write(Y + 'disconnected (' + code + ')  ' + Z);
      }

      scheduleReconnect();
    });
  }

  createWs();
}

module.exports = { connect, openUpgrade };
