'use strict';

const http                           = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const { randomUUID }                 = require('crypto');
const { validate }                   = require('./tokens');
const { errorResponse }              = require('./errors');
const { tratarApi, ipDe }            = require('./api');
const fs                             = require('fs');
const path                           = require('path');

// Painel de pedidos (só no domínio raiz; um túnel com nome nunca serve o painel).
const ADMIN_HTML = fs.readFileSync(path.join(__dirname, 'admin.html'));

const MAX_QUEUE    = 256;
const MAX_BODY     = 10 * 1024 * 1024; // 10 MB
const PING_INTERVAL = 30_000;

const VERSION = require('../package.json').version;

function splashPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>sig3tunnel</title>
  <style>
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      font-family: Georgia, 'Times New Roman', serif;
      background: #fff;
      color: #111;
      border-top: 3px solid #111;
    }
    h1 { font-size: clamp(3rem, 10vw, 5rem); font-weight: 400; letter-spacing: -0.03em; line-height: 1; }
    .meta {
      margin-top: 1.25rem;
      font-size: 0.875rem;
      color: #aaa;
      letter-spacing: 0.01em;
    }
    .ping {
      margin-top: 0.6rem;
      font-family: 'Courier New', monospace;
      font-size: 0.75rem;
      color: #bbb;
    }
    footer {
      position: fixed;
      bottom: 1.75rem;
      left: 0; right: 0;
      text-align: center;
      font-size: 0.7rem;
      color: #999;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
  </style>
</head>
<body>
  <h1>sig3tunnel</h1>
  <p class="meta">relay running &middot; v${VERSION}</p>
  <p class="ping"><a href="/_sig3/ping" style="color:inherit;text-decoration:none;">/_sig3/ping</a></p>
  <footer>SIG3.Tunnel</footer>
</body>
</html>
`;
}

const MAX_UPGRADES = 256;

const peers    = new Map(); // name → ws
const queue    = new Map(); // requestId → { res, timer, peerName }
const upgrades = new Map(); // upgradeId → { socket, peerName }

function nameFromPath(path) {
  const m = (path || '').match(/^\/_sig3\/([a-z0-9][a-z0-9-]{0,62})$/i);
  return m ? m[1].toLowerCase() : 'default';
}

function nameFromHost(host) {
  const m = (host || '').match(/^([a-z0-9][a-z0-9-]*)\.tunel\./i);
  return m ? m[1].toLowerCase() : null;
}

// Só caminho de origem ("/x"). "//host/x" e "http://host/x" chegam como req.url e, resolvidos do
// outro lado contra a base local, trocariam o destino: o túnel viraria passagem para a rede do cliente.
function caminhoLocal(url) {
  return typeof url === 'string' && url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\');
}

// X-Forwarded-For SUBSTITUI o que veio, não acrescenta: o app do outro lado lê só o último IP da
// lista, e acrescentando o último era sempre o nginx (127.0.0.1) - todo visitante aparecia igual.
// O que o visitante manda nesse cabeçalho é forjável e não vai adiante.
function cabecalhosRepasse(req) {
  return {
    ...req.headers,
    'x-forwarded-for': ipDe(req),
    'x-forwarded-host': req.headers.host,
    'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'https',
  };
}

// Um túnel não planta cookie nos outros: tira o Domain= de todo Set-Cookie, que vira só do host
// daquele túnel (com Domain=tunel.<dominio> ele valeria em todos os <codigo>.tunel.<dominio>).
function cookiesSemDominio(headers) {
  for (const nome of Object.keys(headers)) {
    if (nome.toLowerCase() !== 'set-cookie') continue;
    const lista = Array.isArray(headers[nome]) ? headers[nome] : [headers[nome]];
    headers[nome] = lista.map(c => String(c).split(';').filter(p => !/^\s*domain\s*=/i.test(p)).join(';'));
  }
  return headers;
}

// Browser WebSocket upgrades (e.g. Blazor's /_blazor) are carried as raw bytes:
// the relay pipes the browser socket to the client, and the client pipes it to
// localhost. Bytes travel base64-encoded inside JSON, like HTTP bodies do.
// No queue timeout applies: upgrades stay open for as long as the socket does.
function tunnelUpgrade(req, socket, head) {
  if (!caminhoLocal(req.url)) {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  const name = nameFromHost(req.headers.host) || 'default';
  const peer = peers.get(name);

  if (!peer || peer.readyState !== WebSocket.OPEN) {
    socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  if (upgrades.size >= MAX_UPGRADES) {
    socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  const id      = randomUUID();
  const headers = cabecalhosRepasse(req);

  upgrades.set(id, { socket, peerName: name });

  peer.send(JSON.stringify({
    type:    'upgrade',
    id,
    method:  req.method,
    url:     req.url,
    headers,
    head:    head.length ? head.toString('base64') : '',
  }));

  // Dados do upgrade vão como frame binário: 36 bytes do id (UUID ASCII) + os bytes crus. Sem base64.
  socket.on('data', chunk => {
    if (!upgrades.has(id)) return;
    peer.send(Buffer.concat([Buffer.from(id, 'ascii'), chunk]), { binary: true });
  });

  const finish = () => {
    if (!upgrades.delete(id)) return;
    if (peer.readyState === WebSocket.OPEN) peer.send(JSON.stringify({ type: 'up-close', id }));
  };

  socket.on('close', finish);
  socket.on('error', () => { finish(); socket.destroy(); });
}

function serve(port, host) {
  const server = http.createServer((req, res) => {
    if (!caminhoLocal(req.url)) {
      errorResponse(res, 400, req);
      return;
    }

    if ((req.url || '').startsWith('/api-tunel/')) {
      tratarApi(req, res);
      return;
    }

    if (req.method === 'GET' && (req.url === '/admin' || req.url === '/admin/') && nameFromHost(req.headers.host) === null) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(ADMIN_HTML);
      return;
    }

    if (req.url === '/_sig3/ping') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    // Root domain with no subdomain and no default tunnel → splash page.
    if (req.url === '/' && nameFromHost(req.headers.host) === null && !peers.has('default')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(splashPage());
      return;
    }

    const name = nameFromHost(req.headers.host) || 'default';
    const peer = peers.get(name);

    if (!peer || peer.readyState !== WebSocket.OPEN) {
      errorResponse(res, 503, req);
      return;
    }

    if (queue.size >= MAX_QUEUE) {
      errorResponse(res, 429, req);
      return;
    }

    const id       = randomUUID();
    const chunks   = [];
    let bodySize   = 0;
    let bodyTooBig = false;

    req.on('data', chunk => {
      bodySize += chunk.length;
      if (bodySize > MAX_BODY) {
        bodyTooBig = true;
        req.destroy();
        errorResponse(res, 413, req);
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (bodyTooBig) return;

      const headers = cabecalhosRepasse(req);

      const msg = {
        id,
        method:  req.method,
        url:     req.url,
        headers,
        body:    Buffer.concat(chunks).toString('base64'),
      };

      const timer = setTimeout(() => {
        if (!queue.has(id)) return;
        queue.delete(id);
        errorResponse(res, 504, req);
      }, 30_000);

      queue.set(id, { res, req, timer, peerName: name });
      peer.send(JSON.stringify(msg));
    });

    req.on('error', () => errorResponse(res, 400, req));
  });

  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (req, socket, head) => {
    const path = req.url || '';
    if (path === '/_sig3' || /^\/_sig3\/[a-z0-9][a-z0-9-]{0,62}$/i.test(path)) {
      wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
    } else {
      tunnelUpgrade(req, socket, head);
    }
  });

  // Detect dead connections: ping every PING_INTERVAL, terminate if no pong.
  setInterval(() => {
    for (const [name, ws] of peers) {
      if (ws._pingPending) {
        console.log(`[sig3tunnel] "${name}" ping timeout, terminating`);
        ws.terminate();
        continue;
      }
      ws._pingPending = true;
      ws.ping();
    }
  }, PING_INTERVAL).unref();

  wss.on('connection', (ws, req) => {
    const raw   = (req.headers['authorization'] || '').trim();
    const token = raw.startsWith('Bearer ') ? raw.slice(7) : null;

    const rawPath  = req.url || '';
    const isDefault = rawPath === '/_sig3';

    if (!isDefault && !/^\/_sig3\/[a-z0-9][a-z0-9-]{0,62}$/i.test(rawPath)) {
      ws.close(1008, 'invalid path');
      return;
    }

    const name = nameFromPath(rawPath);

    if (!token || !validate(token, name)) {
      ws.close(1008, 'unauthorized');
      return;
    }

    if (peers.has(name) && peers.get(name).readyState === WebSocket.OPEN) {
      ws.close(1008, 'name already in use');
      return;
    }

    ws._pingPending = false;
    ws.on('pong', () => { ws._pingPending = false; });

    peers.set(name, ws);
    console.log(`[sig3tunnel] "${name}" connected from ${req.socket.remoteAddress}`);

    ws.on('message', (raw, isBinary) => {
      // Frame binário do cliente: 36 bytes de id + dados do upgrade.
      if (isBinary) {
        if (raw.length < 36) return;
        const up = upgrades.get(raw.subarray(0, 36).toString('ascii'));
        if (up && up.peerName === name) up.socket.write(raw.subarray(36));
        return;
      }

      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      if (msg.type === 'up-data' || msg.type === 'up-close') {
        const up = upgrades.get(msg.id);
        if (!up || up.peerName !== name) return;
        if (msg.type === 'up-close') {
          upgrades.delete(msg.id);
          up.socket.end();
        } else {
          up.socket.write(Buffer.from(msg.data, 'base64'));
        }
        return;
      }

      // Só o túnel que recebeu a requisição pode respondê-la.
      const entry = queue.get(msg.id);
      if (!entry || entry.peerName !== name) return;

      const { res, timer } = entry;
      queue.delete(msg.id);
      clearTimeout(timer);

      const headers = cookiesSemDominio({ ...(msg.headers || {}) });
      delete headers['transfer-encoding'];

      res.writeHead(msg.status || 200, headers);
      res.end(msg.body ? Buffer.from(msg.body, 'base64') : undefined);
    });

    ws.on('close', () => {
      peers.delete(name);
      console.log(`[sig3tunnel] "${name}" disconnected`);
      for (const [id, entry] of queue) {
        if (entry.peerName !== name) continue;
        clearTimeout(entry.timer);
        errorResponse(entry.res, 502, entry.req);
        queue.delete(id);
      }
      for (const [id, up] of upgrades) {
        if (up.peerName !== name) continue;
        upgrades.delete(id);
        up.socket.destroy();
      }
    });

    ws.on('error', err => console.error(`[sig3tunnel] "${name}" error:`, err.message));
  });

  server.listen(port, host, () => {
    console.log(`[sig3tunnel] relay listening on ${host}:${port}`);
  });

  return server;
}

module.exports = { serve };
