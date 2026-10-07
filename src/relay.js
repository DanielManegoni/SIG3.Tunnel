'use strict';

const http                           = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const { randomUUID }                 = require('crypto');
const { validate }                   = require('./tokens');
const { errorResponse }              = require('./errors');
const { tratarApi }                  = require('./api');
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

const COOKIE_TUNEL = 'sig3tunel';

// IP de origem: o relay escuta só em 127.0.0.1 (quem conecta é o nginx). X-Real-IP só é confiado
// vindo do loopback (mesma regra do api.js); de outra origem, vale o socket.
function ipConfiavel(req) {
  const origem = req.socket.remoteAddress || 'desconhecido';
  const local = origem === '127.0.0.1' || origem === '::1' || origem === '::ffff:127.0.0.1';
  return (local && req.headers['x-real-ip']) || origem;
}

// Tentativas de código no link de entrada: 10 em 15 min bloqueiam o IP por 15 min. Não impede
// acesso (o código nunca foi segredo de acesso, só diz "qual computador") - freia quem fica
// sondando `/00000` a `/99999` pra descobrir quais túneis estão vivos agora.
const TENTATIVAS_LINK_MAX = 10;
const JANELA_LINK_MS      = 15 * 60 * 1000;
const tentativasLink      = new Map(); // ip -> { tentativas, inicio, bloqueadoAte }

function linkBloqueado(ip, agora = Date.now()) {
  const f = tentativasLink.get(ip);
  return !!f && f.bloqueadoAte > agora;
}

function registrarTentativaLink(ip, agora = Date.now()) {
  const f = tentativasLink.get(ip);
  if (!f || agora - f.inicio > JANELA_LINK_MS) {
    tentativasLink.set(ip, { tentativas: 1, inicio: agora, bloqueadoAte: 0 });
    return;
  }
  f.tentativas += 1;
  if (f.tentativas >= TENTATIVAS_LINK_MAX) f.bloqueadoAte = agora + JANELA_LINK_MS;
}

// Sem subdomínio (e sem certificado wildcard): qual peer atende cada pedido vem de um cookie,
// gravado uma vez quando o navegador entra pelo link com o código (ver selecionarTunelPorLink).
function nomeDoCookie(req) {
  const cru = req.headers.cookie || '';
  for (const parte of cru.split(';')) {
    const i = parte.indexOf('=');
    if (i === -1) continue;
    if (parte.slice(0, i).trim() === COOKIE_TUNEL) return (parte.slice(i + 1).trim().toLowerCase() || null);
  }
  return null;
}

// Link de entrada: /<codigo> ou /?conexao=<codigo>, sempre os 5 dígitos que pedidos.js sorteia.
// Grava o cookie e redireciona para "/" limpo - dali em diante é o cookie, não o host, que decide
// o peer. Assim o relay inteiro roda num host só (tunel.<dominio>), sem exigir wildcard.
function selecionarTunelPorLink(req, res) {
  const url = new URL(req.url, 'http://relay');
  const porPath = url.pathname.match(/^\/([0-9]{5})\/?$/);
  const porQuery = url.searchParams.get('conexao');
  const codigo = porPath ? porPath[1] : (porQuery && /^[0-9]{5}$/.test(porQuery) ? porQuery : null);
  if (!codigo) return false;

  const ip = ipConfiavel(req);
  if (linkBloqueado(ip)) {
    res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ erro: 'muitas_tentativas', mensagem: 'Muitos códigos tentados. Espere 15 minutos.' }));
    return true;
  }
  registrarTentativaLink(ip);

  const https = (req.headers['x-forwarded-proto'] || '').toLowerCase() === 'https';
  res.writeHead(302, {
    'Set-Cookie': `${COOKIE_TUNEL}=${codigo}; Path=/; HttpOnly; SameSite=Lax${https ? '; Secure' : ''}`,
    'Cache-Control': 'no-store',
    Location: '/',
  });
  res.end();
  return true;
}

// Browser WebSocket upgrades (e.g. Blazor's /_blazor) are carried as raw bytes:
// the relay pipes the browser socket to the client, and the client pipes it to
// localhost. Bytes travel base64-encoded inside JSON, like HTTP bodies do.
// No queue timeout applies: upgrades stay open for as long as the socket does.
function tunnelUpgrade(req, socket, head) {
  const name = nomeDoCookie(req) || 'default';
  const peer = peers.get(name);

  if (!peer || peer.readyState !== WebSocket.OPEN) {
    socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  if (upgrades.size >= MAX_UPGRADES) {
    socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  const id        = randomUUID();
  const clientIp  = req.socket.remoteAddress;
  const forwarded = req.headers['x-forwarded-for'];
  const headers   = {
    ...req.headers,
    'x-forwarded-for': forwarded ? `${forwarded}, ${clientIp}` : clientIp,
    'x-forwarded-host': req.headers.host,
    'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'https',
  };

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
    if ((req.url || '').startsWith('/api-tunel/')) {
      tratarApi(req, res);
      return;
    }

    if (req.method === 'GET' && (req.url === '/admin' || req.url === '/admin/')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(ADMIN_HTML);
      return;
    }

    if (req.url === '/_sig3/ping') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    if (req.method === 'GET' && selecionarTunelPorLink(req, res)) return;

    // Sem túnel escolhido (sem cookie) e sem túnel padrão conectado → splash page.
    if (req.url === '/' && !nomeDoCookie(req) && !peers.has('default')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(splashPage());
      return;
    }

    const name = nomeDoCookie(req) || 'default';
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

      const clientIp  = req.socket.remoteAddress;
      const forwarded = req.headers['x-forwarded-for'];
      const originalHost = req.headers.host;
      const originalProto = req.headers['x-forwarded-proto'] || 'https';

      const headers   = {
        ...req.headers,
        'x-forwarded-for': forwarded ? `${forwarded}, ${clientIp}` : clientIp,
        'x-forwarded-host': originalHost,
        'x-forwarded-proto': originalProto,
      };

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

      const entry = queue.get(msg.id);
      if (!entry) return;

      const { res, timer } = entry;
      queue.delete(msg.id);
      clearTimeout(timer);

      const headers = { ...(msg.headers || {}) };
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
