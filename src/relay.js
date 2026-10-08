'use strict';

const http                           = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const { randomUUID }                 = require('crypto');
const { validate }                   = require('./tokens');
const { errorResponse }              = require('./errors');
const { tratarApi, ipDe }            = require('./api');
const tecnicos                       = require('./tecnicos');
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

// Por túnel, abaixo do teto geral: o visitante de um cliente não esgota a vaga dos outros.
const MAX_QUEUE_POR_TUNEL    = 64;
const MAX_UPGRADES_POR_TUNEL = 64;

// A Cloudflare corta a resposta em 100 s (erro 524). O SIG3 desiste em 90 s (TunelSig3Tunnel) e
// responde 502; o relay espera um pouco mais, para a resposta do SIG3 chegar antes do 504 daqui.
const TEMPO_RESPOSTA_MS = 95_000;

const peers    = new Map(); // name → ws
const queue    = new Map(); // requestId → { res, timer, peerName }
const upgrades = new Map(); // upgradeId → { socket, peerName }

function nameFromPath(path) {
  const m = (path || '').match(/^\/_sig3\/([a-z0-9][a-z0-9-]{0,62})$/i);
  return m ? m[1].toLowerCase() : 'default';
}

// Endereço do túnel: tunel-<nome>.<dominio> (um nível só, coberto pelo certificado gratuito da
// Cloudflare e escondido atrás da nuvem laranja). O formato antigo <nome>.tunel.<dominio> segue
// aceito enquanto houver SIG3 instalado que ainda monta o endereço assim.
function nameFromHost(host) {
  const h = host || '';
  const m = h.match(/^tunel-([a-z0-9][a-z0-9-]*)\./i) || h.match(/^([a-z0-9][a-z0-9-]*)\.tunel\./i);
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
  return tecnicos.limparCabecalhos({
    ...req.headers,
    'x-forwarded-for': ipDe(req),
    'x-forwarded-host': req.headers.host,
    'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'https',
  });
}

// Só técnico com chave (ou com o cookie que ela rendeu) chega ao SIG3 de um cliente. A conferência
// vem antes de saber se o túnel existe: quem não tem chave não descobre quais clientes estão no ar.
function autorizarTecnico(req, tunel) {
  const auth = tecnicos.autorizar(req, tunel);
  if (auth?.novoCookie) console.log(`[sig3tunnel] técnico "${auth.tecnico.nome}" entrou em "${tunel}" de ${ipDe(req)}`);
  return auth;
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

function contarDoTunel(mapa, nome) {
  let n = 0;
  for (const v of mapa.values()) if (v.peerName === nome) n++;
  return n;
}

// Protocolo: docs/protocolo.md. Quadro binário de HTTP (versão 2):
//   36 bytes do id (UUID ASCII) | 4 bytes, tamanho do JSON (big-endian) | JSON | corpo cru
function montarQuadro(id, cabecalho, corpo) {
  const json = Buffer.from(JSON.stringify(cabecalho), 'utf8');
  const tam  = Buffer.alloc(4);
  tam.writeUInt32BE(json.length);
  return Buffer.concat([Buffer.from(id, 'ascii'), tam, json, corpo]);
}

function lerQuadro(raw) {
  if (raw.length < 40) return null;
  const tam = raw.readUInt32BE(36);
  if (40 + tam > raw.length) return null;
  try {
    return { cabecalho: JSON.parse(raw.subarray(40, 40 + tam).toString('utf8')), corpo: raw.subarray(40 + tam) };
  } catch {
    return null;
  }
}

function responder(entry, status, headersBrutos, corpo) {
  const headers = cookiesSemDominio({ ...(headersBrutos || {}) });
  delete headers['transfer-encoding'];
  if (entry.cookieTecnico) {
    const nome = Object.keys(headers).find(h => h.toLowerCase() === 'set-cookie') || 'set-cookie';
    const atuais = headers[nome] ? [].concat(headers[nome]) : [];
    headers[nome] = [...atuais, entry.cookieTecnico];
  }
  entry.res.writeHead(status || 200, headers);
  entry.res.end(corpo && corpo.length ? corpo : undefined);
}

// Upgrades de WebSocket do navegador (o /_blazor) viajam como bytes crus: o relay liga o socket do
// navegador ao túnel, e o SIG3 o liga ao localhost. Sem timeout: dura enquanto o socket durar.
function tunnelUpgrade(req, socket, head) {
  if (!caminhoLocal(req.url)) {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  const name = nameFromHost(req.headers.host) || 'default';
  if (!autorizarTecnico(req, name)) {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  const peer = peers.get(name);
  if (!peer || peer.readyState !== WebSocket.OPEN) {
    socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  if (upgrades.size >= MAX_UPGRADES || contarDoTunel(upgrades, name) >= MAX_UPGRADES_POR_TUNEL) {
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
      errorResponse(res, 400);
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
    const auth = autorizarTecnico(req, name);
    if (!auth) {
      errorResponse(res, 404);
      return;
    }

    const peer = peers.get(name);
    if (!peer || peer.readyState !== WebSocket.OPEN) {
      errorResponse(res, 503);
      return;
    }

    if (queue.size >= MAX_QUEUE || contarDoTunel(queue, name) >= MAX_QUEUE_POR_TUNEL) {
      errorResponse(res, 429);
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
        errorResponse(res, 413);
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (bodyTooBig) return;

      const cabecalho = { method: req.method, url: req.url, headers: cabecalhosRepasse(req) };
      const corpo     = Buffer.concat(chunks);

      const timer = setTimeout(() => {
        if (!queue.has(id)) return;
        queue.delete(id);
        errorResponse(res, 504);
      }, TEMPO_RESPOSTA_MS);

      queue.set(id, { res, timer, peerName: name, cookieTecnico: auth.novoCookie });
      // SIG3 que avisou a versão 2 recebe o corpo cru; o anterior, em base64 dentro do JSON.
      if (peer._protocolo >= 2) peer.send(montarQuadro(id, cabecalho, corpo), { binary: true });
      else peer.send(JSON.stringify({ id, ...cabecalho, body: corpo.toString('base64') }));
    });

    req.on('error', () => errorResponse(res, 400));
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
    ws._protocolo   = parseInt(req.headers['x-sig3-protocolo'] || '1', 10) || 1;
    ws.on('pong', () => { ws._pingPending = false; });

    peers.set(name, ws);
    console.log(`[sig3tunnel] "${name}" connected from ${req.socket.remoteAddress}`);

    ws.on('message', (raw, isBinary) => {
      // Frame binário: 36 bytes de id + dados de um upgrade, ou o quadro de uma resposta HTTP.
      if (isBinary) {
        if (raw.length < 36) return;
        const id = raw.subarray(0, 36).toString('ascii');
        const up = upgrades.get(id);
        if (up) {
          if (up.peerName === name) up.socket.write(raw.subarray(36));
          return;
        }
        const entry = queue.get(id);
        if (!entry || entry.peerName !== name) return;
        const quadro = lerQuadro(raw);
        if (!quadro) return;
        queue.delete(id);
        clearTimeout(entry.timer);
        responder(entry, quadro.cabecalho.status, quadro.cabecalho.headers, quadro.corpo);
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

      queue.delete(msg.id);
      clearTimeout(entry.timer);
      responder(entry, msg.status, msg.headers, msg.body ? Buffer.from(msg.body, 'base64') : null);
    });

    ws.on('close', () => {
      peers.delete(name);
      console.log(`[sig3tunnel] "${name}" disconnected`);
      for (const [id, entry] of queue) {
        if (entry.peerName !== name) continue;
        clearTimeout(entry.timer);
        errorResponse(entry.res, 502);
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
