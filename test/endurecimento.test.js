'use strict';

// Endurecimento do relay (auditoria de 29/10/2026): upgrade só WebSocket e só depois de um 101, pedido de outro site
// com o cookie do técnico, upgrade aberto de técnico revogado, bloco IPv6 nos limites e segredo do cookie fraco.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http   = require('node:http');
const net    = require('node:net');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');
const { execFileSync } = require('node:child_process');
const WebSocket = require('ws');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-endurecimento-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;

const { serve, derrubarUpgradesDeRevogados } = require('../src/relay');
const tokens   = require('../src/tokens');
const tecnicos = require('../src/tecnicos');
const { chaveDe, criarLimitadorDeFalhas } = require('../src/limite');

const tecnico = tecnicos.emitir('Teste');
const chave   = tecnico.raw;
const cookie  = tecnicos.montarCookie(tecnico, 'echo').split(';')[0];   // sig3tec=<id>.<expira>.<assinatura>

let relayServer, relayPort, echoServer, echoPort, peer;
let respondeComo101 = true;   // o "SIG3" de teste: true repassa ao eco (101 de verdade); false responde um 200 qualquer
const recebidoNoCliente = [];

function freePort() {
  return new Promise((resolve, reject) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

function startEcho() {
  const server = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  const wss = new WebSocket.Server({ server });
  wss.on('connection', ws => ws.on('message', (data, isBinary) => ws.send(data, { binary: isBinary })));
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

function openUpgrade(msg, ws, sockets) {
  if (!respondeComo101) {
    // SIG3 que não obedece: responde ao upgrade com uma resposta HTTP comum e completa, e deixa tudo aberto.
    sockets.set(msg.id, { write: b => recebidoNoCliente.push(b.toString()), end() {} });
    const resp = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok';
    ws.send(Buffer.concat([Buffer.from(msg.id, 'ascii'), Buffer.from(resp)]), { binary: true });
    return;
  }
  const headers = { ...msg.headers, host: `localhost:${echoPort}` };
  const sock = net.connect(echoPort, '127.0.0.1');
  sockets.set(msg.id, sock);
  const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`);
  sock.write(`${msg.method} ${msg.url} HTTP/1.1\r\n${lines.join('\r\n')}\r\n\r\n`);
  sock.on('data', chunk => ws.send(Buffer.concat([Buffer.from(msg.id, 'ascii'), chunk]), { binary: true }));
  sock.on('close', () => { if (sockets.delete(msg.id)) ws.send(JSON.stringify({ type: 'up-close', id: msg.id })); });
  sock.on('error', () => sock.destroy());
}

function openPeer(tok) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3/echo`, { headers: { authorization: `Bearer ${tok}` } });
    const sockets = new Map();
    ws.on('message', (raw, isBinary) => {
      if (isBinary) return sockets.get(raw.subarray(0, 36).toString('ascii'))?.write(raw.subarray(36));
      const msg = JSON.parse(raw);
      if (msg.type === 'upgrade') return openUpgrade(msg, ws, sockets);
      if (msg.type === 'up-close') { sockets.get(msg.id)?.end(); sockets.delete(msg.id); }
    });
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
  });
}

// Pedido HTTP comum; devolve só o status.
function pedir(headers, metodo = 'GET', p = '/') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: relayPort, method: metodo, path: p,
      headers: { host: 'tunel-echo.bossoistec.test', ...headers } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject);
    req.end();
  });
}

// Upgrade cru: devolve a primeira linha da resposta e o socket.
function upgradeCru(headersExtras, host = 'tunel-echo.bossoistec.test') {
  return new Promise((resolve, reject) => {
    const s = net.connect(relayPort, '127.0.0.1');
    let acumulado = '';
    s.on('data', d => {
      acumulado += d.toString();
      if (acumulado.includes('\r\n')) resolve({ linha: acumulado.split('\r\n')[0], socket: s, acumulado: () => acumulado });
    });
    s.on('error', reject);
    s.on('close', () => resolve({ linha: acumulado.split('\r\n')[0], socket: s, acumulado: () => acumulado }));
    const extras = Object.entries(headersExtras).map(([k, v]) => `${k}: ${v}`).join('\r\n');
    s.write(`GET /_blazor HTTP/1.1\r\nHost: ${host}\r\n${extras}\r\n\r\n`);
  });
}

before(async () => {
  relayPort   = await freePort();
  relayServer = serve(relayPort, '127.0.0.1');
  await new Promise((resolve, reject) => { relayServer.once('listening', resolve); relayServer.once('error', reject); });
  echoServer = await startEcho();
  echoPort   = echoServer.address().port;
});

after(() => {
  peer?.terminate();
  relayServer.closeAllConnections();
  echoServer.closeAllConnections();
  relayServer.close();
  echoServer.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

// ── upgrade: só WebSocket ───────────────────────────────────────────────────────────────

test('upgrade que não é WebSocket é recusado com 400 (não vira um pipe cru até a porta local do cliente)', async () => {
  const r = await upgradeCru({ 'X-Sig3-Chave': chave, Connection: 'Upgrade', Upgrade: 'foo' });
  assert.match(r.linha, /400/);
  r.socket.destroy();
});

// ── upgrade: só depois de um 101 ────────────────────────────────────────────────────────

test('resposta do SIG3 ao upgrade que não é 101 derruba o socket e nada que chegar depois vai ao cliente', async () => {
  peer = await openPeer(tokens.issue('echo').raw);
  respondeComo101 = false;
  recebidoNoCliente.length = 0;

  const s = net.connect(relayPort, '127.0.0.1');
  const lido = [];
  s.on('data', d => lido.push(d.toString()));
  const fechou = new Promise(resolve => s.once('close', resolve));
  s.on('error', () => {});
  s.write(`GET /_blazor HTTP/1.1\r\nHost: tunel-echo.bossoistec.test\r\nX-Sig3-Chave: ${chave}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`);
  await Promise.race([fechou, new Promise(r => setTimeout(r, 1500))]);

  // um nginx que guardasse a conexão para reaproveitar mandaria aqui o pedido de outra pessoa
  s.write('GET /api-tunel/admin/pedidos HTTP/1.1\r\nHost: tunel.bossoistec.test\r\nAuthorization: Bearer JWT-DE-OUTRO-USUARIO\r\n\r\n');
  await new Promise(r => setTimeout(r, 300));

  assert.ok(!lido.join('').includes('200 OK'), 'a resposta que não é 101 não pode chegar ao navegador');
  assert.ok(s.destroyed, 'o socket tem de ser derrubado');
  assert.ok(!recebidoNoCliente.join('').includes('JWT-DE-OUTRO-USUARIO'), 'o pedido de outra pessoa não pode chegar ao SIG3');

  respondeComo101 = true;
  peer.terminate();
  await new Promise(r => setTimeout(r, 100));
});

// ── pedido de outro site com o cookie do técnico ────────────────────────────────────────

test('cookie do técnico: pedido disparado por outro site (fetch, POST) é recusado com 403', async () => {
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors' }, 'POST', '/algo'), 403);
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'no-cors' }, 'GET', '/algo'), 403);
  assert.equal(await pedir({ cookie, origin: 'https://tunel-outro.bossoistec.test' }, 'POST', '/algo'), 403);
  assert.equal(await pedir({ cookie, origin: 'null' }, 'POST', '/algo'), 403);
});

test('cookie do técnico: a própria página (mesma origem), a barra de endereço e o clique num link passam', async () => {
  // sem túnel conectado o relay responde 503, o que prova que passou da autorização e da guarda de origem
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'same-origin', origin: 'https://tunel-echo.bossoistec.test' }, 'POST', '/algo'), 503);
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'none', 'sec-fetch-mode': 'navigate' }), 503);
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate' }), 503);
  assert.equal(await pedir({ cookie }), 503);   // cliente sem Fetch Metadata (curl)
});

test('cookie do técnico: navegação por formulário (POST) vinda de outro site é recusada', async () => {
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate' }, 'POST', '/algo'), 403);
});

test('cookie do técnico: o túnel de outro cliente não pode enquadrar este (iframe) e clicar por cima', async () => {
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'iframe' }), 403);
  assert.equal(await pedir({ cookie, 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'iframe' }), 503, 'o próprio túnel pode usar iframe (o visor de PDF)');
});

test('a chave no cabeçalho não passa pela guarda de origem (quem manda esse cabeçalho é o SIG3.Client, não um site)', async () => {
  assert.equal(await pedir({ 'x-sig3-chave': chave, 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'cors' }, 'POST', '/algo'), 503);
});

test('WebSocket com o cookie e Origin de outro túnel (CSWSH entre túneis irmãos) é recusado com 403', async () => {
  const r = await upgradeCru({ cookie, Origin: 'https://tunel-outro.bossoistec.test', Connection: 'Upgrade', Upgrade: 'websocket' });
  assert.match(r.linha, /403/);
  r.socket.destroy();
  const ok = await upgradeCru({ cookie, Origin: 'https://tunel-echo.bossoistec.test', Connection: 'Upgrade', Upgrade: 'websocket' });
  assert.match(ok.linha, /503/, 'a própria página passa da guarda (503: sem túnel conectado)');
  ok.socket.destroy();
});

// ── chave revogada derruba o que já estava aberto ───────────────────────────────────────

test('revogar a chave do técnico derruba o upgrade que ele já tinha aberto', async () => {
  const t2 = tecnicos.emitir('Sera revogado');
  peer = await openPeer(tokens.issue('echo').raw);   // o token anterior continua válido; o nome 'echo' ficou livre

  const browser = new WebSocket(`ws://127.0.0.1:${relayPort}/_blazor?id=1`, { headers: { host: 'tunel-echo.bossoistec.test', 'x-sig3-chave': t2.raw } });
  await new Promise((resolve, reject) => { browser.once('open', resolve); browser.once('error', reject); });
  const fechou = new Promise(resolve => browser.once('close', resolve));

  assert.ok(tecnicos.revogar(t2.id));
  derrubarUpgradesDeRevogados();
  await Promise.race([fechou, new Promise((_, rej) => setTimeout(() => rej(new Error('o upgrade do técnico revogado continuou aberto')), 3000))]);
  peer.terminate();
});

// ── limites por IP: IPv6 conta pelo bloco /64 ───────────────────────────────────────────

test('IPv6: endereços do mesmo bloco /64 dividem a conta; blocos diferentes e IPv4 ficam separados', () => {
  assert.equal(chaveDe('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), chaveDe('2001:db8:1:2::1'));
  assert.equal(chaveDe('2001:DB8:1:2::1'), chaveDe('2001:db8:1:2:0:0:0:9'));
  assert.notEqual(chaveDe('2001:db8:1:2::1'), chaveDe('2001:db8:1:3::1'));
  assert.equal(chaveDe('::ffff:203.0.113.7'), '203.0.113.7');
  assert.equal(chaveDe('203.0.113.7'), '203.0.113.7');
  assert.equal(chaveDe('lixo:::'), 'lixo:::', 'o que não se reconhece fica como veio');
});

test('IPv6: quem troca de endereço dentro do bloco a cada tentativa é bloqueado do mesmo jeito', () => {
  const lim = criarLimitadorDeFalhas({ max: 5, janelaMs: 60_000, bloqueioMs: 60_000 });
  for (let i = 0; i < 5; i++) lim.falha(`2001:db8:9:9:${i}::1`);
  assert.equal(lim.bloqueado('2001:db8:9:9:ffff::7'), true);
  assert.equal(lim.bloqueado('2001:db8:9:8::7'), false);
});

// ── segredo do cookie ───────────────────────────────────────────────────────────────────

test('SIG3TUNNEL_SEGREDO curto impede o relay de subir; com 32 caracteres ou mais, sobe', () => {
  const rodar = segredo => execFileSync(process.execPath, ['-e', "require('./src/tecnicos').verificarSegredo()"], {
    cwd: path.join(__dirname, '..'), stdio: 'pipe',
    env: { ...process.env, SIG3TUNNEL_CONFIG_DIR: tmp, SIG3TUNNEL_SEGREDO: segredo },
  });
  assert.throws(() => rodar('curto'), /menos de 32 caracteres/);
  assert.doesNotThrow(() => rodar('x'.repeat(40)));
});
