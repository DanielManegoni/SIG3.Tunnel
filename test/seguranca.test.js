'use strict';

// Relay num PROCESSO À PARTE: o que se prova aqui é que mensagem hostil não derruba o relay inteiro.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http   = require('node:http');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');
const { spawn } = require('node:child_process');
const WebSocket = require('ws');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-seg-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;
const tokens   = require('../src/tokens');
const tecnicos = require('../src/tecnicos');

let filho, porta, token, chave;

const livre = () => new Promise(r => { const s = http.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

function get(caminho, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: porta, path: caminho, headers }, res => {
      let d = ''; res.on('data', c => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    });
    req.on('error', reject); req.end();
  });
}

const vivo = async () => (await get('/_sig3/ping')).body === 'ok';

function abrir(nome) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${porta}/_sig3/${nome}`, { headers: { authorization: `Bearer ${token.raw}` } });
    ws.once('open', () => resolve(ws)); ws.once('error', reject);
  });
}

before(async () => {
  token = tokens.issue('*');
  chave = tecnicos.emitir('Teste');
  porta = await livre();
  filho = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'sig3tunnel.js'), 'serve', '--port', String(porta)],
    { env: { ...process.env }, stdio: ['ignore', 'ignore', 'ignore'] });
  for (let i = 0; i < 50; i++) { try { if (await vivo()) return; } catch { /* ainda subindo */ } await new Promise(r => setTimeout(r, 100)); }
  throw new Error('relay não subiu');
});

after(() => { filho.kill(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('mensagem "null" de um cliente não derruba o relay', async () => {
  const ws = await abrir('cli1');
  ws.send('null');
  ws.send('[1,2');
  ws.send('42');
  await new Promise(r => setTimeout(r, 300));
  assert.equal(await vivo(), true);
  ws.close();
});

test('resposta com status ou cabeçalho inválido não derruba o relay e o visitante recebe 502', async () => {
  const ws = await abrir('cli2');
  const mal = [{ status: 99999, headers: {} }, { status: 200, headers: { 'x-ruim': 'a\r\nSet-Cookie: x=1' } }, { status: 'abc', headers: { 'content-type': 'text/plain' } }];
  let n = 0;
  ws.on('message', raw => { const m = JSON.parse(raw); ws.send(JSON.stringify({ id: m.id, ...mal[n++ % mal.length], body: '' })); });
  for (let i = 0; i < mal.length; i++) {
    const r = await get('/x', { host: 'tunel-cli2.exemplo.com', 'x-sig3-chave': chave.raw });
    assert.equal(r.status, 502, `resposta ruim #${i}`);
  }
  assert.equal(await vivo(), true);
  ws.close();
});

test('a raiz redireciona para bossoistec.com.br e não mostra versão nem texto do relay', async () => {
  const r = await get('/', { host: 'tunel.bossoistec.com.br' });
  assert.equal(r.status, 302);
  assert.equal(r.headers.location, 'https://bossoistec.com.br');
  assert.doesNotMatch(r.body, /sig3tunnel|relay|v\d/i);
});

test('respostas do próprio relay levam cabeçalhos de segurança', async () => {
  for (const r of [await get('/', { host: 'tunel.bossoistec.com.br' }), await get('/x', { host: 'tunel-zzz.bossoistec.com.br' }), await get('/api-tunel/admin/pedidos')]) {
    assert.equal(r.headers['x-content-type-options'], 'nosniff');
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.equal(r.headers['referrer-policy'], 'no-referrer');
    assert.equal(r.headers['x-frame-options'], 'DENY');
  }
});

test('chave de técnico errada repetida bloqueia o IP (429), e a chave certa também fica barrada', async () => {
  const ruim = { host: 'tunel-qualquer.bossoistec.com.br', 'x-sig3-chave': 'sig3t_' + 'f'.repeat(48), 'x-real-ip': '9.9.9.9' };
  let ultimo;
  for (let i = 0; i < 25; i++) ultimo = (await get('/', ruim)).status;
  assert.equal(ultimo, 429);
  const certa = await get('/', { host: 'tunel-qualquer.bossoistec.com.br', 'x-sig3-chave': chave.raw, 'x-real-ip': '9.9.9.9' });
  assert.equal(certa.status, 429, 'IP bloqueado fica fora mesmo com a chave certa');
  const outroIp = await get('/', { host: 'tunel-qualquer.bossoistec.com.br', 'x-sig3-chave': chave.raw, 'x-real-ip': '8.8.8.8' });
  assert.notEqual(outroIp.status, 429);
});

test('token de túnel errado repetido bloqueia o IP no WebSocket', async () => {
  const tentar = () => new Promise(resolve => {
    const ws = new WebSocket(`ws://127.0.0.1:${porta}/_sig3/x`, { headers: { authorization: 'Bearer sig3_errado', 'x-real-ip': '7.7.7.7' } });
    ws.once('close', (code, motivo) => resolve(String(motivo)));
    ws.once('error', () => resolve('erro'));
  });
  let motivo;
  for (let i = 0; i < 35; i++) motivo = await tentar();
  assert.match(motivo, /rate limited/);
});

test('conteúdo repassado ao técnico: content-length vem do corpo real e hop-by-hop é descartado', async () => {
  const ws = await abrir('cli3');
  ws.on('message', raw => {
    const m = JSON.parse(raw);
    ws.send(JSON.stringify({ id: m.id, status: 200, headers: { 'content-length': '999', connection: 'upgrade', 'transfer-encoding': 'chunked', 'x-ok': 'sim' }, body: Buffer.from('abc').toString('base64') }));
  });
  const r = await get('/', { host: 'tunel-cli3.exemplo.com', 'x-sig3-chave': chave.raw });
  assert.equal(r.status, 200);
  assert.equal(r.body, 'abc');
  assert.equal(r.headers['content-length'], '3');
  assert.equal(r.headers['x-ok'], 'sim');
  ws.close();
});

test('chave do técnico e cookie do relay não chegam ao SIG3 do cliente', async () => {
  const ws = await abrir('cli4');
  let visto;
  ws.on('message', raw => {
    const m = JSON.parse(raw); visto = m.headers;
    ws.send(JSON.stringify({ id: m.id, status: 200, headers: {}, body: '' }));
  });
  await get('/', { host: 'tunel-cli4.exemplo.com', 'x-sig3-chave': chave.raw, cookie: 'sig3tec=abc; sessao=1' });
  assert.equal(visto['x-sig3-chave'], undefined);
  assert.equal(visto.cookie, 'sessao=1');
  ws.close();
});

test('sem X-Real-IP (loopback) os limites por IP não valem: um atacante não bloqueia todo mundo', async () => {
  let motivo;
  for (let i = 0; i < 40; i++) {
    motivo = await new Promise(resolve => {
      const ws = new WebSocket(`ws://127.0.0.1:${porta}/_sig3/y`, { headers: { authorization: 'Bearer sig3_errado' } });
      ws.once('close', (c, m) => resolve(String(m)));
      ws.once('error', () => resolve('erro'));
    });
  }
  assert.match(motivo, /unauthorized/, 'continua unauthorized, nunca rate limited');
  const ws = await abrir('legitimo');   // token certo, mesma origem loopback: tem de conectar
  ws.close();
});
