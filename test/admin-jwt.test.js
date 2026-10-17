'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http   = require('node:http');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-jwt-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;
process.env.SIG3TUNNEL_JWT_SECRET = 'segredo-de-teste-do-jwt-com-40-caracteres-ok';

const { validarAdmin } = require('../src/jwt');
const { serve } = require('../src/relay');

const ISS = 'vsig_backup_manager_issuer';
const AUD = 'vsig_backup_manager_audience';
const SEG = 'a'.repeat(40);

function assinar(payload, segredo = process.env.SIG3TUNNEL_JWT_SECRET, alg = 'HS256') {
  const u = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const corpo = `${u({ alg, typ: 'JWT' })}.${u(payload)}`;
  return `${corpo}.${crypto.createHmac('sha256', segredo).update(corpo).digest('base64url')}`;
}
const valido = (extra = {}) => ({ login: 'x', profile: 'admin', iss: ISS, aud: AUD, exp: Math.floor(Date.now() / 1000) + 3600, ...extra });

let porta, relay;
before(async () => {
  porta = await new Promise(r => { const s = http.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
  relay = serve(porta, '127.0.0.1');
  await new Promise(r => relay.once('listening', r));
});
after(() => { relay.closeAllConnections(); relay.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

function pedir(metodo, caminho, { corpo, cabecalhos = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: porta, method: metodo, path: caminho,
      headers: { 'content-type': 'application/json', ...cabecalhos } }, res => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, corpo: d ? JSON.parse(d) : null }));
    });
    req.on('error', reject);
    req.end(corpo ? JSON.stringify(corpo) : undefined);
  });
}

test('jwt: aceita admin válido e recusa o resto', () => {
  const o = { segredo: process.env.SIG3TUNNEL_JWT_SECRET, issuer: ISS, audience: AUD };
  assert.ok(validarAdmin(assinar(valido()), o));
  assert.equal(validarAdmin(assinar(valido(), 'outro-segredo'), o), null);
  assert.equal(validarAdmin(assinar(valido({ profile: 'user' })), o), null);
  assert.equal(validarAdmin(assinar(valido({ exp: 1 })), o), null);
  assert.equal(validarAdmin(assinar(valido({ iss: 'x' })), o), null);
  assert.equal(validarAdmin(assinar(valido({ aud: 'x' })), o), null);
  assert.equal(validarAdmin(assinar(valido(), undefined, 'none'), o), null);
  assert.equal(validarAdmin(assinar(valido()), { ...o, segredo: '' }), null);
});

test('HTTP: editar nome e responsável com o JWT, e CORS do NewAdmin', async () => {
  const novo = await pedir('POST', '/api-tunel/pedidos', { corpo: { descricao: 'Antigo', segredo: SEG } });
  const { id } = novo.corpo;
  const auth = { authorization: `Bearer ${assinar(valido())}`, origin: 'https://app.bossoistec.com.br' };

  const sem = await pedir('PATCH', `/api-tunel/admin/pedidos/${id}`, { corpo: { descricao: 'Novo' } });
  assert.equal(sem.status, 403);

  const ok = await pedir('PATCH', `/api-tunel/admin/pedidos/${id}`, { corpo: { descricao: 'Novo', responsavel: 'Maria' }, cabecalhos: auth });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers['access-control-allow-origin'], 'https://app.bossoistec.com.br');
  assert.equal(ok.corpo.descricao, 'Novo');
  assert.equal(ok.corpo.responsavel, 'Maria');
  assert.equal(ok.corpo.segredoHash, undefined);

  const lista = await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: auth });
  assert.equal(lista.corpo.find(p => p.id === id).responsavel, 'Maria');

  const vazio = await pedir('PATCH', `/api-tunel/admin/pedidos/${id}`, { corpo: { descricao: '  ' }, cabecalhos: auth });
  assert.equal(vazio.status, 400);

  const pre = await pedir('OPTIONS', `/api-tunel/admin/pedidos/${id}`, { cabecalhos: { origin: 'https://app.bossoistec.com.br' } });
  assert.equal(pre.status, 204);
  const estranho = await pedir('OPTIONS', `/api-tunel/admin/pedidos/${id}`, { cabecalhos: { origin: 'https://mau.com' } });
  assert.equal(estranho.status, 403);
});

test('HTTP: excluir apaga o cliente e revoga o token', async () => {
  const tokens = require('../src/tokens');
  const auth = { authorization: `Bearer ${assinar(valido())}` };
  const novo = await pedir('POST', '/api-tunel/pedidos', { corpo: { descricao: 'Apagar', segredo: SEG } });
  const { id, codigo } = novo.corpo;
  await pedir('POST', `/api-tunel/admin/pedidos/${id}/aprovar`, { cabecalhos: auth });
  const ent = await pedir('GET', `/api-tunel/pedidos/${id}`, { cabecalhos: { 'x-pedido-segredo': SEG } });
  assert.ok(tokens.validate(ent.corpo.token, codigo));

  const sem = await pedir('DELETE', `/api-tunel/admin/pedidos/${id}`);
  assert.equal(sem.status, 403);
  const ok = await pedir('DELETE', `/api-tunel/admin/pedidos/${id}`, { cabecalhos: auth });
  assert.equal(ok.status, 200);

  assert.equal(tokens.validate(ent.corpo.token, codigo), null);
  const lista = await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: auth });
  assert.equal(lista.corpo.some(p => p.id === id), false);
  assert.equal((await pedir('DELETE', `/api-tunel/admin/pedidos/${id}`, { cabecalhos: auth })).status, 404);
});

test('registrarAtividade grava conexão e uso só em pedido entregue, e a lista traz online', async () => {
  const pedidos = require('../src/pedidos');
  const auth = { authorization: `Bearer ${assinar(valido())}` };
  const novo = await pedir('POST', '/api-tunel/pedidos', { corpo: { descricao: 'Uso', segredo: SEG } });
  const { id, codigo } = novo.corpo;

  assert.equal(pedidos.registrarAtividade(codigo, 'ultimaConexao'), false, 'pendente não registra');
  await pedir('POST', `/api-tunel/admin/pedidos/${id}/aprovar`, { cabecalhos: auth });
  await pedir('GET', `/api-tunel/pedidos/${id}`, { cabecalhos: { 'x-pedido-segredo': SEG } });

  const t = Date.parse('2026-10-17T12:00:00Z');
  assert.equal(pedidos.registrarAtividade(codigo, 'ultimaConexao', t), true);
  assert.equal(pedidos.registrarAtividade(codigo, 'ultimoUso', t + 1000), true);
  assert.throws(() => pedidos.registrarAtividade(codigo, 'segredoHash'));

  const lista = await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: auth });
  const c = lista.corpo.find(p => p.id === id);
  assert.equal(c.ultimaConexao, '2026-10-17T12:00:00.000Z');
  assert.equal(c.ultimoUso, '2026-10-17T12:00:01.000Z');
  assert.equal(c.online, false);
});

test('segredo de JWT curto (< 32) desliga o login de admin', async () => {
  const antigo = process.env.SIG3TUNNEL_JWT_SECRET;
  process.env.SIG3TUNNEL_JWT_SECRET = 'curto';
  try {
    const r = await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: { authorization: `Bearer ${assinar(valido(), 'curto')}`, 'x-real-ip': '4.4.4.4' } });
    assert.equal(r.status, 403);
  } finally { process.env.SIG3TUNNEL_JWT_SECRET = antigo; }
});

test('"liberado por" é o login do token, não o que vier no corpo', async () => {
  const auth = { authorization: `Bearer ${assinar(valido({ login: 'Maria' }))}` };
  const novo = await pedir('POST', '/api-tunel/pedidos', { corpo: { descricao: 'Quem', segredo: 'q'.repeat(40) } });
  await pedir('POST', `/api-tunel/admin/pedidos/${novo.corpo.id}/aprovar`, { corpo: { liberadoPor: 'Fulano Forjado' }, cabecalhos: auth });
  const lista = await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: auth });
  assert.equal(lista.corpo.find(p => p.id === novo.corpo.id).liberadoPor, 'Maria');
});

test('corpo JSON que não é objeto é recusado com 400', async () => {
  for (const corpo of ['null', '[1]', '"x"', '42']) {
    const r = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: porta, method: 'POST', path: '/api-tunel/pedidos', headers: { 'content-type': 'application/json', 'x-real-ip': '3.3.3.3' } },
        res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', reject); req.end(corpo);
    });
    assert.equal(r, 400, corpo);
  }
});

test('adivinhar o segredo de um pedido bloqueia o IP', async () => {
  const novo = await pedir('POST', '/api-tunel/pedidos', { corpo: { descricao: 'Alvo', segredo: 'a'.repeat(40) }, cabecalhos: { 'x-real-ip': '2.2.2.2' } });
  let ultimo;
  for (let i = 0; i < 12; i++) ultimo = (await pedir('GET', `/api-tunel/pedidos/${novo.corpo.id}`, { cabecalhos: { 'x-pedido-segredo': 'b'.repeat(40), 'x-real-ip': '1.1.1.1' } })).status;
  assert.equal(ultimo, 429);
});

test('taxa: mais de 120 chamadas por minuto do mesmo IP levam 429', async () => {
  let ultimo;
  for (let i = 0; i < 125; i++) ultimo = (await pedir('GET', '/api-tunel/nada', { cabecalhos: { 'x-real-ip': '6.6.6.6' } })).status;
  assert.equal(ultimo, 429);
});

test('perfil "user" lê a lista, mas não altera nada; token inválido continua negado', async () => {
  const user = { authorization: `Bearer ${assinar(valido({ profile: 'user', login: 'Paula' }))}` };
  const adm  = { authorization: `Bearer ${assinar(valido())}` };
  const novo = await pedir('POST', '/api-tunel/pedidos', { corpo: { descricao: 'Perfil', segredo: 'p'.repeat(40) } });
  const id = novo.corpo.id;

  assert.equal((await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: user })).status, 200);
  assert.equal((await pedir('PATCH', `/api-tunel/admin/pedidos/${id}`, { corpo: { descricao: 'X' }, cabecalhos: user })).status, 403);
  assert.equal((await pedir('POST', `/api-tunel/admin/pedidos/${id}/aprovar`, { cabecalhos: user })).status, 403);
  assert.equal((await pedir('POST', `/api-tunel/admin/pedidos/${id}/recusar`, { cabecalhos: user })).status, 403);
  assert.equal((await pedir('DELETE', `/api-tunel/admin/pedidos/${id}`, { cabecalhos: user })).status, 403);

  const lista = await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: adm });
  assert.equal(lista.corpo.find(p => p.id === id).descricao, 'Perfil', 'nada mudou');
  assert.equal((await pedir('GET', '/api-tunel/admin/pedidos', { cabecalhos: { authorization: `Bearer ${assinar(valido({ profile: 'outro' }))}`, 'x-real-ip': '5.5.5.5' } })).status, 403);
});
