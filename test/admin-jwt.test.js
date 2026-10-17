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
process.env.SIG3TUNNEL_JWT_SECRET = 'segredo-de-teste-do-jwt';

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
