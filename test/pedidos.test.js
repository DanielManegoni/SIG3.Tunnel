'use strict';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http   = require('node:http');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-pedidos-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;
process.env.SIG3TUNNEL_ADMIN_SENHA = 'senha-de-teste-123';

const pedidos = require('../src/pedidos');
const tokens  = require('../src/tokens');
const { serve } = require('../src/relay');

const SEG_A = 'a'.repeat(40);
const SEG_B = 'b'.repeat(40);
const AGORA = Date.parse('2026-10-06T12:00:00Z');

beforeEach(() => {
  for (const f of ['pedidos.json', 'tokens.json']) fs.rmSync(path.join(tmp, f), { force: true });
});

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

function erro(fn) {
  try { fn(); } catch (e) { return e.codigo; }
  return null;
}

test('pedido válido fica pendente', () => {
  const r = pedidos.criar({ dns: '7856', descricao: 'Bossois Tec', segredo: SEG_A, ip: '1.1.1.1', agora: AGORA });
  assert.equal(r.status, 'pendente');
});

test('nome fora do padrão é recusado', () => {
  assert.equal(erro(() => pedidos.criar({ dns: 'nome com espaco', descricao: 'x', segredo: SEG_A, ip: '1' })), 'nome_invalido');
  assert.equal(erro(() => pedidos.criar({ dns: '-inicio', descricao: 'x', segredo: SEG_A, ip: '1' })), 'nome_invalido');
});

test('descrição vazia e segredo curto são recusados', () => {
  assert.equal(erro(() => pedidos.criar({ dns: 'a1', descricao: '  ', segredo: SEG_A, ip: '1' })), 'descricao_invalida');
  assert.equal(erro(() => pedidos.criar({ dns: 'a1', descricao: 'x', segredo: 'curto', ip: '1' })), 'segredo_invalido');
});

test('segundo pedido para o mesmo nome é recusado enquanto o primeiro vive', () => {
  pedidos.criar({ dns: '7856', descricao: 'um', segredo: SEG_A, ip: '1' });
  assert.equal(erro(() => pedidos.criar({ dns: '7856', descricao: 'dois', segredo: SEG_B, ip: '2' })), 'nome_em_uso');
});

test('limite de pedidos pendentes por IP', () => {
  for (let i = 0; i < pedidos.MAX_PENDENTES_POR_IP; i++)
    pedidos.criar({ dns: `n${i}`, descricao: 'x', segredo: SEG_A, ip: '9.9.9.9' });
  assert.equal(erro(() => pedidos.criar({ dns: 'extra', descricao: 'x', segredo: SEG_A, ip: '9.9.9.9' })), 'muitos_pedidos');
  // Outro IP continua podendo pedir.
  assert.equal(erro(() => pedidos.criar({ dns: 'outro', descricao: 'x', segredo: SEG_A, ip: '8.8.8.8' })), null);
});

test('pendente não entrega token', () => {
  const { id } = pedidos.criar({ dns: 'p1', descricao: 'x', segredo: SEG_A, ip: '1' });
  assert.deepEqual(pedidos.entregar(id, SEG_A), { status: 'pendente' });
});

test('segredo errado não entrega, mesmo aprovado', () => {
  const { id } = pedidos.criar({ dns: 'p2', descricao: 'x', segredo: SEG_A, ip: '1' });
  pedidos.aprovar(id);
  assert.equal(erro(() => pedidos.entregar(id, SEG_B)), 'segredo_errado');
});

test('aprovado entrega um token com escopo do nome, uma única vez', () => {
  const { id } = pedidos.criar({ dns: '7856', descricao: 'x', segredo: SEG_A, ip: '1' });
  pedidos.aprovar(id);

  const r = pedidos.entregar(id, SEG_A);
  assert.equal(r.status, 'aprovado');
  assert.equal(r.nome, '7856');
  assert.ok(tokens.validate(r.token, '7856'), 'token vale para o nome aprovado');
  assert.equal(tokens.validate(r.token, 'outro-nome'), null, 'e não vale para outro nome');

  assert.equal(erro(() => pedidos.entregar(id, SEG_A)), 'ja_entregue');
});

test('recusado não entrega e libera o nome', () => {
  const { id } = pedidos.criar({ dns: 'rec', descricao: 'x', segredo: SEG_A, ip: '1' });
  pedidos.recusar(id);
  assert.deepEqual(pedidos.entregar(id, SEG_A), { status: 'recusado' });
  assert.equal(erro(() => pedidos.criar({ dns: 'rec', descricao: 'x', segredo: SEG_B, ip: '2' })), null);
});

test('pedido pendente expira após 24 h e não é mais aprovável', () => {
  const { id } = pedidos.criar({ dns: 'exp', descricao: 'x', segredo: SEG_A, ip: '1', agora: AGORA });
  const depois = AGORA + pedidos.VALIDADE_MS + 1;
  assert.deepEqual(pedidos.entregar(id, SEG_A, depois), { status: 'expirado' });
  assert.equal(erro(() => pedidos.aprovar(id, depois)), 'estado_invalido');
});

test('modo de teste (autoAprovar) entrega na primeira consulta', () => {
  const { id, status } = pedidos.criar({ dns: 'auto', descricao: 'x', segredo: SEG_A, ip: '1', autoAprovar: true });
  assert.equal(status, 'aprovado');
  assert.equal(pedidos.entregar(id, SEG_A).status, 'aprovado');
});

test('listar não expõe o hash do segredo', () => {
  pedidos.criar({ dns: 'lista', descricao: 'x', segredo: SEG_A, ip: '1' });
  for (const p of pedidos.listar()) assert.equal(p.segredoHash, undefined);
});

// ---- HTTP ponta a ponta (relay real, sem túnel) -------------------------------

let relay, porta;

function freePort() {
  return new Promise((resolve, reject) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

function pedir(metodo, caminho, { corpo, cabecalhos = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: porta, method: metodo, path: caminho,
      headers: { 'content-type': 'application/json', ...cabecalhos } }, res => {
      let dados = '';
      res.on('data', c => { dados += c; });
      res.on('end', () => resolve({ status: res.statusCode, corpo: dados ? JSON.parse(dados) : null }));
    });
    req.on('error', reject);
    req.end(corpo ? JSON.stringify(corpo) : undefined);
  });
}

before(async () => {
  porta = await freePort();
  relay = serve(porta, '127.0.0.1');
  await new Promise((resolve, reject) => { relay.once('listening', resolve); relay.once('error', reject); });
});

after(() => {
  relay.closeAllConnections();
  relay.close();
});

test('HTTP: pedir, consultar, aprovar pelo admin e pegar o token', async () => {
  const novo = await pedir('POST', '/api/pedidos', { corpo: { dns: 'http1', descricao: 'Bossois Tec', segredo: SEG_A } });
  assert.equal(novo.status, 201);
  assert.equal(novo.corpo.status, 'pendente');
  const id = novo.corpo.id;

  const antes = await pedir('GET', `/api/pedidos/${id}`, { cabecalhos: { 'x-pedido-segredo': SEG_A } });
  assert.equal(antes.corpo.status, 'pendente');

  const sem = await pedir('POST', `/api/admin/pedidos/${id}/aprovar`);
  assert.equal(sem.status, 403, 'aprovar sem senha de admin é negado');

  const ok = await pedir('POST', `/api/admin/pedidos/${id}/aprovar`, { cabecalhos: { 'x-admin-senha': 'senha-de-teste-123' } });
  assert.equal(ok.status, 200);

  const entregue = await pedir('GET', `/api/pedidos/${id}`, { cabecalhos: { 'x-pedido-segredo': SEG_A } });
  assert.equal(entregue.status, 200);
  assert.equal(entregue.corpo.status, 'aprovado');
  assert.ok(entregue.corpo.token.startsWith('sig3_'));
  assert.ok(tokens.validate(entregue.corpo.token, 'http1'));
});

test('HTTP: lista de admin sem senha é negada e a senha errada também', async () => {
  assert.equal((await pedir('GET', '/api/admin/pedidos')).status, 403);
  assert.equal((await pedir('GET', '/api/admin/pedidos', { cabecalhos: { 'x-admin-senha': 'errada' } })).status, 403);
});

test('HTTP: JSON inválido e rota desconhecida', async () => {
  const r = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: porta, method: 'POST', path: '/api/pedidos',
      headers: { 'content-type': 'application/json' } }, res => {
      let d = ''; res.on('data', c => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, d }));
    });
    req.on('error', reject); req.end('{nao-e-json');
  });
  assert.equal(r.status, 400);
  assert.equal((await pedir('GET', '/api/nada-aqui')).status, 404);
});
