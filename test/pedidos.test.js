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

test('pedido gera um código de 5 dígitos, sem o cliente escolher nome', () => {
  const r = pedidos.criar({ descricao: 'Bossois Tec', segredo: SEG_A, ip: '1.1.1.1', agora: AGORA });
  assert.equal(r.status, 'pendente');
  assert.match(r.codigo, /^[1-9][0-9]{4}$/);
});

test('códigos gerados para pedidos vivos são distintos', () => {
  const codigos = new Set();
  for (let i = 0; i < 20; i++) {
    codigos.add(pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: `10.0.0.${i}`, agora: AGORA }).codigo);
  }
  assert.equal(codigos.size, 20);
});

test('descrição vazia e segredo curto são recusados', () => {
  assert.equal(erro(() => pedidos.criar({ descricao: '  ', segredo: SEG_A, ip: '1' })), 'descricao_invalida');
  assert.equal(erro(() => pedidos.criar({ descricao: 'x', segredo: 'curto', ip: '1' })), 'segredo_invalido');
});

test('limite de pedidos pendentes por IP', () => {
  for (let i = 0; i < pedidos.MAX_PENDENTES_POR_IP; i++)
    pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '9.9.9.9' });
  assert.equal(erro(() => pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '9.9.9.9' })), 'muitos_pedidos');
  // Outro IP continua podendo pedir.
  assert.equal(erro(() => pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '8.8.8.8' })), null);
});

test('pendente não entrega token', () => {
  const { id } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1' });
  assert.deepEqual(pedidos.entregar(id, SEG_A), { status: 'pendente' });
});

test('segredo errado não entrega, mesmo aprovado', () => {
  const { id } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1' });
  pedidos.aprovar(id);
  assert.equal(erro(() => pedidos.entregar(id, SEG_B)), 'segredo_errado');
});

test('aprovado entrega um token com escopo do código, uma única vez', () => {
  const { id, codigo } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1' });
  pedidos.aprovar(id, Date.now(), 'Daniel');

  const r = pedidos.entregar(id, SEG_A);
  assert.equal(r.status, 'aprovado');
  assert.equal(r.nome, codigo);
  assert.ok(tokens.validate(r.token, codigo), 'token vale para o código aprovado');
  assert.equal(tokens.validate(r.token, 'outro'), null, 'e não vale para outro nome');

  assert.equal(erro(() => pedidos.entregar(id, SEG_A)), 'ja_entregue');
});

test('aprovação registra quem liberou', () => {
  const { id } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1' });
  const p = pedidos.aprovar(id, Date.now(), 'Daniel');
  assert.equal(p.liberadoPor, 'Daniel');
});

test('recusado não entrega token', () => {
  const { id } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1' });
  pedidos.recusar(id);
  assert.deepEqual(pedidos.entregar(id, SEG_A), { status: 'recusado' });
});

test('pedido pendente expira após 24 h e não é mais aprovável', () => {
  const { id } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1', agora: AGORA });
  const depois = AGORA + pedidos.VALIDADE_MS + 1;
  assert.deepEqual(pedidos.entregar(id, SEG_A, depois), { status: 'expirado' });
  assert.equal(erro(() => pedidos.aprovar(id, depois)), 'estado_invalido');
});

test('modo de teste (autoAprovar) entrega na primeira consulta', () => {
  const { id, status } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1', autoAprovar: true });
  assert.equal(status, 'aprovado');
  assert.equal(pedidos.entregar(id, SEG_A).status, 'aprovado');
});

test('listar não expõe o hash do segredo', () => {
  pedidos.criar({ descricao: 'x', segredo: SEG_A, ip: '1' });
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
  const novo = await pedir('POST', '/api/pedidos', { corpo: { descricao: 'Bossois Tec', segredo: SEG_A } });
  assert.equal(novo.status, 201);
  assert.match(novo.corpo.codigo, /^[1-9][0-9]{4}$/);
  assert.equal(novo.corpo.status, 'pendente');
  const { id, codigo } = novo.corpo;

  const antes = await pedir('GET', `/api/pedidos/${id}`, { cabecalhos: { 'x-pedido-segredo': SEG_A } });
  assert.equal(antes.corpo.status, 'pendente');

  const sem = await pedir('POST', `/api/admin/pedidos/${id}/aprovar`);
  assert.equal(sem.status, 403, 'aprovar sem senha de admin é negado');

  const ok = await pedir('POST', `/api/admin/pedidos/${id}/aprovar`, {
    corpo: { liberadoPor: 'Daniel' },
    cabecalhos: { 'x-admin-senha': 'senha-de-teste-123' },
  });
  assert.equal(ok.status, 200);

  const entregue = await pedir('GET', `/api/pedidos/${id}`, { cabecalhos: { 'x-pedido-segredo': SEG_A } });
  assert.equal(entregue.status, 200);
  assert.equal(entregue.corpo.status, 'aprovado');
  assert.equal(entregue.corpo.nome, codigo);
  assert.ok(entregue.corpo.token.startsWith('sig3_'));
  assert.ok(tokens.validate(entregue.corpo.token, codigo));
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

test('HTTP: /admin serve o painel HTML no domínio raiz', async () => {
  const r = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: porta, path: '/admin' }, res => {
      let d = ''; res.on('data', c => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, tipo: res.headers['content-type'], d }));
    }).on('error', reject);
  });
  assert.equal(r.status, 200);
  assert.match(r.tipo, /text\/html/);
  assert.match(r.d, /SIG3\.Tunnel - pedidos/);
});

test('limite de pedidos por IP numa hora vale mesmo depois de aprovados', () => {
  const ip = '5.5.5.5';
  for (let i = 0; i < pedidos.MAX_CRIADOS_IP_HORA; i++) {
    const { id } = pedidos.criar({ descricao: 'x', segredo: SEG_A, ip, agora: AGORA });
    pedidos.aprovar(id, AGORA, 'teste');   // aprovado não conta como pendente, mas conta na hora
  }
  assert.equal(erro(() => pedidos.criar({ descricao: 'x', segredo: SEG_A, ip, agora: AGORA + 1000 })), 'muitos_pedidos');
  // Uma hora depois, o IP pode pedir de novo.
  assert.equal(erro(() => pedidos.criar({ descricao: 'x', segredo: SEG_A, ip, agora: AGORA + 61 * 60 * 1000 })), null);
});

test('recusado antigo é podado do arquivo na próxima criação', () => {
  const velho = new Date(Date.now() - pedidos.PODA_MS - 60_000).toISOString();
  fs.writeFileSync(path.join(tmp, 'pedidos.json'), JSON.stringify([{
    id: 'aaaaaaaaaaaaaaaa', codigo: '11111', descricao: 'antigo', segredoHash: 'x', ip: '1',
    criado: velho, expira: velho, status: 'recusado',
  }]));

  pedidos.criar({ descricao: 'novo', segredo: SEG_A, ip: '2' });

  const ids = pedidos.listar().map(p => p.id);
  assert.ok(!ids.includes('aaaaaaaaaaaaaaaa'), 'o recusado antigo saiu');
});

test('HTTP: login de admin é bloqueado depois de muitas senhas erradas', async () => {
  const cab = { 'x-real-ip': '7.7.7.7', 'x-admin-senha': 'errada' };
  for (let i = 0; i < 10; i++) {
    assert.equal((await pedir('GET', '/api/admin/pedidos', { cabecalhos: cab })).status, 403);
  }
  const bloqueado = await pedir('GET', '/api/admin/pedidos', { cabecalhos: cab });
  assert.equal(bloqueado.status, 429);
  assert.equal(bloqueado.corpo.erro, 'muitas_tentativas');
});
