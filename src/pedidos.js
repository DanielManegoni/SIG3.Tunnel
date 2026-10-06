'use strict';

// Pedidos de nome de túnel. Qualquer pessoa pode PEDIR um nome; o token só existe depois de
// alguém com acesso de administrador aprovar, e só é entregue a quem tem o segredo do pedido.

const fs     = require('fs');
const crypto = require('crypto');
const { PEDIDOS_FILE, ensureDir } = require('./paths');
const tokens = require('./tokens');

const NOME_VALIDO   = /^[a-z0-9][a-z0-9-]{0,62}$/i;
const MAX_PENDENTES_POR_IP = 5;
const MAX_PENDENTES         = 200;
const VALIDADE_MS           = 24 * 60 * 60 * 1000; // pedido pendente expira em 24 h

// Nome ocupado = pedido vivo (pendente/aprovado) ou já entregue. Recusado ou expirado libera o nome.
const OCUPA = new Set(['pendente', 'aprovado', 'entregue']);

class ErroPedido extends Error {
  constructor(codigo, mensagem) { super(mensagem); this.codigo = codigo; }
}

function lerPedidos() {
  try {
    return JSON.parse(fs.readFileSync(PEDIDOS_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function gravarPedidos(lista) {
  ensureDir();
  fs.writeFileSync(PEDIDOS_FILE, JSON.stringify(lista, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
}

function hashSegredo(segredo) {
  return crypto.createHash('sha256').update(segredo).digest('hex');
}

// Pendente que passou da validade vira 'expirado' na hora de ler: não precisa de job de limpeza.
function atual(p, agora) {
  if (p.status === 'pendente' && agora > Date.parse(p.expira)) return { ...p, status: 'expirado' };
  return p;
}

function criar({ dns, descricao, segredo, ip, agora = Date.now(), autoAprovar = false }) {
  const nome = String(dns || '').toLowerCase();
  if (!NOME_VALIDO.test(nome)) throw new ErroPedido('nome_invalido', 'O nome só aceita letras, números e hífen (até 63).');

  const desc = String(descricao || '').trim();
  if (desc.length < 1 || desc.length > 120) throw new ErroPedido('descricao_invalida', 'A descrição precisa ter de 1 a 120 caracteres.');

  if (typeof segredo !== 'string' || segredo.length < 32) throw new ErroPedido('segredo_invalido', 'Segredo do pedido ausente ou curto demais.');

  const lista = lerPedidos().map(p => atual(p, agora));

  if (lista.some(p => p.dns === nome && OCUPA.has(p.status)))
    throw new ErroPedido('nome_em_uso', 'Esse nome já foi pedido ou está em uso.');

  const pendentes = lista.filter(p => p.status === 'pendente');
  if (pendentes.length >= MAX_PENDENTES) throw new ErroPedido('fila_cheia', 'Há pedidos demais na fila. Tente mais tarde.');
  if (pendentes.filter(p => p.ip === ip).length >= MAX_PENDENTES_POR_IP)
    throw new ErroPedido('muitos_pedidos', 'Você já tem pedidos em aberto. Espere a resposta antes de pedir outro.');

  const pedido = {
    id: crypto.randomBytes(8).toString('hex'),
    dns: nome,
    descricao: desc,
    segredoHash: hashSegredo(segredo),
    ip,
    criado: new Date(agora).toISOString(),
    expira: new Date(agora + VALIDADE_MS).toISOString(),
    status: autoAprovar ? 'aprovado' : 'pendente',
  };
  lista.push(pedido);
  gravarPedidos(lista);
  return { id: pedido.id, status: pedido.status };
}

function mudarStatus(id, de, para, agora = Date.now()) {
  const lista = lerPedidos().map(p => atual(p, agora));
  const i = lista.findIndex(p => p.id === id);
  if (i === -1) throw new ErroPedido('nao_encontrado', 'Pedido não encontrado.');
  if (!de.includes(lista[i].status)) throw new ErroPedido('estado_invalido', `Pedido está como "${lista[i].status}".`);
  lista[i].status = para;
  gravarPedidos(lista);
  return lista[i];
}

const aprovar = (id, agora) => mudarStatus(id, ['pendente'], 'aprovado', agora);
const recusar = (id, agora) => mudarStatus(id, ['pendente'], 'recusado', agora);

// Entrega o token uma vez, a quem apresenta o segredo do pedido. O token é emitido agora (escopo = nome).
function entregar(id, segredo, agora = Date.now()) {
  const lista = lerPedidos().map(p => atual(p, agora));
  const i = lista.findIndex(p => p.id === id);
  if (i === -1) throw new ErroPedido('nao_encontrado', 'Pedido não encontrado.');

  const p = lista[i];
  const esperado = Buffer.from(p.segredoHash, 'hex');
  const recebido = Buffer.from(hashSegredo(String(segredo || '')), 'hex');
  if (esperado.length !== recebido.length || !crypto.timingSafeEqual(esperado, recebido))
    throw new ErroPedido('segredo_errado', 'Segredo não confere.');

  if (p.status === 'pendente') return { status: 'pendente' };
  if (p.status === 'recusado') return { status: 'recusado' };
  if (p.status === 'expirado') return { status: 'expirado' };
  if (p.status === 'entregue') throw new ErroPedido('ja_entregue', 'O token deste pedido já foi entregue.');

  const emitido = tokens.issue(p.dns);
  lista[i].status = 'entregue';
  lista[i].tokenId = emitido.id;
  lista[i].entregue = new Date(agora).toISOString();
  gravarPedidos(lista);
  return { status: 'aprovado', token: emitido.raw, nome: p.dns };
}

// Visão do administrador: sem o hash do segredo.
function listar(agora = Date.now()) {
  return lerPedidos().map(p => {
    const q = atual(p, agora);
    const { segredoHash, ...publico } = q;
    return publico;
  });
}

module.exports = { criar, aprovar, recusar, entregar, listar, ErroPedido, MAX_PENDENTES_POR_IP, VALIDADE_MS };
