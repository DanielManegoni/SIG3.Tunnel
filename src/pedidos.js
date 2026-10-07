'use strict';

// Pedidos de túnel. Quem pede NÃO escolhe o nome: o servidor sorteia um código de 5 dígitos, que vira
// o prefixo do endereço (<codigo>.tunel.<dominio>). Só depois da aprovação de um administrador o
// token é emitido, e só é entregue a quem tem o segredo do pedido.

const fs     = require('fs');
const crypto = require('crypto');
const { PEDIDOS_FILE, ensureDir } = require('./paths');
const tokens = require('./tokens');

const MAX_PENDENTES_POR_IP  = 5;
const MAX_PENDENTES         = 200;
const MAX_CRIADOS_IP_HORA   = 10;   // pedidos criados por um IP numa hora (qualquer status)
const MAX_CRIADOS_HORA      = 100;  // pedidos criados por todos numa hora
const VALIDADE_MS           = 24 * 60 * 60 * 1000; // pedido pendente expira em 24 h
const PODA_MS               = 7 * 24 * 60 * 60 * 1000; // recusado/expirado some do arquivo após 7 dias
const UMA_HORA_MS           = 60 * 60 * 1000;
const TENTATIVAS_CODIGO     = 50;

// Código ocupado = pedido vivo (pendente/aprovado) ou já entregue. Recusado ou expirado libera o código.
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

// Sorteia 5 dígitos (10000 a 99999) que ainda não estão em uso.
function sortearCodigo(usados) {
  for (let i = 0; i < TENTATIVAS_CODIGO; i++) {
    const c = String(crypto.randomInt(10000, 100000));
    if (!usados.has(c)) return c;
  }
  throw new ErroPedido('sem_codigo', 'Não consegui gerar um código livre agora. Tente de novo.');
}

function criar({ descricao, segredo, ip, agora = Date.now(), autoAprovar = false }) {
  const desc = String(descricao || '').trim();
  if (desc.length < 1 || desc.length > 120) throw new ErroPedido('descricao_invalida', 'A descrição precisa ter de 1 a 120 caracteres.');

  if (typeof segredo !== 'string' || segredo.length < 32) throw new ErroPedido('segredo_invalido', 'Segredo do pedido ausente ou curto demais.');

  // Poda: recusado/expirado antigo some do arquivo (o código dele já estava livre).
  const lista = lerPedidos()
    .map(p => atual(p, agora))
    .filter(p => !(['recusado', 'expirado'].includes(p.status) && agora - Date.parse(p.criado) > PODA_MS));

  const pendentes = lista.filter(p => p.status === 'pendente');
  if (pendentes.length >= MAX_PENDENTES) throw new ErroPedido('fila_cheia', 'Há pedidos demais na fila. Tente mais tarde.');
  if (pendentes.filter(p => p.ip === ip).length >= MAX_PENDENTES_POR_IP)
    throw new ErroPedido('muitos_pedidos', 'Você já tem pedidos em aberto. Espere a resposta antes de pedir outro.');

  // Limite por hora, contando todos os status: quem aprova rápido não escapa do limite.
  const umaHora = lista.filter(p => agora - Date.parse(p.criado) < UMA_HORA_MS);
  if (umaHora.length >= MAX_CRIADOS_HORA) throw new ErroPedido('fila_cheia', 'Muitos pedidos nesta hora. Tente mais tarde.');
  if (umaHora.filter(p => p.ip === ip).length >= MAX_CRIADOS_IP_HORA)
    throw new ErroPedido('muitos_pedidos', 'Muitos pedidos deste computador nesta hora. Tente mais tarde.');

  const usados = new Set(lista.filter(p => OCUPA.has(p.status)).map(p => p.codigo));

  const pedido = {
    id: crypto.randomBytes(8).toString('hex'),
    codigo: sortearCodigo(usados),
    descricao: desc,
    segredoHash: hashSegredo(segredo),
    ip,
    criado: new Date(agora).toISOString(),
    expira: new Date(agora + VALIDADE_MS).toISOString(),
    status: autoAprovar ? 'aprovado' : 'pendente',
  };
  lista.push(pedido);
  gravarPedidos(lista);
  return { id: pedido.id, codigo: pedido.codigo, status: pedido.status };
}

function mudarStatus(id, de, para, agora, extra = {}) {
  const lista = lerPedidos().map(p => atual(p, agora));
  const i = lista.findIndex(p => p.id === id);
  if (i === -1) throw new ErroPedido('nao_encontrado', 'Pedido não encontrado.');
  if (!de.includes(lista[i].status)) throw new ErroPedido('estado_invalido', `Pedido está como "${lista[i].status}".`);
  lista[i].status = para;
  Object.assign(lista[i], extra);
  gravarPedidos(lista);
  return lista[i];
}

// liberadoPor é quem do lado da Bossois autorizou (texto livre, até 60 caracteres).
const aprovar = (id, agora = Date.now(), liberadoPor) => {
  const quem = String(liberadoPor || '').trim().slice(0, 60);
  return mudarStatus(id, ['pendente'], 'aprovado', agora, quem ? { liberadoPor: quem } : {});
};
const recusar = (id, agora = Date.now()) => mudarStatus(id, ['pendente'], 'recusado', agora);

// Entrega o token uma vez, a quem apresenta o segredo do pedido. O token é emitido agora, com escopo = código.
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

  // Marca como entregue ANTES de emitir: uma queda no meio não gera dois tokens para o mesmo pedido.
  // Se o token nem chegou a ser gravado, o pedido volta a aprovado e o próximo GET tenta de novo.
  lista[i].status = 'entregue';
  lista[i].entregue = new Date(agora).toISOString();
  gravarPedidos(lista);

  let emitido;
  try {
    emitido = tokens.issue(p.codigo);
  } catch (e) {
    lista[i].status = 'aprovado';
    delete lista[i].entregue;
    gravarPedidos(lista);
    throw e;
  }
  lista[i].tokenId = emitido.id;
  gravarPedidos(lista);
  return { status: 'aprovado', token: emitido.raw, nome: p.codigo };
}

// Visão do administrador: sem o hash do segredo.
function listar(agora = Date.now()) {
  return lerPedidos().map(p => {
    const q = atual(p, agora);
    const { segredoHash, ...publico } = q;
    return publico;
  });
}

module.exports = { criar, aprovar, recusar, entregar, listar, ErroPedido, MAX_PENDENTES_POR_IP, MAX_CRIADOS_IP_HORA, VALIDADE_MS, PODA_MS };
