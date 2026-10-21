'use strict';

// API de pedidos de nome (ver src/pedidos.js). Rotas em /api-tunel/.
//
//   POST /api-tunel/pedidos                       { descricao, segredo }        -> 201 { id, codigo, status }
//   GET  /api-tunel/pedidos/<id>                  cabecalho X-Pedido-Segredo    -> { status, token? }
//   GET    /api-tunel/admin/pedidos                 Authorization: Bearer <jwt>  -> lista
//   GET    /api-tunel/admin/tecnicos                Authorization: Bearer <jwt>  -> [{ id, nome, criado }]  (chaves dos tecnicos do suporte; sem hash)
//   POST   /api-tunel/admin/tecnicos                { nome }  -> 201 { id, nome, chave }   a chave em claro SO aparece nesta resposta
//   DELETE /api-tunel/admin/tecnicos/<id>           revoga a chave (o cookie do tecnico perde a validade na hora)
//   PATCH  /api-tunel/admin/pedidos/<id>            { descricao?, responsavel? }
//   DELETE /api-tunel/admin/pedidos/<id>            revoga o token e derruba o tunel
//   POST   /api-tunel/admin/pedidos/<id>/aprovar
//   POST   /api-tunel/admin/pedidos/<id>/recusar
//
// Admin so por JWT do NewAdmin (perfil admin). Desligado se SIG3TUNNEL_JWT_SECRET estiver vazio.
// SIG3TUNNEL_AUTO_APROVAR=1 aprova sem humano: SO PARA TESTE. Com ele ligado, qualquer um recebe token.

const pedidos = require('./pedidos');
const jwt     = require('./jwt');
const tecnicos = require('./tecnicos');
const { criarLimitadorDeFalhas, criarLimitadorDeTaxa } = require('./limite');
const { CABECALHOS_SEGUROS } = require('./seguranca');

const MAX_JSON = 8 * 1024;

function enviar(res, status, corpo) {
  res.writeHead(status, { ...CABECALHOS_SEGUROS, 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(corpo));
}

function lerJson(req) {
  return new Promise((resolve, reject) => {
    const partes = [];
    let tamanho = 0;
    req.on('data', c => {
      tamanho += c.length;
      if (tamanho > MAX_JSON) {
        reject(new Error('corpo_grande'));
        req.destroy();
        return;
      }
      partes.push(c);
    });
    req.on('end', () => {
      try {
        const obj = JSON.parse(Buffer.concat(partes).toString('utf8') || '{}');
        if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) reject(new SyntaxError('o corpo precisa ser um objeto'));
        else resolve(obj);
      } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

// O IP de origem: o relay escuta só em 127.0.0.1, então quem conecta é o nginx. O X-Real-IP só é confiado
// quando a conexão é de loopback (o nginx o define e sobrescreve); de outra origem, vale o socket.
function ipDe(req) {
  const origem = req.socket.remoteAddress || 'desconhecido';
  const local = origem === '127.0.0.1' || origem === '::1' || origem === '::ffff:127.0.0.1';
  return (local && req.headers['x-real-ip']) || origem;
}

// Admin entra só pelo JWT do NewAdmin (Authorization: Bearer), que só vale com SIG3TUNNEL_JWT_SECRET
// definido. Emissor e audiência têm o padrão do NewAdmin e podem ser trocados. Um segredo curto é
// recusado: com menos de 32 caracteres dá para adivinhá-lo e forjar um token de admin.
const SEGREDO_MIN = 32;
let avisouSegredoCurto = false;

// Devolve { payload } ou { erro: 'invalido' | 'expirado' } (ver jwt.conferirToken).
function conferirAdmin(req) {
  const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
  if (!m) return { erro: 'invalido' };
  const segredo = process.env.SIG3TUNNEL_JWT_SECRET || '';
  if (segredo.length < SEGREDO_MIN) {
    if (segredo && !avisouSegredoCurto) {
      avisouSegredoCurto = true;
      console.error(`[sig3tunnel] SIG3TUNNEL_JWT_SECRET tem menos de ${SEGREDO_MIN} caracteres: login de admin DESLIGADO.`);
    }
    return { erro: 'invalido' };
  }
  return jwt.conferirToken(m[1], {
    segredo,
    issuer:   process.env.SIG3TUNNEL_JWT_ISSUER   || 'vsig_backup_manager_issuer',
    audience: process.env.SIG3TUNNEL_JWT_AUDIENCE || 'vsig_backup_manager_audience',
    perfis:   ['admin', 'user'],   // qualquer usuário do NewAdmin autenticado entra; o que ele PODE fazer é conferido por rota
  });
}

// Token de admin inválido: 10 erros em 15 min bloqueiam o IP por 15 min. Acerto zera a conta.
const falhasAdmin = criarLimitadorDeFalhas({ max: 10, janelaMs: 15 * 60_000, bloqueioMs: 15 * 60_000 });
// Segredo de pedido errado (quem tenta adivinhar o segredo de outro pedido).
const falhasSegredo = criarLimitadorDeFalhas({ max: 10, janelaMs: 15 * 60_000, bloqueioMs: 15 * 60_000 });
// Teto de chamadas por IP na API toda (inclusive as públicas).
const taxaApi = criarLimitadorDeTaxa({ max: 120, janelaMs: 60_000 });

// { estado: 'ok', login, perfil } | { estado: 'negado' } | { estado: 'expirado' } | { estado: 'bloqueado' }
// Token expirado (assinatura certa, só o prazo venceu) NÃO conta como falha: é uma sessão legítima que acabou, e
// contar derrubaria o IP de um escritório inteiro depois de dez cliques de quem esqueceu de entrar de novo.
function admin(req) {
  const ip = ipDe(req);
  if (falhasAdmin.bloqueado(ip)) return { estado: 'bloqueado' };
  const { payload, erro } = conferirAdmin(req);
  if (erro === 'expirado') return { estado: 'expirado' };
  if (!payload) {
    falhasAdmin.falha(ip);
    return { estado: 'negado' };
  }
  falhasAdmin.zerar(ip);
  return { estado: 'ok', login: String(payload.login || 'admin').slice(0, 60), perfil: payload.profile };
}

// Trilha de auditoria: quem (login do JWT, não o que veio no corpo) fez o quê, de onde.
const auditar = (req, login, acao, id) =>
  console.log(`[sig3tunnel] admin "${login}" ${acao} ${id} de ${ipDe(req)}`);

const STATUS_DE_ERRO = {
  nao_encontrado:      404,
  responsavel_invalido: 400,
  segredo_errado:      403,
  sem_codigo:          503,
  estado_invalido:     409,
  ja_entregue:         409,
  fila_cheia:          429,
  muitos_pedidos:      429,
};

// CORS só para o NewAdmin (origem fixa). SIG3TUNNEL_CORS_ORIGINS (vírgula) acrescenta outras, p.ex. em teste.
const ORIGENS_FIXAS = ['https://app.bossoistec.com.br', 'http://localhost:5173'];   // 5173 = vite do NewAdmin em desenvolvimento

function cors(req, res) {
  const extras = (process.env.SIG3TUNNEL_CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const lista = [...ORIGENS_FIXAS, ...extras];
  const origem = req.headers.origin;
  if (!origem || !lista.includes(origem)) return false;
  res.setHeader('Access-Control-Allow-Origin', origem);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Max-Age', '600');
  return true;
}

async function tratarApi(req, res, { derrubar = () => {}, conectado = () => false } = {}) {
  const p = new URL(req.url, 'http://relay').pathname;
  const comCors = cors(req, res);
  if (!taxaApi.permitir(ipDe(req))) return enviar(res, 429, { erro: 'muitas_chamadas', mensagem: 'Muitas chamadas. Espere um minuto.' });
  if (req.method === 'OPTIONS') {
    res.writeHead(comCors ? 204 : 403, CABECALHOS_SEGUROS);
    return res.end();
  }
  try {
    if (req.method === 'POST' && p === '/api-tunel/pedidos') {
      const corpo = await lerJson(req);
      const r = pedidos.criar({
        descricao: corpo.descricao,
        segredo: corpo.segredo,
        ip: ipDe(req),
        autoAprovar: process.env.SIG3TUNNEL_AUTO_APROVAR === '1',
      });
      return enviar(res, 201, r);
    }

    let m = p.match(/^\/api-tunel\/pedidos\/([0-9a-f]{16})$/);
    if (req.method === 'GET' && m) {
      const ip = ipDe(req);
      if (falhasSegredo.bloqueado(ip)) return enviar(res, 429, { erro: 'muitas_tentativas', mensagem: 'Muitas tentativas inválidas. Espere 15 minutos.' });
      try {
        return enviar(res, 200, pedidos.entregar(m[1], req.headers['x-pedido-segredo']));
      } catch (e) {
        if (e instanceof pedidos.ErroPedido && e.codigo === 'segredo_errado') falhasSegredo.falha(ip);
        throw e;
      }
    }

    if (p.startsWith('/api-tunel/admin/')) {
      const acesso = admin(req);
      if (acesso.estado === 'bloqueado') return enviar(res, 429, { erro: 'muitas_tentativas', mensagem: 'Muitas tentativas inválidas. Espere 15 minutos.' });
      if (acesso.estado === 'expirado') return enviar(res, 401, { erro: 'sessao_expirada', mensagem: 'Sua sessão expirou. Entre de novo.' });
      if (acesso.estado !== 'ok') return enviar(res, 403, { erro: 'admin_negado' });
      // Usuário comum só LÊ as listas (clientes e técnicos); aprovar, recusar, editar e excluir são do perfil admin.
      const leitura = req.method === 'GET' && (p === '/api-tunel/admin/pedidos' || p === '/api-tunel/admin/tecnicos');
      if (!leitura && acesso.perfil !== 'admin')
        return enviar(res, 403, { erro: 'somente_admin', mensagem: 'Só administradores podem alterar clientes do túnel.' });
      if (req.method === 'GET' && p === '/api-tunel/admin/pedidos') return enviar(res, 200, pedidos.listar().map(p => ({ ...p, online: conectado(p.codigo) })));
      // Só id, nome e data: o hash da chave nunca sai do relay.
      if (req.method === 'GET' && p === '/api-tunel/admin/tecnicos') return enviar(res, 200, tecnicos.listar());
      if (req.method === 'POST' && p === '/api-tunel/admin/tecnicos') {
        const corpo = await lerJson(req);
        const nome = typeof corpo.nome === 'string' ? corpo.nome.trim() : '';
        if (!nome) return enviar(res, 400, { erro: 'nome_invalido', mensagem: 'Informe o nome do técnico.' });
        if (nome.length > 60) return enviar(res, 400, { erro: 'nome_invalido', mensagem: 'O nome do técnico aceita até 60 caracteres.' });
        const t = tecnicos.emitir(nome);
        auditar(req, acesso.login, `emitiu a chave do técnico "${t.nome}"`, t.id);
        return enviar(res, 201, { id: t.id, nome: t.nome, chave: t.raw });
      }
      m = p.match(/^\/api-tunel\/admin\/tecnicos\/([0-9a-f]{8})$/);
      if (req.method === 'DELETE' && m) {
        const antes = tecnicos.listar().find(x => x.id === m[1]);
        if (!tecnicos.revogar(m[1])) return enviar(res, 404, { erro: 'nao_encontrado', mensagem: 'Técnico não encontrado.' });
        auditar(req, acesso.login, `revogou a chave do técnico "${antes ? antes.nome : '?'}"`, m[1]);
        return enviar(res, 200, { id: m[1], excluido: true });
      }
      m = p.match(/^\/api-tunel\/admin\/pedidos\/([0-9a-f]{16})$/);
      if (req.method === 'DELETE' && m) {
        const r = pedidos.excluir(m[1]);
        auditar(req, acesso.login, `excluiu o pedido (código ${r.codigo})`, r.id);
        derrubar(r.codigo);
        return enviar(res, 200, { id: r.id, excluido: true });
      }
      if (req.method === 'PATCH' && m) {
        const corpo = await lerJson(req);
        const r = pedidos.editar(m[1], { descricao: corpo.descricao, responsavel: corpo.responsavel });
        auditar(req, acesso.login, 'editou o pedido', r.id);
        return enviar(res, 200, r);
      }
      m = p.match(/^\/api-tunel\/admin\/pedidos\/([0-9a-f]{16})\/(aprovar|recusar)$/);
      if (req.method === 'POST' && m) {
        // Quem liberou é o login do token (não dá para forjar), e não o que o cliente mandar no corpo.
        const r = m[2] === 'aprovar' ? pedidos.aprovar(m[1], Date.now(), acesso.login) : pedidos.recusar(m[1]);
        auditar(req, acesso.login, m[2] === 'aprovar' ? 'aprovou o pedido' : 'recusou o pedido', r.id);
        return enviar(res, 200, { id: r.id, status: r.status });
      }
    }

    return enviar(res, 404, { erro: 'nao_encontrado' });
  } catch (e) {
    if (e instanceof pedidos.ErroPedido) {
      return enviar(res, STATUS_DE_ERRO[e.codigo] || 400, { erro: e.codigo, mensagem: e.message });
    }
    if (e instanceof SyntaxError) return enviar(res, 400, { erro: 'json_invalido' });
    if (e.message === 'corpo_grande') return enviar(res, 413, { erro: 'corpo_grande' });
    console.error('[sig3tunnel] erro na API:', e);
    return enviar(res, 500, { erro: 'interno' });
  }
}

module.exports = { tratarApi, ipDe };
