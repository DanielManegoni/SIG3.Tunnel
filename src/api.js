'use strict';

// API de pedidos de nome (ver src/pedidos.js). Rotas em /api/.
//
//   POST /api/pedidos                       { dns, descricao, segredo }   -> 201 { id, status }
//   GET  /api/pedidos/<id>                  cabecalho X-Pedido-Segredo    -> { status, token? }
//   GET  /api/admin/pedidos                 cabecalho X-Admin-Senha       -> lista
//   POST /api/admin/pedidos/<id>/aprovar    cabecalho X-Admin-Senha
//   POST /api/admin/pedidos/<id>/recusar    cabecalho X-Admin-Senha
//
// Admin desligado se SIG3TUNNEL_ADMIN_SENHA estiver vazia.
// SIG3TUNNEL_AUTO_APROVAR=1 aprova sem humano: SO PARA TESTE. Com ele ligado, qualquer um recebe token.

const crypto  = require('crypto');
const pedidos = require('./pedidos');

const MAX_JSON = 8 * 1024;

function enviar(res, status, corpo) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
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
      try { resolve(JSON.parse(Buffer.concat(partes).toString('utf8') || '{}')); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

// O IP de origem vem do nginx (X-Real-IP, que ele mesmo define); o socket é o próprio nginx.
function ipDe(req) {
  return req.headers['x-real-ip'] || req.socket.remoteAddress || 'desconhecido';
}

function adminOk(req) {
  const senha = process.env.SIG3TUNNEL_ADMIN_SENHA || '';
  if (!senha) return false;
  const a = Buffer.from(senha);
  const b = Buffer.from(String(req.headers['x-admin-senha'] || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const STATUS_DE_ERRO = {
  nao_encontrado:      404,
  segredo_errado:      403,
  nome_em_uso:         409,
  estado_invalido:     409,
  ja_entregue:         409,
  fila_cheia:          429,
  muitos_pedidos:      429,
};

async function tratarApi(req, res) {
  const p = new URL(req.url, 'http://relay').pathname;
  try {
    if (req.method === 'POST' && p === '/api/pedidos') {
      const corpo = await lerJson(req);
      const r = pedidos.criar({
        dns: corpo.dns,
        descricao: corpo.descricao,
        segredo: corpo.segredo,
        ip: ipDe(req),
        autoAprovar: process.env.SIG3TUNNEL_AUTO_APROVAR === '1',
      });
      return enviar(res, 201, r);
    }

    let m = p.match(/^\/api\/pedidos\/([0-9a-f]{16})$/);
    if (req.method === 'GET' && m) {
      return enviar(res, 200, pedidos.entregar(m[1], req.headers['x-pedido-segredo']));
    }

    if (p.startsWith('/api/admin/')) {
      if (!adminOk(req)) return enviar(res, 403, { erro: 'admin_negado' });
      if (req.method === 'GET' && p === '/api/admin/pedidos') return enviar(res, 200, pedidos.listar());
      m = p.match(/^\/api\/admin\/pedidos\/([0-9a-f]{16})\/(aprovar|recusar)$/);
      if (req.method === 'POST' && m) {
        const r = m[2] === 'aprovar' ? pedidos.aprovar(m[1]) : pedidos.recusar(m[1]);
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

module.exports = { tratarApi };
