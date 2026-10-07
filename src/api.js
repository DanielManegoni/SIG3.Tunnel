'use strict';

// API de pedidos de nome (ver src/pedidos.js). Rotas em /api-tunel/.
//
//   POST /api-tunel/pedidos                       { descricao, segredo }        -> 201 { id, codigo, status }
//   GET  /api-tunel/pedidos/<id>                  cabecalho X-Pedido-Segredo    -> { status, token? }
//   GET  /api-tunel/admin/pedidos                 cabecalho X-Admin-Senha       -> lista
//   POST /api-tunel/admin/pedidos/<id>/aprovar    cabecalho X-Admin-Senha
//   POST /api-tunel/admin/pedidos/<id>/recusar    cabecalho X-Admin-Senha
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

// O IP de origem: o relay escuta só em 127.0.0.1, então quem conecta é o nginx. O X-Real-IP só é confiado
// quando a conexão é de loopback (o nginx o define e sobrescreve); de outra origem, vale o socket.
function ipDe(req) {
  const origem = req.socket.remoteAddress || 'desconhecido';
  const local = origem === '127.0.0.1' || origem === '::1' || origem === '::ffff:127.0.0.1';
  return (local && req.headers['x-real-ip']) || origem;
}

function adminOk(req) {
  const senha = process.env.SIG3TUNNEL_ADMIN_SENHA || '';
  if (!senha) return false;
  const a = Buffer.from(senha);
  const b = Buffer.from(String(req.headers['x-admin-senha'] || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Tentativas de senha de admin por IP: 10 erros em 15 min bloqueiam o IP por 15 min. Acerto zera a conta.
const FALHAS_MAX    = 10;
const JANELA_MS     = 15 * 60 * 1000;
const falhasAdmin   = new Map(); // ip -> { falhas, inicio, bloqueadoAte }

function adminBloqueado(ip, agora = Date.now()) {
  const f = falhasAdmin.get(ip);
  return !!f && f.bloqueadoAte > agora;
}

function registrarFalhaAdmin(ip, agora = Date.now()) {
  const f = falhasAdmin.get(ip);
  if (!f || agora - f.inicio > JANELA_MS) {
    falhasAdmin.set(ip, { falhas: 1, inicio: agora, bloqueadoAte: 0 });
    return;
  }
  f.falhas += 1;
  if (f.falhas >= FALHAS_MAX) f.bloqueadoAte = agora + JANELA_MS;
}

// Só o acerto zera: quem erra de propósito não ganha tentativas novas.
function admin(req) {
  const ip = ipDe(req);
  if (adminBloqueado(ip)) return 'bloqueado';
  if (!adminOk(req)) {
    registrarFalhaAdmin(ip);
    return 'negado';
  }
  falhasAdmin.delete(ip);
  return 'ok';
}

const STATUS_DE_ERRO = {
  nao_encontrado:      404,
  segredo_errado:      403,
  sem_codigo:          503,
  estado_invalido:     409,
  ja_entregue:         409,
  fila_cheia:          429,
  muitos_pedidos:      429,
};

async function tratarApi(req, res) {
  const p = new URL(req.url, 'http://relay').pathname;
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
      return enviar(res, 200, pedidos.entregar(m[1], req.headers['x-pedido-segredo']));
    }

    if (p.startsWith('/api-tunel/admin/')) {
      const estado = admin(req);
      if (estado === 'bloqueado') return enviar(res, 429, { erro: 'muitas_tentativas', mensagem: 'Muitas senhas erradas. Espere 15 minutos.' });
      if (estado !== 'ok') return enviar(res, 403, { erro: 'admin_negado' });
      if (req.method === 'GET' && p === '/api-tunel/admin/pedidos') return enviar(res, 200, pedidos.listar());
      m = p.match(/^\/api-tunel\/admin\/pedidos\/([0-9a-f]{16})\/(aprovar|recusar)$/);
      if (req.method === 'POST' && m) {
        const r = m[2] === 'aprovar'
          ? pedidos.aprovar(m[1], Date.now(), (await lerJson(req).catch(() => ({}))).liberadoPor)
          : pedidos.recusar(m[1]);
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
