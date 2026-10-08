'use strict';

// Chaves dos técnicos do suporte. Só quem tem uma chega a um tunel-<codigo>: o SIG3.Client --suporte
// manda a chave no cabeçalho X-Sig3-Chave, e o relay devolve um cookie assinado que vale para aquele
// túnel e serve às requisições seguintes (inclusive o WebSocket do Blazor). Guarda só o hash da chave.

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { CONFIG_DIR, ensureDir } = require('./paths');

const ARQUIVO        = path.join(CONFIG_DIR, 'tecnicos.json');
const ARQUIVO_SEGREDO = path.join(CONFIG_DIR, 'segredo-cookie');

const CABECALHO = 'x-sig3-chave';
const COOKIE    = 'sig3tec';
const VALIDADE_COOKIE_MS = 4 * 60 * 60 * 1000;   // o teto da sessão de suporte no SIG3

function ler() {
  try { return JSON.parse(fs.readFileSync(ARQUIVO, 'utf8')); } catch { return []; }
}

function gravar(lista) {
  ensureDir();
  fs.writeFileSync(ARQUIVO, JSON.stringify(lista, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(ARQUIVO, 0o600); } catch { /* Windows */ }
}

const hash = raw => crypto.createHash('sha256').update(raw).digest('hex');

function emitir(nome) {
  const n = String(nome || '').trim().slice(0, 60);
  if (!n) throw new Error('nome do técnico vazio');
  const raw = 'sig3t_' + crypto.randomBytes(24).toString('hex');
  const id  = crypto.randomBytes(4).toString('hex');
  const lista = ler();
  lista.push({ id, nome: n, hash: hash(raw), criado: new Date().toISOString() });
  gravar(lista);
  return { id, nome: n, raw };
}

const listar = () => ler().map(({ id, nome, criado }) => ({ id, nome, criado }));

function revogar(id) {
  const antes = ler();
  const depois = antes.filter(t => t.id !== id);
  if (depois.length === antes.length) return false;
  gravar(depois);
  return true;
}

function porChave(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('sig3t_')) return null;
  const h = Buffer.from(hash(raw), 'hex');
  return ler().find(t => {
    const esperado = Buffer.from(t.hash, 'hex');
    return esperado.length === h.length && crypto.timingSafeEqual(esperado, h);
  }) || null;
}

// O segredo do cookie nasce sozinho na primeira vez e fica ao lado dos tokens. Trocá-lo derruba
// todos os cookies emitidos (os técnicos entram de novo com a chave, sem perceber).
let segredoEmMemoria = null;
function segredo() {
  if (segredoEmMemoria) return segredoEmMemoria;
  if (process.env.SIG3TUNNEL_SEGREDO) return (segredoEmMemoria = Buffer.from(process.env.SIG3TUNNEL_SEGREDO));
  try {
    segredoEmMemoria = fs.readFileSync(ARQUIVO_SEGREDO);
  } catch {
    ensureDir();
    segredoEmMemoria = crypto.randomBytes(32);
    fs.writeFileSync(ARQUIVO_SEGREDO, segredoEmMemoria, { mode: 0o600 });
  }
  return segredoEmMemoria;
}

const assinatura = (id, expira, tunel) =>
  crypto.createHmac('sha256', segredo()).update(`${id}.${expira}.${tunel}`).digest('base64url');

// Cookie: <id do técnico>.<expira em ms>.<assinatura de id+expira+túnel>. Preso ao túnel: o cookie de
// um cliente não abre outro.
function montarCookie(tecnico, tunel, agora = Date.now()) {
  const expira = agora + VALIDADE_COOKIE_MS;
  const valor = `${tecnico.id}.${expira}.${assinatura(tecnico.id, expira, tunel)}`;
  return `${COOKIE}=${valor}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${VALIDADE_COOKIE_MS / 1000}`;
}

function lerCookie(req) {
  for (const parte of String(req.headers.cookie || '').split(';')) {
    const i = parte.indexOf('=');
    if (i > 0 && parte.slice(0, i).trim() === COOKIE) return parte.slice(i + 1).trim();
  }
  return null;
}

function porCookie(valor, tunel, agora = Date.now()) {
  const [id, expiraTxt, ass] = String(valor || '').split('.');
  const expira = Number(expiraTxt);
  if (!id || !ass || !Number.isFinite(expira) || expira <= agora) return null;
  const esperada = Buffer.from(assinatura(id, expira, tunel));
  const recebida = Buffer.from(ass);
  if (esperada.length !== recebida.length || !crypto.timingSafeEqual(esperada, recebida)) return null;
  return ler().find(t => t.id === id) || null;   // técnico revogado perde o cookie na hora
}

// Quem está chegando a este túnel: { tecnico, novoCookie } ou null. A chave no cabeçalho vale mais
// que o cookie e devolve um cookie novo para a janela usar dali em diante.
function autorizar(req, tunel) {
  const chave = req.headers[CABECALHO];
  if (chave) {
    const tecnico = porChave(Array.isArray(chave) ? chave[0] : chave);
    return tecnico ? { tecnico, novoCookie: montarCookie(tecnico, tunel) } : null;
  }
  const tecnico = porCookie(lerCookie(req), tunel);
  return tecnico ? { tecnico, novoCookie: null } : null;
}

// O que é do relay não vai ao SIG3 do cliente: nem a chave do técnico, nem o cookie dele.
function limparCabecalhos(headers) {
  delete headers[CABECALHO];
  if (headers.cookie) {
    const resto = String(headers.cookie).split(';').filter(p => p.split('=')[0].trim() !== COOKIE).join(';').trim();
    if (resto) headers.cookie = resto; else delete headers.cookie;
  }
  return headers;
}

module.exports = { emitir, listar, revogar, autorizar, limparCabecalhos, montarCookie, porCookie, COOKIE, CABECALHO };
