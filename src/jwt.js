'use strict';

// Valida o JWT HS256 que o NewAdmin da Bossois já usa (emitido por api.bossoistec.com.br/auth/token).
// Só confere; nunca emite. Sem SIG3TUNNEL_JWT_SECRET o login por JWT fica desligado.

const crypto = require('crypto');

const b64 = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// Confere o token e diz o resultado: { payload } se vale, ou { erro: 'expirado' | 'invalido' }.
// 'expirado' é só isto: assinatura, emissor, audiência e perfil corretos e o prazo (exp) vencido. É uma sessão
// legítima que acabou, e o painel precisa saber para mandar a pessoa entrar de novo; não é tentativa de invasão.
// O perfil aceito vem de `perfis` (padrão: só admin).
function conferirToken(token, { segredo, issuer, audience, agora = Date.now(), perfis = ['admin'] } = {}) {
  const invalido = { erro: 'invalido' };
  if (!segredo || typeof token !== 'string') return invalido;
  const partes = token.split('.');
  if (partes.length !== 3) return invalido;

  let cab, payload;
  try {
    cab = JSON.parse(b64(partes[0]).toString('utf8'));
    payload = JSON.parse(b64(partes[1]).toString('utf8'));
  } catch { return invalido; }
  if (!cab || cab.alg !== 'HS256' || !payload || typeof payload !== 'object') return invalido;

  const esperada = crypto.createHmac('sha256', segredo).update(`${partes[0]}.${partes[1]}`).digest();
  const recebida = b64(partes[2]);
  if (esperada.length !== recebida.length || !crypto.timingSafeEqual(esperada, recebida)) return invalido;

  // Daqui em diante a assinatura é nossa: o conteúdo é confiável.
  if (issuer && payload.iss !== issuer) return invalido;
  if (audience && payload.aud !== audience) return invalido;
  if (!perfis.includes(payload.profile)) return invalido;
  const s = agora / 1000;
  if (typeof payload.exp !== 'number') return invalido;
  if (typeof payload.nbf === 'number' && s < payload.nbf) return invalido;
  if (s >= payload.exp) return { erro: 'expirado' };
  return { payload };
}

// Devolve o payload se o token é válido e o perfil está em `perfis` (padrão: só admin); senão null.
function validarAdmin(token, opcoes) {
  return conferirToken(token, opcoes).payload || null;
}

module.exports = { validarAdmin, conferirToken };
