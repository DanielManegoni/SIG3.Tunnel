'use strict';

// Valida o JWT HS256 que o NewAdmin da Bossois já usa (emitido por api.bossoistec.com.br/auth/token).
// Só confere; nunca emite. Sem SIG3TUNNEL_JWT_SECRET o login por JWT fica desligado.

const crypto = require('crypto');

const b64 = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// Devolve o payload se o token é válido e o perfil é admin; senão null.
function validarAdmin(token, { segredo, issuer, audience, agora = Date.now() } = {}) {
  if (!segredo || typeof token !== 'string') return null;
  const partes = token.split('.');
  if (partes.length !== 3) return null;

  let cab, payload;
  try {
    cab = JSON.parse(b64(partes[0]).toString('utf8'));
    payload = JSON.parse(b64(partes[1]).toString('utf8'));
  } catch { return null; }
  if (cab.alg !== 'HS256') return null;

  const esperada = crypto.createHmac('sha256', segredo).update(`${partes[0]}.${partes[1]}`).digest();
  const recebida = b64(partes[2]);
  if (esperada.length !== recebida.length || !crypto.timingSafeEqual(esperada, recebida)) return null;

  const s = agora / 1000;
  if (typeof payload.exp !== 'number' || s >= payload.exp) return null;
  if (typeof payload.nbf === 'number' && s < payload.nbf) return null;
  if (issuer && payload.iss !== issuer) return null;
  if (audience && payload.aud !== audience) return null;
  if (payload.profile !== 'admin') return null;
  return payload;
}

module.exports = { validarAdmin };
