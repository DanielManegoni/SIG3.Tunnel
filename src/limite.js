'use strict';

// Limitadores por IP, em memória. Um é o de FALHAS (errou N vezes na janela, fica bloqueado), o outro é o
// de TAXA (no máximo N pedidos por janela). Os dois se limpam sozinhos: o mapa nunca passa de MAX_IPS.

const MAX_IPS = 10_000;

function podar(mapa, agora, vivo) {
  if (mapa.size < MAX_IPS) return;
  for (const [ip, v] of mapa) if (!vivo(v, agora)) mapa.delete(ip);
  // Ainda cheio (ataque com muitos IPs): descarta os mais antigos, que são os primeiros a entrar.
  for (const ip of mapa.keys()) { if (mapa.size < MAX_IPS * 0.9) break; mapa.delete(ip); }
}

function criarLimitadorDeFalhas({ max, janelaMs, bloqueioMs }) {
  const mapa = new Map(); // ip -> { falhas, inicio, bloqueadoAte }
  const vivo = (v, agora) => v.bloqueadoAte > agora || agora - v.inicio <= janelaMs;
  return {
    bloqueado: (ip, agora = Date.now()) => (mapa.get(ip)?.bloqueadoAte || 0) > agora,
    falha(ip, agora = Date.now()) {
      const f = mapa.get(ip);
      if (!f || (f.bloqueadoAte <= agora && agora - f.inicio > janelaMs)) {
        podar(mapa, agora, vivo);
        mapa.set(ip, { falhas: 1, inicio: agora, bloqueadoAte: 0 });
        return;
      }
      f.falhas += 1;
      if (f.falhas >= max) f.bloqueadoAte = agora + bloqueioMs;
    },
    zerar: ip => mapa.delete(ip),
    tamanho: () => mapa.size,
  };
}

function criarLimitadorDeTaxa({ max, janelaMs }) {
  const mapa = new Map(); // ip -> { n, inicio }
  const vivo = (v, agora) => agora - v.inicio <= janelaMs;
  return {
    // true = pode passar
    permitir(ip, agora = Date.now()) {
      const v = mapa.get(ip);
      if (!v || agora - v.inicio > janelaMs) {
        podar(mapa, agora, vivo);
        mapa.set(ip, { n: 1, inicio: agora });
        return true;
      }
      v.n += 1;
      return v.n <= max;
    },
    tamanho: () => mapa.size,
  };
}

module.exports = { criarLimitadorDeFalhas, criarLimitadorDeTaxa };
