'use strict';

// Limitadores por IP, em memória. Um é o de FALHAS (errou N vezes na janela, fica bloqueado), o outro é o
// de TAXA (no máximo N pedidos por janela). Os dois se limpam sozinhos: o mapa nunca passa de MAX_IPS.

const MAX_IPS = 10_000;

// Loopback = o nginx sem X-Real-IP: não dá para saber QUEM é. Limitar por esse "IP" juntaria todo mundo
// numa conta só, e um atacante bloquearia todos os clientes. Então não se limita, e avisa uma vez.
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
let avisouLoopback = false;
function limitavel(ip) {
  if (!LOOPBACK.has(ip)) return true;
  if (!avisouLoopback) {
    avisouLoopback = true;
    console.error('[sig3tunnel] requisição sem X-Real-IP (IP de loopback): limites por IP DESLIGADOS para ela. Confira o proxy_set_header X-Real-IP do nginx.');
  }
  return false;
}

// Quem chega por IPv6 costuma ter um bloco /64 inteiro (2^64 endereços): contar por endereço deixa o atacante trocar
// de endereço a cada tentativa e nunca ser bloqueado. Para IPv6 a conta é do bloco /64; IPv4 e IPv4 embutido em
// IPv6 (::ffff:1.2.3.4) seguem por endereço. Entrada que não se reconhece fica como veio.
function chaveDe(ip) {
  const s = String(ip);
  const v4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (v4) return v4[1];
  if (!s.includes(':')) return s;
  const lados = s.split('%')[0].split('::');
  if (lados.length > 2) return s;
  const esq = lados[0] ? lados[0].split(':') : [];
  const dir = lados.length === 2 && lados[1] ? lados[1].split(':') : [];
  let grupos;
  if (lados.length === 2) {
    const faltam = 8 - esq.length - dir.length;
    if (faltam < 1) return s;
    grupos = [...esq, ...new Array(faltam).fill('0'), ...dir];
  } else grupos = esq;
  if (grupos.length !== 8 || grupos.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) return s;
  return grupos.slice(0, 4).map(g => g.toLowerCase().replace(/^0+(?=.)/, '')).join(':') + '::/64';
}

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
    bloqueado: (ip, agora = Date.now()) => limitavel(ip) && (mapa.get(chaveDe(ip))?.bloqueadoAte || 0) > agora,
    falha(ip, agora = Date.now()) {
      if (!limitavel(ip)) return;
      const k = chaveDe(ip);
      const f = mapa.get(k);
      if (!f || (f.bloqueadoAte <= agora && agora - f.inicio > janelaMs)) {
        podar(mapa, agora, vivo);
        mapa.set(k, { falhas: 1, inicio: agora, bloqueadoAte: 0 });
        return;
      }
      f.falhas += 1;
      if (f.falhas >= max) f.bloqueadoAte = agora + bloqueioMs;
    },
    zerar: ip => mapa.delete(chaveDe(ip)),
    tamanho: () => mapa.size,
  };
}

function criarLimitadorDeTaxa({ max, janelaMs }) {
  const mapa = new Map(); // ip -> { n, inicio }
  const vivo = (v, agora) => agora - v.inicio <= janelaMs;
  return {
    // true = pode passar
    permitir(ip, agora = Date.now()) {
      if (!limitavel(ip)) return true;
      const k = chaveDe(ip);
      const v = mapa.get(k);
      if (!v || agora - v.inicio > janelaMs) {
        podar(mapa, agora, vivo);
        mapa.set(k, { n: 1, inicio: agora });
        return true;
      }
      v.n += 1;
      return v.n <= max;
    },
    tamanho: () => mapa.size,
  };
}

module.exports = { criarLimitadorDeFalhas, criarLimitadorDeTaxa, chaveDe };
