'use strict';

// Leitura e gravação dos arquivos de dados do relay (tokens, pedidos, técnicos).
//
// Gravação atômica: escreve num temporário na mesma pasta, guarda a versão anterior em <arquivo>.bak
// e troca pelo rename, que é instantâneo - uma queda no meio nunca deixa o arquivo pela metade.
// Leitura que falha (permissão, JSON quebrado) lança ErroArquivo em vez de virar lista vazia: lista
// vazia em silêncio derrubava todos os clientes sem pista nenhuma no log.

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

class ErroArquivo extends Error {
  constructor(caminho, causa) {
    const motivo = causa.code === 'EACCES'
      ? 'sem permissão de leitura (o dono do arquivo tem de ser o usuário do serviço)'
      : causa instanceof SyntaxError ? `JSON inválido (restaure de ${path.basename(caminho)}.bak)` : causa.message;
    super(`não consegui ler ${caminho}: ${motivo}`);
    this.caminho = caminho;
  }
}

/** Conteúdo do arquivo, ou `padrao` se ele ainda não existe. Qualquer outra falha lança ErroArquivo. */
function lerJson(caminho, padrao = []) {
  let texto;
  try {
    texto = fs.readFileSync(caminho, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return padrao;
    throw new ErroArquivo(caminho, e);
  }
  try {
    return JSON.parse(texto);
  } catch (e) {
    throw new ErroArquivo(caminho, e);
  }
}

// Leitura com cache: só volta ao disco quando o arquivo muda (data e tamanho). Os arquivos lidos a
// cada acesso (técnicos, tokens) deixam de ser relidos inteiros em toda requisição.
const cache = new Map(); // caminho -> { mtimeMs, size, dados }

function lerJsonCache(caminho, padrao = []) {
  let st;
  try {
    st = fs.statSync(caminho);
  } catch (e) {
    if (e.code === 'ENOENT') { cache.delete(caminho); return padrao; }
    throw new ErroArquivo(caminho, e);
  }
  const c = cache.get(caminho);
  if (c && c.mtimeMs === st.mtimeMs && c.size === st.size) return c.dados;
  const dados = lerJson(caminho, padrao);
  cache.set(caminho, { mtimeMs: st.mtimeMs, size: st.size, dados });
  return dados;
}

function gravarJson(caminho, dados) {
  const pasta = path.dirname(caminho);
  fs.mkdirSync(pasta, { recursive: true });
  const temporario = `${caminho}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;

  const fd = fs.openSync(temporario, 'w', 0o600);
  try {
    fs.writeSync(fd, JSON.stringify(dados, null, 2) + '\n');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  try {
    if (fs.existsSync(caminho)) fs.copyFileSync(caminho, `${caminho}.bak`);
    donoDaPasta(pasta, temporario, `${caminho}.bak`);
    fs.renameSync(temporario, caminho);
  } catch (e) {
    try { fs.unlinkSync(temporario); } catch { /* já não existe */ }
    throw e;
  }
  cache.delete(caminho);
}

// Rodada como root (a CLI, por engano), a gravação criaria o arquivo com dono root, e o serviço, que
// roda com usuário próprio, deixaria de conseguir lê-lo. O arquivo fica com o dono da pasta.
function donoDaPasta(pasta, ...arquivos) {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) return;
  const { uid, gid } = fs.statSync(pasta);
  for (const a of arquivos) {
    try { fs.chownSync(a, uid, gid); } catch { /* .bak pode não existir na primeira gravação */ }
  }
}

module.exports = { lerJson, lerJsonCache, gravarJson, ErroArquivo };
