'use strict';

const http                           = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const { randomUUID }                 = require('crypto');
const { validate }                   = require('./tokens');
const { errorResponse }              = require('./errors');
const { tratarApi, ipDe }            = require('./api');
const { registrarAtividade }         = require('./pedidos');
const tecnicos                       = require('./tecnicos');
const { lerJson }                    = require('./arquivo');
const { criarLimitadorDeFalhas, criarLimitadorDeTaxa } = require('./limite');
const { CABECALHOS_SEGUROS, REDIRECIONAR_RAIZ_PARA } = require('./seguranca');
const { TOKENS_FILE, PEDIDOS_FILE, TECNICOS_FILE } = require('./paths');

const MAX_QUEUE    = 256;
const MAX_BODY     = 10 * 1024 * 1024; // 10 MB
const PING_INTERVAL = 30_000;
const MAX_MENSAGEM_WS = 64 * 1024 * 1024; // maior mensagem aceita de um túnel (o padrão do ws é 100 MB)

const MAX_UPGRADES = 256;

// Por túnel, abaixo do teto geral: o visitante de um cliente não esgota a vaga dos outros.
const MAX_QUEUE_POR_TUNEL    = 64;
const MAX_UPGRADES_POR_TUNEL = 64;

// O SIG3 tem este tempo para responder ao pedido de upgrade com o 101; passou, o socket do navegador é derrubado.
const HANDSHAKE_UPGRADE_MS = 30_000;
const PREFIXO_101          = 'HTTP/1.1 101';

// A Cloudflare corta a resposta em 100 s (erro 524). O SIG3 desiste em 90 s (TunelSig3Tunnel) e
// responde 502; o relay espera um pouco mais, para a resposta do SIG3 chegar antes do 504 daqui.
const TEMPO_RESPOSTA_MS = 95_000;

// Quem erra a chave de técnico ou o token de túnel várias vezes fica bloqueado por um tempo. Só conta erro
// de quem APRESENTOU uma credencial: visitante sem nada (scanner) leva 404 e não enche a conta.
const falhasTecnico = criarLimitadorDeFalhas({ max: 20, janelaMs: 15 * 60_000, bloqueioMs: 15 * 60_000 });
const falhasToken   = criarLimitadorDeFalhas({ max: 30, janelaMs: 15 * 60_000, bloqueioMs: 10 * 60_000 });
// Quem tem token válido também não reconecta sem parar: cada conexão grava em disco. Chave = nome do túnel.
const taxaConexao   = criarLimitadorDeTaxa({ max: 30, janelaMs: 60_000 });

const peers    = new Map(); // name → ws
const queue    = new Map(); // requestId → { res, timer, peerName }
const upgrades = new Map(); // upgradeId → { socket, peerName }

function nameFromPath(path) {
  const m = (path || '').match(/^\/_sig3\/([a-z0-9][a-z0-9-]{0,62})$/i);
  return m ? m[1].toLowerCase() : 'default';
}

// Endereço do túnel: tunel-<nome>.<dominio> (um nível só, coberto pelo certificado gratuito da
// Cloudflare e escondido atrás da nuvem laranja). O formato antigo <nome>.tunel.<dominio> segue
// aceito enquanto houver SIG3 instalado que ainda monta o endereço assim.
function nameFromHost(host) {
  const h = host || '';
  const m = h.match(/^tunel-([a-z0-9][a-z0-9-]*)\./i) || h.match(/^([a-z0-9][a-z0-9-]*)\.tunel\./i);
  return m ? m[1].toLowerCase() : null;
}

// Só caminho de origem ("/x"). "//host/x" e "http://host/x" chegam como req.url e, resolvidos do
// outro lado contra a base local, trocariam o destino: o túnel viraria passagem para a rede do cliente.
function caminhoLocal(url) {
  return typeof url === 'string' && url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\');
}

// X-Forwarded-For SUBSTITUI o que veio, não acrescenta: o app do outro lado lê só o último IP da
// lista, e acrescentando o último era sempre o nginx (127.0.0.1) - todo visitante aparecia igual.
// O que o visitante manda nesse cabeçalho é forjável e não vai adiante.
function cabecalhosRepasse(req) {
  return tecnicos.limparCabecalhos({
    ...req.headers,
    'x-forwarded-for': ipDe(req),
    'x-forwarded-host': req.headers.host,
    'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'https',
  });
}

// Só técnico com chave (ou com o cookie que ela rendeu) chega ao SIG3 de um cliente. A conferência
// vem antes de saber se o túnel existe: quem não tem chave não descobre quais clientes estão no ar.
// Devolve { tecnico, novoCookie }, null (sem acesso) ou 'bloqueado' (IP com chaves erradas demais).
function autorizarTecnico(req, tunel) {
  const ip = ipDe(req);
  const comChave = !!req.headers[tecnicos.CABECALHO];
  if (comChave && falhasTecnico.bloqueado(ip)) return 'bloqueado';
  const auth = tecnicos.autorizar(req, tunel);
  if (comChave) { if (auth) falhasTecnico.zerar(ip); else falhasTecnico.falha(ip); }
  if (auth?.novoCookie) console.log(`[sig3tunnel] técnico "${auth.tecnico.nome}" entrou em "${tunel}" de ${ip}`);
  return auth;
}

// Os túneis são irmãos (tunel-A e tunel-B no mesmo domínio): para o navegador são o MESMO site, e o cookie do
// técnico em A acompanha um pedido que a página servida em B dispare contra A (um formulário, um fetch, um
// WebSocket). Quem serve a página de B é o SIG3 de um cliente, que o relay não controla. Então um pedido
// autorizado só pelo cookie precisa nascer na própria página do túnel: o navegador diz isso em Sec-Fetch-Site e
// Origin. Só o clique num link (navegação GET) vindo de outro site passa. A chave no cabeçalho não passa por
// aqui: um site não consegue pôr cabeçalho próprio no pedido sem o relay deixar.
function origemSuspeita(req) {
  const site = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (site === 'cross-site' || site === 'same-site') {
    const modo = String(req.headers['sec-fetch-mode'] || '').toLowerCase();
    if (!(modo === 'navigate' && (req.method === 'GET' || req.method === 'HEAD'))) return true;
    // enquadrar um túnel dentro da página de outro (iframe) é clickjacking entre irmãos
    if (['iframe', 'frame', 'embed', 'object'].includes(String(req.headers['sec-fetch-dest'] || '').toLowerCase())) return true;
  }
  const origem = req.headers.origin;
  if (origem === undefined) return false;
  try { return new URL(origem).host !== String(req.headers.host || '').toLowerCase(); }
  catch { return true; }   // "null" (iframe isolado, data:) e o que não for um endereço
}

// Um túnel não planta cookie nos outros: tira o Domain= de todo Set-Cookie, que vira só do host
// daquele túnel (com Domain=tunel.<dominio> ele valeria em todos os <codigo>.tunel.<dominio>).
function cookiesSemDominio(headers) {
  for (const nome of Object.keys(headers)) {
    if (nome.toLowerCase() !== 'set-cookie') continue;
    const lista = Array.isArray(headers[nome]) ? headers[nome] : [headers[nome]];
    headers[nome] = lista.map(c => String(c).split(';').filter(p => !/^\s*domain\s*=/i.test(p)).join(';'));
  }
  return headers;
}

function contarDoTunel(mapa, nome) {
  let n = 0;
  for (const v of mapa.values()) if (v.peerName === nome) n++;
  return n;
}

// Protocolo: docs/protocolo.md. Quadro binário de HTTP (versão 2):
//   36 bytes do id (UUID ASCII) | 4 bytes, tamanho do JSON (big-endian) | JSON | corpo cru
function montarQuadro(id, cabecalho, corpo) {
  const json = Buffer.from(JSON.stringify(cabecalho), 'utf8');
  const tam  = Buffer.alloc(4);
  tam.writeUInt32BE(json.length);
  return Buffer.concat([Buffer.from(id, 'ascii'), tam, json, corpo]);
}

function lerQuadro(raw) {
  if (raw.length < 40) return null;
  const tam = raw.readUInt32BE(36);
  if (40 + tam > raw.length) return null;
  try {
    return { cabecalho: JSON.parse(raw.subarray(40, 40 + tam).toString('utf8')), corpo: raw.subarray(40 + tam) };
  } catch {
    return null;
  }
}

// A resposta vem do SIG3 do cliente e nunca é confiável: status ou cabeçalho malformado lançaria dentro
// do writeHead, e uma exceção ali derrubava o relay inteiro (todos os túneis). Resposta inválida vira 502.
const NOME_CABECALHO  = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const CONTROLE        = /[\x00-\x08\x0a-\x1f\x7f]/;
const SALTA_CABECALHO = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

function cabecalhosDeResposta(brutos) {
  if (brutos == null) return {};
  if (typeof brutos !== 'object' || Array.isArray(brutos)) return null;
  const saida = {};
  for (const [nome, valor] of Object.entries(brutos)) {
    if (!NOME_CABECALHO.test(nome)) return null;
    const lista = Array.isArray(valor) ? valor : [valor];
    if (!lista.length || !lista.every(v => typeof v === 'string' && !CONTROLE.test(v))) return null;
    if (SALTA_CABECALHO.has(nome.toLowerCase())) continue;
    saida[nome] = valor;
  }
  return saida;
}

function responder(entry, status, headersBrutos, corpo) {
  const codigo = Number.isInteger(status) && status >= 200 && status <= 599 ? status : null;
  const limpos = cabecalhosDeResposta(headersBrutos);
  if (codigo === null || limpos === null) {
    console.error(`[sig3tunnel] "${entry.peerName}" mandou resposta inválida (status ${JSON.stringify(status)}); devolvido 502`);
    errorResponse(entry.res, 502);
    return;
  }
  const headers = cookiesSemDominio(limpos);
  // O tamanho vem do corpo que o relay realmente tem, não do que o cliente declarou (exceto HEAD, sem corpo).
  const cl = Object.keys(headers).find(h => h.toLowerCase() === 'content-length');
  const declarado = cl ? String(headers[cl]) : null;
  if (cl) delete headers[cl];
  const tamanho = corpo && corpo.length ? corpo.length : 0;
  if (entry.metodo === 'HEAD') { if (declarado && /^\d+$/.test(declarado)) headers['content-length'] = declarado; }
  else if (codigo !== 204 && codigo !== 304) headers['content-length'] = String(tamanho);
  if (entry.cookieTecnico) {
    const nome = Object.keys(headers).find(h => h.toLowerCase() === 'set-cookie') || 'set-cookie';
    const atuais = headers[nome] ? [].concat(headers[nome]) : [];
    headers[nome] = [...atuais, entry.cookieTecnico];
  }
  try {
    entry.res.writeHead(codigo, headers);
    entry.res.end(tamanho ? corpo : undefined);
  } catch (e) {
    console.error(`[sig3tunnel] resposta de "${entry.peerName}" recusada pelo servidor: ${e.message}`);
    errorResponse(entry.res, 502);
  }
}

// Encerra um upgrade pelo relay. `destruir` corta o socket na hora (o normal é terminar a escrita e deixar o
// navegador fechar); `avisar` manda ao SIG3 o up-close, para ele soltar o socket local.
function fecharUpgrade(id, { destruir = false, avisar = false } = {}) {
  const up = upgrades.get(id);
  if (!up) return;
  upgrades.delete(id);
  clearTimeout(up.timer);
  if (destruir) up.socket.destroy(); else up.socket.end();
  const peer = peers.get(up.peerName);
  if (avisar && peer && peer.readyState === WebSocket.OPEN) peer.send(JSON.stringify({ type: 'up-close', id }));
}

// A resposta do SIG3 ao pedido de upgrade tem de ser um 101; só depois disso os bytes dele passam crus ao
// navegador. Sem essa conferência, o SIG3 podia responder com uma resposta HTTP comum e completa e deixar o
// socket aberto: para o nginx (se ele guarda conexões com o relay para reaproveitar) a resposta terminou, a
// conexão volta ao conjunto, e o próximo pedido de OUTRA pessoa cai neste socket e é entregue a esse SIG3, com o
// Authorization e os cookies dela. Resposta que não é 101 derruba o socket: a conexão nunca é reaproveitada.
function escreverNoUpgrade(id, up, bytes) {
  if (up.confirmado) { up.socket.write(bytes); return; }
  up.inicio = Buffer.concat([up.inicio, bytes]);
  if (up.inicio.length < PREFIXO_101.length) return;
  if (up.inicio.toString('latin1', 0, PREFIXO_101.length) !== PREFIXO_101) {
    console.error(`[sig3tunnel] "${up.peerName}" respondeu ao upgrade com algo que não é um 101; socket derrubado`);
    fecharUpgrade(id, { destruir: true, avisar: true });
    return;
  }
  up.confirmado = true;
  clearTimeout(up.timer);
  up.socket.write(up.inicio);
  up.inicio = null;
}

// Técnico revogado perde o cookie na hora, mas o upgrade que ele já tinha aberto (o circuito do Blazor) seguiria
// vivo. Derruba os upgrades cujo técnico não existe mais; roda a cada ping e quando a API revoga uma chave.
function derrubarUpgradesDeRevogados() {
  for (const [id, up] of upgrades) {
    if (!up.tecnicoId || tecnicos.existe(up.tecnicoId)) continue;
    console.log(`[sig3tunnel] chave revogada: upgrade de "${up.peerName}" derrubado`);
    fecharUpgrade(id, { destruir: true, avisar: true });
  }
}

// Upgrades de WebSocket do navegador (o /_blazor) viajam como bytes crus: o relay liga o socket do
// navegador ao túnel, e o SIG3 o liga ao localhost. Dura enquanto o socket durar; o que tem prazo é o 101.
function tunnelUpgrade(req, socket, head) {
  // Depois do 'upgrade' o http do Node solta o tratamento de erro do socket: sem este, um ECONNRESET do
  // navegador (que acontece o tempo todo) vira exceção não tratada e derruba o relay.
  socket.on('error', () => socket.destroy());
  if (!caminhoLocal(req.url)) {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  const name = nameFromHost(req.headers.host) || 'default';
  const acesso = autorizarTecnico(req, name);
  if (acesso === 'bloqueado') {
    socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  if (!acesso) {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  // Só WebSocket. Qualquer outro "Upgrade" abriria um pipe de bytes até a porta local do cliente, por onde dá para
  // falar HTTP à vontade com ela, fora das conferências que o SIG3 faz em cada pedido.
  if (String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  if (!acesso.novoCookie && origemSuspeita(req)) {
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  const peer = peers.get(name);
  if (!peer || peer.readyState !== WebSocket.OPEN) {
    socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  if (upgrades.size >= MAX_UPGRADES || contarDoTunel(upgrades, name) >= MAX_UPGRADES_POR_TUNEL) {
    socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  const id      = randomUUID();
  const headers = cabecalhosRepasse(req);

  // inicio/confirmado: o que o SIG3 respondeu até agora e se já provou ser um 101 (ver escreverNoUpgrade).
  const timer = setTimeout(() => {
    if (!upgrades.get(id)?.confirmado) {
      console.error(`[sig3tunnel] "${name}" não respondeu ao upgrade em ${HANDSHAKE_UPGRADE_MS / 1000} s; socket derrubado`);
      fecharUpgrade(id, { destruir: true, avisar: true });
    }
  }, HANDSHAKE_UPGRADE_MS);
  timer.unref();
  upgrades.set(id, { socket, peerName: name, tecnicoId: acesso.tecnico.id, confirmado: false, inicio: Buffer.alloc(0), timer });

  peer.send(JSON.stringify({
    type:    'upgrade',
    id,
    method:  req.method,
    url:     req.url,
    headers,
    head:    head.length ? head.toString('base64') : '',
  }));

  // Dados do upgrade vão como frame binário: 36 bytes do id (UUID ASCII) + os bytes crus. Sem base64.
  socket.on('data', chunk => {
    if (!upgrades.has(id)) return;
    peer.send(Buffer.concat([Buffer.from(id, 'ascii'), chunk]), { binary: true });
  });

  const finish = () => {
    const up = upgrades.get(id);
    if (!up) return;
    upgrades.delete(id);
    clearTimeout(up.timer);
    if (peer.readyState === WebSocket.OPEN) peer.send(JSON.stringify({ type: 'up-close', id }));
  };

  socket.on('close', finish);
  socket.on('error', () => finish());
}

// Arquivo de dados ilegível impede o relay de subir: rodar sem ele seria recusar todo cliente e todo
// técnico sem dizer por quê. Arquivo que ainda não existe é normal (instalação nova).
function verificarArquivos() {
  for (const f of [TOKENS_FILE, PEDIDOS_FILE, TECNICOS_FILE]) lerJson(f);
}

// Recusa uma conexão de túnel. O close do WebSocket espera o outro lado responder (até 30 s); quem não é
// cliente de verdade não responde, e as conexões ficariam penduradas. Passado o prazo curto, corta.
function recusarCliente(ws, motivo) {
  ws.close(1008, motivo);
  setTimeout(() => ws.terminate(), 3000).unref();
}

// Mensagem recebida do SIG3 de um cliente (túnel <name>): resposta de requisição ou dados de um upgrade.
function tratarMensagem(name, raw, isBinary) {
  // Frame binário: 36 bytes de id + dados de um upgrade, ou o quadro de uma resposta HTTP.
  if (isBinary) {
    if (raw.length < 36) return;
    const id = raw.subarray(0, 36).toString('ascii');
    const up = upgrades.get(id);
    if (up) {
      if (up.peerName === name) escreverNoUpgrade(id, up, raw.subarray(36));
      return;
    }
    const entry = queue.get(id);
    if (!entry || entry.peerName !== name) return;
    const quadro = lerQuadro(raw);
    if (!quadro || typeof quadro.cabecalho !== 'object' || quadro.cabecalho === null) return;
    queue.delete(id);
    clearTimeout(entry.timer);
    responder(entry, quadro.cabecalho.status, quadro.cabecalho.headers, quadro.corpo);
    return;
  }

  let msg;
  try { msg = JSON.parse(raw); } catch { return; }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return;

  if (msg.type === 'up-data' || msg.type === 'up-close') {
    const up = upgrades.get(msg.id);
    if (!up || up.peerName !== name) return;
    if (msg.type === 'up-close') {
      fecharUpgrade(msg.id);
    } else if (typeof msg.data === 'string') {
      escreverNoUpgrade(msg.id, up, Buffer.from(msg.data, 'base64'));
    }
    return;
  }

  // Só o túnel que recebeu a requisição pode respondê-la.
  const entry = queue.get(msg.id);
  if (!entry || entry.peerName !== name) return;

  queue.delete(msg.id);
  clearTimeout(entry.timer);
  const corpo = typeof msg.body === 'string' && msg.body ? Buffer.from(msg.body, 'base64') : null;
  responder(entry, msg.status, msg.headers, corpo);
}

// Porta local que o SIG3 do cliente anuncia ao conectar (X-Sig3-Porta). Só informação para o painel: um
// valor que não seja um inteiro de até 5 dígitos é ignorado.
function portaAnunciada(req) {
  const v = String(req.headers['x-sig3-porta'] || '');
  return /^\d{1,5}$/.test(v) ? Number(v) : undefined;
}

// Registra conexão/uso no pedido do cliente. Falha de gravação não pode derrubar o túnel.
// Cada gravação lê o arquivo de pedidos inteiro, reescreve e dá fsync, tudo síncrono: sem teto, um SIG3 que
// reconecta em laço (com token válido) ocuparia o relay de todos os clientes.
const ultimaGravacao = new Map(); // "campo:nome" -> instante da última gravação
const INTERVALO_GRAVACAO_MS = { ultimoUso: 60_000, ultimaConexao: 15_000 };
function registrar(nome, campo, extras) {
  try {
    const agora = Date.now();
    const chave = `${campo}:${nome}`;
    if (agora - (ultimaGravacao.get(chave) || 0) < INTERVALO_GRAVACAO_MS[campo]) return;
    ultimaGravacao.set(chave, agora);
    registrarAtividade(nome, campo, agora, extras);
  } catch (e) {
    console.error(`[sig3tunnel] não consegui registrar ${campo} de "${nome}": ${e.message}`);
  }
}

function serve(port, host) {
  verificarArquivos();
  tecnicos.verificarSegredo();   // segredo do cookie fraco impede o relay de subir, em vez de assinar cookies frágeis
  if (process.env.SIG3TUNNEL_AUTO_APROVAR === '1')
    console.error('[sig3tunnel] ATENÇÃO: SIG3TUNNEL_AUTO_APROVAR=1. Todo pedido é aprovado sem ninguém olhar. Só serve para teste; tire isto da produção.');
  const server = http.createServer((req, res) => {
    if (!caminhoLocal(req.url)) {
      errorResponse(res, 400);
      return;
    }

    if ((req.url || '').startsWith('/api-tunel/')) {
      // derrubar: fecha o túnel conectado com esse nome (usado ao excluir um cliente)
      tratarApi(req, res, {
        derrubar:  nome => { const ws = peers.get(nome); if (ws) ws.close(1008, 'tunnel removed'); },
        conectado: nome => peers.get(nome)?.readyState === WebSocket.OPEN,
        aoRevogarTecnico: derrubarUpgradesDeRevogados,
      });
      return;
    }

    if (req.url === '/_sig3/ping') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    const name = nameFromHost(req.headers.host) || 'default';
    const auth = autorizarTecnico(req, name);
    if (auth === 'bloqueado') {
      errorResponse(res, 429);
      return;
    }
    if (!auth) {
      // Endereço do relay aberto no navegador, sem chave: vai para o site da empresa, sem revelar nada.
      if (nameFromHost(req.headers.host) === null && req.url.split('?')[0] === '/') {
        res.writeHead(302, { ...CABECALHOS_SEGUROS, Location: REDIRECIONAR_RAIZ_PARA, 'Content-Length': '0' });
        res.end();
        return;
      }
      errorResponse(res, 404);
      return;
    }
    if (!auth.novoCookie && origemSuspeita(req)) {
      errorResponse(res, 403);
      return;
    }

    registrar(name, 'ultimoUso');   // técnico autorizado acessou este túnel (mesmo que ele esteja offline)

    const peer = peers.get(name);
    if (!peer || peer.readyState !== WebSocket.OPEN) {
      errorResponse(res, 503);
      return;
    }

    if (queue.size >= MAX_QUEUE || contarDoTunel(queue, name) >= MAX_QUEUE_POR_TUNEL) {
      errorResponse(res, 429);
      return;
    }

    const id       = randomUUID();
    const chunks   = [];
    let bodySize   = 0;
    let bodyTooBig = false;

    req.on('data', chunk => {
      bodySize += chunk.length;
      if (bodySize > MAX_BODY) {
        bodyTooBig = true;
        req.destroy();
        errorResponse(res, 413);
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (bodyTooBig) return;

      const cabecalho = { method: req.method, url: req.url, headers: cabecalhosRepasse(req) };
      const corpo     = Buffer.concat(chunks);

      const timer = setTimeout(() => {
        if (!queue.has(id)) return;
        queue.delete(id);
        errorResponse(res, 504);
      }, TEMPO_RESPOSTA_MS);

      queue.set(id, { res, timer, peerName: name, cookieTecnico: auth.novoCookie, metodo: req.method });
      // SIG3 que avisou a versão 2 recebe o corpo cru; o anterior, em base64 dentro do JSON.
      if (peer._protocolo >= 2) peer.send(montarQuadro(id, cabecalho, corpo), { binary: true });
      else peer.send(JSON.stringify({ id, ...cabecalho, body: corpo.toString('base64') }));
    });

    req.on('error', () => errorResponse(res, 400));
  });

  // Contra conexão lenta (slowloris): o cabeçalho tem de chegar em 20 s e o pedido inteiro em 2 min.
  server.headersTimeout  = 20_000;
  server.requestTimeout  = 120_000;
  server.maxHeadersCount = 100;
  // O Node só confere esses prazos a cada connectionsCheckingInterval (30 s por padrão): o "20 s" virava até 50 s.
  server.connectionsCheckingInterval = 5_000;

  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_MENSAGEM_WS });

  server.on('upgrade', (req, socket, head) => {
    const path = req.url || '';
    if (path === '/_sig3' || /^\/_sig3\/[a-z0-9][a-z0-9-]{0,62}$/i.test(path)) {
      wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
    } else {
      tunnelUpgrade(req, socket, head);
    }
  });

  // Detect dead connections: ping every PING_INTERVAL, terminate if no pong.
  setInterval(() => {
    derrubarUpgradesDeRevogados();   // revogação feita pelo CLI (outro processo) chega aqui
    for (const [name, ws] of peers) {
      if (ws._pingPending) {
        console.log(`[sig3tunnel] "${name}" ping timeout, terminating`);
        ws.terminate();
        continue;
      }
      ws._pingPending = true;
      ws.ping();
    }
  }, PING_INTERVAL).unref();

  wss.on('connection', (ws, req) => {
    const raw   = (req.headers['authorization'] || '').trim();
    const token = raw.startsWith('Bearer ') ? raw.slice(7) : null;

    const rawPath  = req.url || '';
    const isDefault = rawPath === '/_sig3';

    if (!isDefault && !/^\/_sig3\/[a-z0-9][a-z0-9-]{0,62}$/i.test(rawPath)) {
      recusarCliente(ws, 'invalid path');
      return;
    }

    const name = nameFromPath(rawPath);
    const ip   = ipDe(req);

    if (falhasToken.bloqueado(ip)) {
      recusarCliente(ws, 'rate limited');
      return;
    }
    if (!token || !validate(token, name)) {
      if (token) falhasToken.falha(ip);
      recusarCliente(ws, 'unauthorized');
      return;
    }
    falhasToken.zerar(ip);

    if (!taxaConexao.permitir(name)) {
      recusarCliente(ws, 'rate limited');
      return;
    }

    if (peers.has(name) && peers.get(name).readyState === WebSocket.OPEN) {
      recusarCliente(ws, 'name already in use');
      return;
    }

    ws._pingPending = false;
    ws._protocolo   = parseInt(req.headers['x-sig3-protocolo'] || '1', 10) || 1;
    ws.on('pong', () => { ws._pingPending = false; });

    peers.set(name, ws);
    registrar(name, 'ultimaConexao', { porta: portaAnunciada(req) });
    console.log(`[sig3tunnel] "${name}" connected from ${ip}`);

    // Mensagem de um túnel é entrada não confiável: qualquer exceção aqui derrubaria o relay inteiro.
    ws.on('message', (raw, isBinary) => {
      try {
        tratarMensagem(name, raw, isBinary);
      } catch (e) {
        console.error(`[sig3tunnel] "${name}" mandou mensagem inválida: ${e.message}`);
      }
    });

    ws.on('close', () => {
      peers.delete(name);
      console.log(`[sig3tunnel] "${name}" disconnected`);
      for (const [id, entry] of queue) {
        if (entry.peerName !== name) continue;
        clearTimeout(entry.timer);
        errorResponse(entry.res, 502);
        queue.delete(id);
      }
      for (const [id, up] of upgrades) {
        if (up.peerName === name) fecharUpgrade(id, { destruir: true });
      }
    });

    ws.on('error', err => console.error(`[sig3tunnel] "${name}" error:`, err.message));
  });

  server.listen(port, host, () => {
    console.log(`[sig3tunnel] relay listening on ${host}:${port}`);
  });

  return server;
}

module.exports = { serve, derrubarUpgradesDeRevogados };
