'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http   = require('node:http');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');
const WebSocket = require('ws');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-relay-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;

const { serve } = require('../src/relay');
const tokens    = require('../src/tokens');
const tecnicos  = require('../src/tecnicos');

let relayServer;
let chaveTecnico;
let relayPort;
let globalToken;
let scopedToken;

function freePort() {
  return new Promise((resolve, reject) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

// Visitante de túnel é sempre um técnico com chave; semChave: true simula quem não tem.
function httpGet(port, opts = {}) {
  const { semChave, ...resto } = opts;
  const headers = { ...(semChave ? {} : { 'x-sig3-chave': chaveTecnico.raw }), ...(resto.headers || {}) };
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, ...resto, headers }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(opts.body ?? undefined);
  });
}

// Connect a WS tunnel client that responds to requests with a static handler.
function openTunnel(path, raw, handler) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}${path}`, {
      headers: { authorization: `Bearer ${raw}` },
    });
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
    ws.on('message', async msg => {
      const req = JSON.parse(msg);
      const reply = await handler(req);
      ws.send(JSON.stringify({ id: req.id, ...reply }));
    });
  });
}

// SIG3 que fala o protocolo 2: requisição e resposta em quadro binário (docs/protocolo.md).
function quadro(id, cabecalho, corpo) {
  const json = Buffer.from(JSON.stringify(cabecalho));
  const tam = Buffer.alloc(4);
  tam.writeUInt32BE(json.length);
  return Buffer.concat([Buffer.from(id, 'ascii'), tam, json, corpo]);
}

function openTunnelV2(path, raw, handler) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}${path}`, {
      headers: { authorization: `Bearer ${raw}`, 'x-sig3-protocolo': '2' },
    });
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
    ws.on('message', async (msg, isBinary) => {
      assert.ok(isBinary, 'protocolo 2 recebe a requisição em binário');
      const id = msg.subarray(0, 36).toString('ascii');
      const tam = msg.readUInt32BE(36);
      const req = JSON.parse(msg.subarray(40, 40 + tam).toString());
      const reply = await handler({ ...req, corpo: msg.subarray(40 + tam) });
      ws.send(quadro(id, { status: reply.status, headers: reply.headers }, reply.corpo), { binary: true });
    });
  });
}

before(async () => {
  relayPort   = await freePort();
  relayServer = serve(relayPort, '127.0.0.1');
  await new Promise((resolve, reject) => {
    relayServer.once('listening', resolve);
    relayServer.once('error', reject);
  });
  globalToken = tokens.issue('*');
  scopedToken = tokens.issue('preview');
  chaveTecnico = tecnicos.emitir('Teste');
});

after(() => {
  relayServer.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('/_sig3/ping returns ok', async () => {
  const r = await httpGet(relayPort, { path: '/_sig3/ping' });
  assert.equal(r.status, 200);
  assert.equal(r.body, 'ok');
});

test('request to unconnected tunnel returns 503', async () => {
  const r = await httpGet(relayPort, { path: '/anything', headers: { host: '127.0.0.1' } });
  assert.equal(r.status, 503);
  assert.ok(r.headers['content-type'].includes('text/html'));
  assert.ok(!/avelor/i.test(r.body));
});

test('GET / on root domain with no default tunnel returns splash page', async () => {
  const r = await httpGet(relayPort, { path: '/', headers: { host: 'tunel.example.com' } });
  assert.equal(r.status, 200);
  assert.ok(r.headers['content-type'].includes('text/html'));
  assert.ok(r.body.includes('sig3tunnel'));
  assert.ok(r.body.includes('relay running'));
});

test('relay rejects connection with invalid token', async () => {
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3`, {
      headers: { authorization: 'Bearer sig3_invalid' },
    });
    ws.once('close', (code) => {
      assert.equal(code, 1008);
      resolve();
    });
    ws.once('error', reject);
  });
});

test('relay rejects connection with mismatched scope', async () => {
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3/staging`, {
      headers: { authorization: `Bearer ${scopedToken.raw}` },
    });
    ws.once('close', (code) => {
      assert.equal(code, 1008);
      resolve();
    });
    ws.once('error', reject);
  });
});

test('relay forwards HTTP request to connected client and returns response', async () => {
  const ws = await openTunnel('/_sig3', globalToken.raw, req => ({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: Buffer.from('hello from tunnel').toString('base64'),
  }));

  try {
    const r = await httpGet(relayPort, { path: '/some/path', headers: { host: '127.0.0.1' } });
    assert.equal(r.status, 200);
    assert.equal(r.body, 'hello from tunnel');
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('relay echoes request method and URL to client', async () => {
  let received;
  const ws = await openTunnel('/_sig3', globalToken.raw, req => {
    received = req;
    return { status: 204, headers: {}, body: '' };
  });

  try {
    await httpGet(relayPort, { method: 'POST', path: '/echo-test', headers: { host: '127.0.0.1' } });
    assert.equal(received.method, 'POST');
    assert.equal(received.url, '/echo-test');
    assert.ok(received.id);
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('relay responds 502 to in-flight requests when client disconnects', async () => {
  const ws = await openTunnel('/_sig3', globalToken.raw, () =>
    new Promise(() => { /* never responds */ }),
  );

  const pending = httpGet(relayPort, { path: '/slow', headers: { host: '127.0.0.1' } });

  // Give relay time to enqueue the request, then disconnect.
  await new Promise(r => setTimeout(r, 50));
  ws.terminate();

  const r = await pending;
  assert.equal(r.status, 502);
});

test('scoped token connects to matching path', async () => {
  const ws = await openTunnel('/_sig3/preview', scopedToken.raw, req => ({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: Buffer.from('scoped').toString('base64'),
  }));

  try {
    // Route to "preview" tunnel via subdomain-style host header
    const r = await httpGet(relayPort, {
      path: '/test',
      headers: { host: 'preview.tunel.example.com' },
    });
    assert.equal(r.status, 200);
    assert.equal(r.body, 'scoped');
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('one-level host tunel-<name>.<domain> routes to the tunnel; the root and other names do not', async () => {
  const ws = await openTunnel('/_sig3/preview', scopedToken.raw, () => ({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: Buffer.from('um nivel').toString('base64'),
  }));

  try {
    const r = await httpGet(relayPort, { path: '/test', headers: { host: 'tunel-preview.example.com' } });
    assert.equal(r.status, 200);
    assert.equal(r.body, 'um nivel');

    const raiz = await httpGet(relayPort, { path: '/', headers: { host: 'tunel.example.com' } });
    assert.ok(raiz.body.includes('relay running'));

    const outro = await httpGet(relayPort, { path: '/test', headers: { host: 'agrovett.example.com' } });
    assert.equal(outro.status, 503);
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

// ---- chave do técnico ---------------------------------------------------------

test('without a technician key a tunnel answers 404, and does not reveal whether it is connected', async () => {
  let chamado = false;
  const ws = await openTunnel('/_sig3/fechado', globalToken.raw, () => { chamado = true; return { status: 200, headers: {}, body: '' }; });
  try {
    const conectado = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-fechado.example.com' }, semChave: true });
    const inexistente = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-nada.example.com' }, semChave: true });
    const chaveFalsa = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-fechado.example.com', 'x-sig3-chave': 'sig3t_' + '0'.repeat(48) }, semChave: true });
    assert.equal(conectado.status, 404);
    assert.equal(inexistente.status, 404);
    assert.equal(chaveFalsa.status, 404);
    assert.equal(chamado, false);
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('the key opens the tunnel, returns a cookie that works on its own, and neither reaches the client SIG3', async () => {
  const recebidos = [];
  const ws = await openTunnel('/_sig3/chave', globalToken.raw, req => {
    recebidos.push(req.headers);
    return { status: 200, headers: { 'set-cookie': ['app=1; Path=/'] }, body: '' };
  });
  try {
    const primeira = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-chave.example.com', cookie: 'outro=x' } });
    assert.equal(primeira.status, 200);
    const cookies = primeira.headers['set-cookie'];
    assert.equal(cookies[0], 'app=1; Path=/');
    const nosso = cookies.find(c => c.startsWith('sig3tec='));
    assert.match(nosso, /HttpOnly/);

    const segunda = await httpGet(relayPort, { path: '/x', headers: { host: 'tunel-chave.example.com', cookie: nosso.split(';')[0] + '; outro=x' }, semChave: true });
    assert.equal(segunda.status, 200);

    for (const h of recebidos) {
      assert.equal(h['x-sig3-chave'], undefined);
      assert.ok(!String(h.cookie || '').includes('sig3tec'));
    }
    assert.equal(recebidos[1].cookie, 'outro=x');
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('the cookie of one tunnel does not open another, and a revoked technician loses the cookie at once', async () => {
  const outro = tecnicos.emitir('Saiu da empresa');
  const ws = await openTunnel('/_sig3/aaa', globalToken.raw, () => ({ status: 200, headers: {}, body: '' }));
  const ws2 = await openTunnel('/_sig3/bbb', globalToken.raw, () => ({ status: 200, headers: {}, body: '' }));
  try {
    const r = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-aaa.example.com', 'x-sig3-chave': outro.raw }, semChave: true });
    const cookie = r.headers['set-cookie'].find(c => c.startsWith('sig3tec=')).split(';')[0];

    const noOutro = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-bbb.example.com', cookie }, semChave: true });
    assert.equal(noOutro.status, 404);

    tecnicos.revogar(outro.id);
    const depois = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-aaa.example.com', cookie }, semChave: true });
    assert.equal(depois.status, 404);
  } finally {
    for (const w of [ws, ws2]) { w.close(); await new Promise(r => w.once('close', r)); }
  }
});

test('an expired cookie is refused', () => {
  const t = tecnicos.emitir('Expira');
  const cookie = tecnicos.montarCookie(t, 'zzz', Date.now() - 5 * 60 * 60 * 1000);
  const valor = cookie.split(';')[0].slice('sig3tec='.length);
  assert.equal(tecnicos.porCookie(valor, 'zzz'), null);
  assert.ok(tecnicos.porCookie(tecnicos.montarCookie(t, 'zzz').split(';')[0].slice(8), 'zzz'));
});

test('protocol 2: request and response bodies travel as raw bytes, untouched', async () => {
  const bytes = Buffer.from([0, 255, 1, 254, 10, 13, 0x80]);
  let recebido;
  const ws = await openTunnelV2('/_sig3/binario', globalToken.raw, req => {
    recebido = req;
    return { status: 201, headers: { 'content-type': 'application/octet-stream' }, corpo: Buffer.concat([req.corpo, bytes]) };
  });

  try {
    const r = await new Promise((resolve, reject) => {
      const req = http.request({ hostname: '127.0.0.1', port: relayPort, method: 'POST', path: '/eco?x=1',
        headers: { host: 'tunel-binario.example.com', 'x-sig3-chave': chaveTecnico.raw } }, res => {
        const partes = [];
        res.on('data', c => partes.push(c));
        res.on('end', () => resolve({ status: res.statusCode, corpo: Buffer.concat(partes) }));
      });
      req.on('error', reject);
      req.end(bytes);
    });
    assert.equal(recebido.method, 'POST');
    assert.equal(recebido.url, '/eco?x=1');
    assert.deepEqual(recebido.corpo, bytes);
    assert.equal(r.status, 201);
    assert.deepEqual(r.corpo, Buffer.concat([bytes, bytes]));
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('one tunnel cannot use up the queue slots of the others', async () => {
  const travado = await openTunnel('/_sig3/lotado', globalToken.raw, () => new Promise(() => {}));
  const livre = await openTunnel('/_sig3/livre', globalToken.raw, () => ({ status: 200, headers: {}, body: '' }));

  const pendentes = [];
  try {
    for (let i = 0; i < 64; i++) pendentes.push(httpGet(relayPort, { path: `/p${i}`, headers: { host: 'tunel-lotado.example.com' } }));
    await new Promise(r => setTimeout(r, 100));

    const excedente = await httpGet(relayPort, { path: '/mais', headers: { host: 'tunel-lotado.example.com' } });
    assert.equal(excedente.status, 429);
    const outro = await httpGet(relayPort, { path: '/', headers: { host: 'tunel-livre.example.com' } });
    assert.equal(outro.status, 200);
  } finally {
    travado.terminate();
    await Promise.all(pendentes);
    livre.close();
    await new Promise(r => livre.once('close', r));
  }
});

test('relay rejects duplicate tunnel name', async () => {
  const ws1 = await openTunnel('/_sig3', globalToken.raw, () => ({ status: 200, headers: {}, body: '' }));

  try {
    await new Promise((resolve, reject) => {
      const ws2 = new WebSocket(`ws://127.0.0.1:${relayPort}/_sig3`, {
        headers: { authorization: `Bearer ${globalToken.raw}` },
      });
      ws2.once('close', (code) => {
        assert.equal(code, 1008);
        resolve();
      });
      ws2.once('error', reject);
    });
  } finally {
    ws1.close();
    await new Promise(r => ws1.once('close', r));
  }
});

test('relay adds X-Forwarded headers for reverse proxy compat (Next.js hydration)', async () => {
  let receivedHeaders;
  const ws = await openTunnel('/_sig3/myapp', globalToken.raw, req => {
    receivedHeaders = req.headers;
    return { status: 200, headers: {}, body: '' };
  });

  try {
    await httpGet(relayPort, {
      path: '/test-page',
      headers: { host: 'myapp.tunel.example.com' },
    });
    // SIG3.Tunnel should preserve the original host in x-forwarded-host
    assert.equal(receivedHeaders['x-forwarded-host'], 'myapp.tunel.example.com');
    // SIG3.Tunnel should set x-forwarded-proto (defaults to https for security)
    assert.equal(receivedHeaders['x-forwarded-proto'], 'https');
    // Client will later change Host to localhost:PORT, but these headers persist
    // so Next.js can determine the real origin without code changes
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('x-forwarded-for carries only the visitor IP (from nginx X-Real-IP), never what the visitor sent', async () => {
  let receivedHeaders;
  const ws = await openTunnel('/_sig3/ipreal', globalToken.raw, req => {
    receivedHeaders = req.headers;
    return { status: 200, headers: {}, body: '' };
  });

  try {
    await httpGet(relayPort, {
      path: '/',
      headers: { host: 'ipreal.tunel.example.com', 'x-forwarded-for': '6.6.6.6', 'x-real-ip': '8.8.4.4' },
    });
    assert.equal(receivedHeaders['x-forwarded-for'], '8.8.4.4');
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('Set-Cookie from a tunnel loses its Domain attribute (one tunnel cannot set cookies on the others)', async () => {
  const ws = await openTunnel('/_sig3/biscoito', globalToken.raw, () => ({
    status: 200,
    headers: { 'set-cookie': ['a=1; Domain=tunel.example.com; Path=/', 'b=2; Path=/; HttpOnly'] },
    body: '',
  }));

  try {
    const r = await httpGet(relayPort, { path: '/', headers: { host: 'biscoito.tunel.example.com' } });
    assert.deepEqual(r.headers['set-cookie'].filter(c => !c.startsWith('sig3tec=')), ['a=1; Path=/', 'b=2; Path=/; HttpOnly']);
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('a request target that is not an origin path ("//host", absolute URL) is refused before reaching any tunnel', async () => {
  let chamado = false;
  const ws = await openTunnel('/_sig3/rede', globalToken.raw, () => { chamado = true; return { status: 200, headers: {}, body: '' }; });

  try {
    for (const alvo of ['//192.168.0.1/', 'http://192.168.0.1/', '/\\192.168.0.1/']) {
      const r = await httpGet(relayPort, { path: alvo, headers: { host: 'rede.tunel.example.com' } });
      assert.equal(r.status, 400, alvo);
    }
    assert.equal(chamado, false);
  } finally {
    ws.close();
    await new Promise(r => ws.once('close', r));
  }
});

test('a tunnel cannot answer a request that was sent to another tunnel', async () => {
  let idDoAlfa;
  const chegou = new Promise(resolve => {
    openTunnel('/_sig3/alfa', globalToken.raw, req => { idDoAlfa = req.id; resolve(); return new Promise(() => {}); })
      .then(ws => { alfa = ws; });
  });
  let alfa;
  const beta = await openTunnel('/_sig3/beta', globalToken.raw, () => ({ status: 200, headers: {}, body: '' }));
  await new Promise(r => setTimeout(r, 30));

  try {
    const pendente = httpGet(relayPort, { path: '/', headers: { host: 'alfa.tunel.example.com' } });
    await chegou;
    beta.send(JSON.stringify({ id: idDoAlfa, status: 200, headers: {}, body: Buffer.from('intruso').toString('base64') }));
    await new Promise(r => setTimeout(r, 50));
    alfa.send(JSON.stringify({ id: idDoAlfa, status: 200, headers: {}, body: Buffer.from('legitimo').toString('base64') }));
    assert.equal((await pendente).body, 'legitimo');
  } finally {
    for (const ws of [alfa, beta]) { ws.close(); await new Promise(r => ws.once('close', r)); }
  }
});
