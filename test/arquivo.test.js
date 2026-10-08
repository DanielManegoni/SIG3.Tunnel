'use strict';

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const os     = require('node:os');
const path   = require('node:path');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-arquivo-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;

const { lerJson, lerJsonCache, gravarJson, ErroArquivo } = require('../src/arquivo');
const tokens = require('../src/tokens');
const { TOKENS_FILE } = require('../src/paths');
const { serve } = require('../src/relay');

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const caminho = nome => path.join(tmp, nome);

test('missing file reads as the default, not as an error', () => {
  assert.deepEqual(lerJson(caminho('nao-existe.json')), []);
  assert.deepEqual(lerJsonCache(caminho('nao-existe.json'), { a: 1 }), { a: 1 });
});

test('writing keeps the previous version in .bak and leaves no temp file behind', () => {
  const f = caminho('dados.json');
  gravarJson(f, [1]);
  gravarJson(f, [1, 2]);

  assert.deepEqual(lerJson(f), [1, 2]);
  assert.deepEqual(JSON.parse(fs.readFileSync(f + '.bak', 'utf8')), [1]);
  assert.deepEqual(fs.readdirSync(tmp).filter(n => n.includes('.tmp-')), []);
});

test('a broken file throws ErroArquivo pointing at the .bak, instead of reading as empty', () => {
  const f = caminho('quebrado.json');
  fs.writeFileSync(f, '[{"id": "a"');
  assert.throws(() => lerJson(f), e => e instanceof ErroArquivo && /JSON inválido/.test(e.message) && /quebrado\.json\.bak/.test(e.message));
});

test('the cache returns the same data until the file changes', () => {
  const f = caminho('cache.json');
  gravarJson(f, ['a']);
  const primeira = lerJsonCache(f);
  assert.equal(lerJsonCache(f), primeira);

  gravarJson(f, ['a', 'b']);
  assert.deepEqual(lerJsonCache(f), ['a', 'b']);
});

test('a token check with an unreadable tokens file refuses and logs, never accepts', () => {
  const ok = tokens.issue('*');
  assert.ok(tokens.validate(ok.raw, 'x'));

  const original = fs.readFileSync(TOKENS_FILE);
  fs.writeFileSync(TOKENS_FILE, '{quebrado');
  const erros = [];
  const antes = console.error;
  console.error = m => erros.push(m);
  try {
    assert.equal(tokens.validate(ok.raw, 'x'), null);
    assert.ok(erros.some(m => /tokens\.json/.test(m)));
  } finally {
    console.error = antes;
    fs.writeFileSync(TOKENS_FILE, original);
  }
});

test('the relay refuses to start with an unreadable data file', () => {
  const original = fs.readFileSync(TOKENS_FILE);
  fs.writeFileSync(TOKENS_FILE, '{quebrado');
  try {
    assert.throws(() => serve(0, '127.0.0.1'), ErroArquivo);
  } finally {
    fs.writeFileSync(TOKENS_FILE, original);
  }
});
