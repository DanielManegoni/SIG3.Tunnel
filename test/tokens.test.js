'use strict';

const { test, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-tokens-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;

const tokens = require('../src/tokens');

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

beforeEach(() => {
  try { fs.unlinkSync(path.join(tmp, 'tokens.json')); } catch { /* ok */ }
});

test('issue returns id, raw token with bf_ prefix, and scope', () => {
  const r = tokens.issue('preview');
  assert.ok(r.id);
  assert.ok(r.raw.startsWith('bf_'));
  assert.equal(r.scope, 'preview');
});

test('issue stores hash not raw value', () => {
  const r    = tokens.issue('staging');
  const list = JSON.parse(fs.readFileSync(path.join(tmp, 'tokens.json'), 'utf8'));
  const entry = list.find(t => t.id === r.id);
  assert.ok(entry, 'entry not found in file');
  assert.equal(entry.hash.length, 64);       // SHA-256 hex
  assert.ok(!entry.hash.startsWith('bf_'));  // hash, not raw
  assert.ok(!('raw' in entry));
});

test('list omits hash field', () => {
  tokens.issue('a');
  tokens.issue('b');
  for (const t of tokens.list()) {
    assert.ok(!('hash' in t));
    assert.ok(t.id);
    assert.ok(t.scope);
    assert.ok(t.created);
  }
});

test('validate accepts correct token and scope', () => {
  const r = tokens.issue('myapp');
  const entry = tokens.validate(r.raw, 'myapp');
  assert.ok(entry);
  assert.equal(entry.id, r.id);
});

test('validate rejects wrong raw value', () => {
  tokens.issue('myapp');
  assert.equal(tokens.validate('bf_notvalid', 'myapp'), null);
});

test('validate rejects scope mismatch', () => {
  const r = tokens.issue('staging');
  assert.equal(tokens.validate(r.raw, 'production'), null);
});

test('global token validates against any scope', () => {
  const r = tokens.issue('*');
  assert.ok(tokens.validate(r.raw, 'anything'));
  assert.ok(tokens.validate(r.raw, 'other'));
  assert.ok(tokens.validate(r.raw, null));
  assert.ok(tokens.validate(r.raw, 'default'));
});

test('revoke removes token', () => {
  const r = tokens.issue('temp');
  assert.ok(tokens.validate(r.raw, 'temp'));
  assert.equal(tokens.revoke(r.id), true);
  assert.equal(tokens.validate(r.raw, 'temp'), null);
});

test('revoke returns false for unknown id', () => {
  assert.equal(tokens.revoke('doesnotexist'), false);
});

test('multiple tokens coexist independently', () => {
  const a = tokens.issue('alpha');
  const b = tokens.issue('beta');
  assert.ok(tokens.validate(a.raw, 'alpha'));
  assert.ok(tokens.validate(b.raw, 'beta'));
  assert.equal(tokens.validate(a.raw, 'beta'), null);
  assert.equal(tokens.validate(b.raw, 'alpha'), null);
});
