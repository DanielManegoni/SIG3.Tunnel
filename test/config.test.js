'use strict';

const { test, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const os     = require('node:os');
const fs     = require('node:fs');
const path   = require('node:path');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-config-'));
process.env.SIG3TUNNEL_CONFIG_DIR = tmp;

const { readConfig, writeConfig, requireConfig } = require('../src/config');

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

beforeEach(() => {
  try { fs.unlinkSync(path.join(tmp, 'config.json')); } catch { /* ok */ }
});

test('readConfig returns empty object when file absent', () => {
  assert.deepEqual(readConfig(), {});
});

test('writeConfig + readConfig round-trip', () => {
  writeConfig({ endpoint: 'wss://example.com', token: 'bf_abc' });
  const cfg = readConfig();
  assert.equal(cfg.endpoint, 'wss://example.com');
  assert.equal(cfg.token, 'bf_abc');
});

test('writeConfig creates config directory if missing', () => {
  fs.rmSync(tmp, { recursive: true, force: true });
  writeConfig({ endpoint: 'wss://x.com', token: 'bf_y' });
  assert.ok(fs.existsSync(path.join(tmp, 'config.json')));
});

test('requireConfig returns config when endpoint and token present', () => {
  writeConfig({ endpoint: 'wss://example.com', token: 'bf_abc' });
  const cfg = requireConfig();
  assert.equal(cfg.endpoint, 'wss://example.com');
  assert.equal(cfg.token, 'bf_abc');
});

test('requireConfig exits 1 when config missing', async () => {
  const { execFile } = require('node:child_process');
  const BIN = path.join(__dirname, '..', 'bin', 'sig3tunnel.js');
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-empty-'));
  try {
    await new Promise((resolve, reject) => {
      execFile(process.execPath, [BIN, 'connect', '3000'],
        { env: { ...process.env, SIG3TUNNEL_CONFIG_DIR: empty } },
        (err, _stdout, stderr) => {
          if (!err) return reject(new Error('expected non-zero exit'));
          assert.equal(err.code, 1);
          assert.ok(stderr.includes('sig3tunnel use'));
          resolve();
        });
    });
  } finally {
    fs.rmSync(empty, { recursive: true, force: true });
  }
});
