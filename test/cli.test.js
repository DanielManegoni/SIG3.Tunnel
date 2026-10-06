'use strict';

const { test }   = require('node:test');
const assert     = require('node:assert/strict');
const { execFile } = require('node:child_process');
const os         = require('node:os');
const fs         = require('node:fs');
const path       = require('node:path');

const BIN = path.join(__dirname, '..', 'bin', 'sig3tunnel.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-cli-'));

function run(args, extraEnv = {}) {
  return new Promise(resolve => {
    execFile(
      process.execPath,
      [BIN, ...args],
      { env: { ...process.env, SIG3TUNNEL_CONFIG_DIR: tmp, ...extraEnv } },
      (err, stdout, stderr) => resolve({ code: err?.code ?? 0, stdout, stderr }),
    );
  });
}

// ── help / version ────────────────────────────────────────────────────────────

test('no args prints usage and exits 0', async () => {
  const { code, stdout } = await run([]);
  assert.equal(code, 0);
  assert.ok(stdout.includes('sig3tunnel'));
  assert.ok(stdout.includes('serve'));
});

test('help prints usage and exits 0', async () => {
  const { code, stdout } = await run(['help']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('serve'));
  assert.ok(stdout.includes('connect'));
  assert.ok(stdout.includes('token'));
});

test('--help prints usage and exits 0', async () => {
  const { code, stdout } = await run(['--help']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('serve'));
});

test('-h prints usage and exits 0', async () => {
  const { code, stdout } = await run(['-h']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('serve'));
});

test('--version prints semver and exits 0', async () => {
  const { code, stdout } = await run(['--version']);
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+/);
});

test('-v prints semver and exits 0', async () => {
  const { code, stdout } = await run(['-v']);
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+/);
});

// ── error paths ───────────────────────────────────────────────────────────────

test('unknown command exits 1 with helpful message', async () => {
  const { code, stderr } = await run(['unknowncmd']);
  assert.equal(code, 1);
  assert.ok(stderr.includes('unknown command'));
  assert.ok(stderr.includes('unknowncmd'));
});

test('token issue without scope exits 1', async () => {
  const { code, stderr } = await run(['token', 'issue']);
  assert.equal(code, 1);
  assert.ok(stderr.includes('scope'));
});

test('token unknown subcommand exits 1', async () => {
  const { code, stderr } = await run(['token', 'badcmd']);
  assert.equal(code, 1);
  assert.ok(stderr.includes('unknown subcommand'));
});

test('use without args exits 1', async () => {
  const { code, stderr } = await run(['use']);
  assert.equal(code, 1);
  assert.ok(stderr.includes('usage'));
});

test('connect without saved config exits 1', async () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-nocfg-'));
  try {
    const { code, stderr } = await run(['connect', '3000'], { SIG3TUNNEL_CONFIG_DIR: empty });
    assert.equal(code, 1);
    assert.ok(stderr.includes('sig3tunnel use'));
  } finally {
    fs.rmSync(empty, { recursive: true, force: true });
  }
});

// ── token commands ────────────────────────────────────────────────────────────

test('token issue --scope creates token and prints id + raw', async () => {
  const { code, stdout } = await run(['token', 'issue', '--scope', 'ci']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('id:'));
  assert.ok(stdout.includes('token:'));
  assert.ok(stdout.match(/sig3_[0-9a-f]+/));
});

test('token issue --global creates global token', async () => {
  const { code, stdout } = await run(['token', 'issue', '--global']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('global'));
});

test('token list shows issued tokens', async () => {
  await run(['token', 'issue', '--scope', 'list-test']);
  const { code, stdout } = await run(['token', 'list']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('list-test'));
});

test('token revoke removes token', async () => {
  const issue = await run(['token', 'issue', '--scope', 'revoke-test']);
  const clean = issue.stdout.replace(/\x1b\[[0-9;]*m/g, '');
  const match = clean.match(/id:\s+([0-9a-f]+)/);
  assert.ok(match, 'could not parse id from output');
  const id = match[1].trim();

  const { code, stdout } = await run(['token', 'revoke', id]);
  assert.equal(code, 0);
  assert.ok(stdout.includes('revoked'));
});

test('token revoke unknown id exits 1', async () => {
  const { code, stderr } = await run(['token', 'revoke', 'deadbeef']);
  assert.equal(code, 1);
  assert.ok(stderr.includes('not found'));
});

// ── use ───────────────────────────────────────────────────────────────────────

test('use saves endpoint and token to config', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sig3tunnel-use-'));
  try {
    const { code, stdout } = await run(['use', 'wss://example.com', 'sig3_mytoken'], { SIG3TUNNEL_CONFIG_DIR: dir });
    assert.equal(code, 0);
    assert.ok(stdout.includes('saved'));
    const cfg = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
    assert.equal(cfg.endpoint, 'wss://example.com');
    assert.equal(cfg.token, 'sig3_mytoken');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
