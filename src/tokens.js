'use strict';

const crypto                   = require('crypto');
const { TOKENS_FILE } = require('./paths');
const { lerJsonCache, gravarJson } = require('./arquivo');

const readTokens  = () => lerJsonCache(TOKENS_FILE);
const writeTokens = list => gravarJson(TOKENS_FILE, list);

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function issue(scope) {
  const raw  = 'sig3_' + crypto.randomBytes(24).toString('hex');
  const hash = hashToken(raw);
  const id   = crypto.randomBytes(4).toString('hex');

  const list = [...readTokens()];
  list.push({ id, hash, scope, created: new Date().toISOString() });
  writeTokens(list);

  return { id, raw, scope };
}

function list() {
  return readTokens().map(({ id, scope, created }) => ({ id, scope, created }));
}

function revoke(id) {
  const before = readTokens();
  const after  = before.filter(t => t.id !== id);
  if (after.length === before.length) return false;
  writeTokens(after);
  return true;
}

// Returns the matching token entry (without hash) or null.
// name is the tunnel name being requested (e.g. "preview"), or null for the default.
function validate(raw, name) {
  const hash = hashToken(raw);
  let tokens;
  try {
    tokens = readTokens();
  } catch (e) {
    // Arquivo ilegível recusa a conexão e avisa; nunca vira "nenhum token" em silêncio.
    console.error(`[sig3tunnel] ${e.message}`);
    return null;
  }
  const entry = tokens.find(t => t.hash === hash);
  if (!entry) return null;

  if (entry.scope === '*') return entry;

  const requested = (name || 'default').toLowerCase();
  if (entry.scope === requested) return entry;

  return null;
}

module.exports = { issue, list, revoke, validate };
