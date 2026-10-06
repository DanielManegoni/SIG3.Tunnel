'use strict';

const fs                                              = require('fs');
const { CONFIG_FILE, ensureDir }                      = require('./paths');
const { fatal }                                       = require('./fmt');

function readConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function writeConfig(data) {
  ensureDir();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function requireConfig() {
  const cfg = readConfig();
  if (!cfg.endpoint || !cfg.token) {
    fatal('not configured. Run:\n  sig3tunnel use <endpoint> <token>');
  }
  return cfg;
}

module.exports = { readConfig, writeConfig, requireConfig };
