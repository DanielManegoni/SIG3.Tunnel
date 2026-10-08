'use strict';

const path = require('path');
const os   = require('os');
const fs   = require('fs');

const CONFIG_DIR   = process.env.SIG3TUNNEL_CONFIG_DIR || path.join(os.homedir(), '.config', 'sig3tunnel');
const TOKENS_FILE  = path.join(CONFIG_DIR, 'tokens.json');
const PEDIDOS_FILE = path.join(CONFIG_DIR, 'pedidos.json');
const TECNICOS_FILE = path.join(CONFIG_DIR, 'tecnicos.json');

function ensureDir() {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

module.exports = { CONFIG_DIR, TOKENS_FILE, PEDIDOS_FILE, TECNICOS_FILE, ensureDir };
