'use strict';

const G  = '\x1b[90m';
const W  = '\x1b[97m';
const GR = '\x1b[32m';
const R  = '\x1b[31m';
const Z  = '\x1b[0m';

function fatal(msg) {
  process.stderr.write(R + 'error: ' + Z + msg + '\n');
  process.exit(1);
}

function ok(msg) {
  process.stdout.write(GR + '✓ ' + Z + msg + '\n');
}

module.exports = { G, W, Z, fatal, ok };
