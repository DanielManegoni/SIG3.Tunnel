#!/usr/bin/env node
'use strict';

const { fatal, ok, info, G, W, GR, Y, Z } = require('../src/fmt');
const { readConfig, writeConfig, requireConfig } = require('../src/config');
const tokens  = require('../src/tokens');
const daemon  = require('../src/daemon');
const relay   = require('../src/relay');
const client  = require('../src/client');

const USAGE = `
${G}sig3tunnel${Z} — self-hosted WebSocket tunnel relay

${G}server:${Z}
  ${W}serve${Z} [--port 9001] [--host 0.0.0.0] [--daemon]    start the relay
  ${W}stop${Z}                              stop the daemon
  ${W}status${Z}                            daemon status

${G}tokens:${Z}
  ${W}token issue${Z} --scope <name>        issue a token scoped to one subdomain
  ${W}token issue${Z} --global              issue a token valid for all subdomains
  ${W}token list${Z}                        list active tokens
  ${W}token revoke${Z} <id>                 revoke a token

${G}client:${Z}
  ${W}use${Z} <endpoint> <token>            save endpoint and token to ~/.config/sig3tunnel/
  ${W}connect${Z} <port>                    expose localhost:<port> through the relay
  ${W}connect${Z} <port> --name <name>      use a specific subdomain
  ${W}connect${Z} <port> --run "cmd"        start a process and tunnel it

${G}config:${Z} ~/.config/sig3tunnel/config.json
`;

function parseFlags(args) {
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      const next = args[i + 1];
      flags[key] = (next && !next.startsWith('--')) ? (i++, next) : true;
    }
  }
  return flags;
}

(async () => {
  const [,, cmd, sub, ...rest] = process.argv;

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    process.stdout.write(USAGE + '\n');
    process.exit(0);
  }

  if (cmd === '--version' || cmd === '-v') {
    process.stdout.write(require('../package.json').version + '\n');
    process.exit(0);
  }

  switch (cmd) {

    // ── serve ────────────────────────────────────────────────────────────────
    case 'serve': {
      const flags = parseFlags([sub, ...rest].filter(Boolean));
      const port  = parseInt(flags.port || process.env.PORT || '9001', 10);
      const host  = flags.host || process.env.HOST || '0.0.0.0';

      if (flags.daemon && !process.env.SIG3TUNNEL_DAEMON) {
        daemon.start(process.argv.slice(1));
        break;
      }

      relay.serve(port, host);
      break;
    }

    // ── stop / status ────────────────────────────────────────────────────────
    case 'stop':   daemon.stop();   break;
    case 'status': daemon.status(); break;

    // ── token ────────────────────────────────────────────────────────────────
    case 'token': {
      switch (sub) {

        case 'issue': {
          const flags = parseFlags(rest);

          if (!flags.scope && !flags.global) {
            fatal('specify the token scope:\n' +
              '  sig3tunnel token issue --scope <subdomain>\n' +
              '  sig3tunnel token issue --global');
          }

          const scope  = flags.global ? '*' : flags.scope.toLowerCase();
          const result = tokens.issue(scope);

          ok('token issued');
          process.stdout.write('\n');
          process.stdout.write(G + '  id:     ' + Z + result.id + '\n');
          process.stdout.write(G + '  scope:  ' + Z + (scope === '*' ? 'global' : scope) + '\n');
          process.stdout.write(G + '  token:  ' + Z + W + result.raw + Z + '\n');
          process.stdout.write('\n');
          process.stdout.write(G + '  → run on your machine:\n' + Z);
          process.stdout.write('  ' + W + `sig3tunnel use <endpoint> ${result.raw}` + Z + '\n\n');
          break;
        }

        case 'list': {
          const list = tokens.list();
          if (!list.length) {
            process.stdout.write(G + 'no tokens\n' + Z);
            break;
          }
          process.stdout.write('\n');
          process.stdout.write(
            G + 'id        scope           created\n' + Z +
            G + '────────  ──────────────  ────────────────────\n' + Z,
          );
          for (const t of list) {
            const scope = t.scope === '*' ? 'global' : t.scope;
            process.stdout.write(
              W + t.id.padEnd(10) + Z +
              scope.padEnd(16) +
              G + t.created + Z + '\n',
            );
          }
          process.stdout.write('\n');
          break;
        }

        case 'revoke': {
          const id = sub === 'revoke' ? rest[0] : null;
          if (!id) fatal('usage: sig3tunnel token revoke <id>');
          if (tokens.revoke(id)) ok('token ' + id + ' revoked');
          else fatal('token not found: ' + id);
          break;
        }

        default:
          fatal('unknown subcommand: token ' + (sub || '') + '\n  run: sig3tunnel help');
      }
      break;
    }

    // ── use ──────────────────────────────────────────────────────────────────
    case 'use': {
      const endpoint = sub;
      const token    = rest[0];
      if (!endpoint || !token) fatal('usage: sig3tunnel use <endpoint> <token>');

      writeConfig({ endpoint, token });
      ok('saved to ~/.config/sig3tunnel/config.json');
      break;
    }

    // ── connect ──────────────────────────────────────────────────────────────
    case 'connect': {
      const cfg  = requireConfig();
      const port = sub;
      await client.connect(cfg, port, rest);
      break;
    }

    default:
      fatal('unknown command: ' + cmd + '\n  run: sig3tunnel help');
  }
})();
