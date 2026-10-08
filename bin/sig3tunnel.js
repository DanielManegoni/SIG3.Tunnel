#!/usr/bin/env node
'use strict';

const { fatal, ok, G, W, Z } = require('../src/fmt');
const tokens   = require('../src/tokens');
const tecnicos = require('../src/tecnicos');
const relay  = require('../src/relay');

// O lado cliente do túnel é o próprio SIG3 (VSig.Web, TunelSig3Tunnel.cs): aqui só o relay e os tokens.
const USAGE = `
${G}sig3tunnel${Z} — relay do acesso remoto do SIG3

${G}servidor:${Z}
  ${W}serve${Z} [--port 9001] [--host 127.0.0.1]   sobe o relay (atrás do nginx)

${G}tokens:${Z}
  ${W}token issue${Z} --scope <nome>        token que só abre o túnel <nome>
  ${W}token issue${Z} --global              token que abre qualquer túnel
  ${W}token list${Z}                        lista os tokens
  ${W}token revoke${Z} <id>                 revoga um token

${G}técnicos do suporte (só eles chegam a um tunel-<código>):${Z}
  ${W}suporte emitir${Z} --nome <nome>      emite a chave de um técnico (mostrada uma vez só)
  ${W}suporte listar${Z}                    lista os técnicos
  ${W}suporte revogar${Z} <id>              revoga a chave (e os acessos abertos com ela)
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
  case 'serve': {
    const flags = parseFlags([sub, ...rest].filter(Boolean));
    const port  = parseInt(flags.port || process.env.PORT || '9001', 10);
    // Só loopback por padrão: o relay não fala HTTPS e confia no X-Real-IP de quem vem do loopback (o nginx).
    const host  = flags.host || process.env.HOST || '127.0.0.1';
    relay.serve(port, host);
    break;
  }

  case 'token': {
    switch (sub) {
      case 'issue': {
        const flags = parseFlags(rest);
        if (!flags.scope && !flags.global) {
          fatal('specify the token scope:\n' +
            '  sig3tunnel token issue --scope <name>\n' +
            '  sig3tunnel token issue --global');
        }

        const scope  = flags.global ? '*' : flags.scope.toLowerCase();
        const result = tokens.issue(scope);

        ok('token issued');
        process.stdout.write('\n');
        process.stdout.write(G + '  id:     ' + Z + result.id + '\n');
        process.stdout.write(G + '  scope:  ' + Z + (scope === '*' ? 'global' : scope) + '\n');
        process.stdout.write(G + '  token:  ' + Z + W + result.raw + Z + '\n\n');
        break;
      }

      case 'list': {
        const list = tokens.list();
        if (!list.length) {
          process.stdout.write(G + 'no tokens\n' + Z);
          break;
        }
        process.stdout.write('\n' +
          G + 'id        scope           created\n' + Z +
          G + '────────  ──────────────  ────────────────────\n' + Z);
        for (const t of list) {
          const scope = t.scope === '*' ? 'global' : t.scope;
          process.stdout.write(W + t.id.padEnd(10) + Z + scope.padEnd(16) + G + t.created + Z + '\n');
        }
        process.stdout.write('\n');
        break;
      }

      case 'revoke': {
        const id = rest[0];
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

  case 'suporte': {
    switch (sub) {
      case 'emitir': {
        const flags = parseFlags(rest);
        if (!flags.nome || flags.nome === true) fatal('informe o técnico: sig3tunnel suporte emitir --nome <nome>');
        const t = tecnicos.emitir(flags.nome);
        ok('chave emitida para ' + t.nome);
        process.stdout.write('\n');
        process.stdout.write(G + '  id:     ' + Z + t.id + '\n');
        process.stdout.write(G + '  chave:  ' + Z + W + t.raw + Z + '\n\n');
        process.stdout.write(G + '  Guarde agora: ela não aparece de novo. O técnico cola no SIG3.Client --suporte.\n\n' + Z);
        break;
      }

      case 'listar': {
        const lista = tecnicos.listar();
        if (!lista.length) {
          process.stdout.write(G + 'nenhum técnico\n' + Z);
          break;
        }
        for (const t of lista) process.stdout.write(W + t.id.padEnd(10) + Z + t.nome.padEnd(30) + G + t.criado + Z + '\n');
        break;
      }

      case 'revogar': {
        const id = rest[0];
        if (!id) fatal('uso: sig3tunnel suporte revogar <id>');
        if (tecnicos.revogar(id)) ok('chave ' + id + ' revogada');
        else fatal('técnico não encontrado: ' + id);
        break;
      }

      default:
        fatal('unknown subcommand: suporte ' + (sub || '') + '\n  run: sig3tunnel help');
    }
    break;
  }

  default:
    fatal('unknown command: ' + cmd + '\n  run: sig3tunnel help');
}
