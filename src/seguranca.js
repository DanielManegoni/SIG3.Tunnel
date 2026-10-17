'use strict';

// Cabeçalhos das respostas que o PRÓPRIO relay gera (erros, redirecionamento, API). Respostas que vêm do
// SIG3 do cliente, repassadas ao técnico, não passam por aqui: o conteúdo é dele.
const CABECALHOS_SEGUROS = {
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000',
};

// Para onde vai quem abre o endereço do relay sem chave: o site da empresa, sem mostrar nada do relay.
const REDIRECIONAR_RAIZ_PARA = process.env.SIG3TUNNEL_REDIRECT_RAIZ || 'https://bossoistec.com.br';

module.exports = { CABECALHOS_SEGUROS, REDIRECIONAR_RAIZ_PARA };
