'use strict';

const MENSAGENS = {
  400: 'Pedido inválido.',
  404: 'Não encontrado.',
  413: 'Conteúdo grande demais.',
  429: 'Muitos pedidos ao mesmo tempo. Tente de novo em instantes.',
  502: 'O acesso foi desconectado.',
  503: 'Este acesso não está conectado agora.',
  504: 'O sistema demorou demais para responder.',
};

function pagina(status, mensagem) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${status}</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: flex; flex-direction: column; align-items: center;
         justify-content: center; padding: 16px; box-sizing: border-box; background: Canvas;
         color: CanvasText; font-family: system-ui, "Segoe UI", sans-serif; text-align: center; }
  .codigo { font-size: 4rem; font-weight: 300; line-height: 1; }
  p { margin-top: 1rem; color: GrayText; }
</style>
</head>
<body>
  <div class="codigo">${status}</div>
  <p>${mensagem}</p>
</body>
</html>
`;
}

function errorResponse(res, status) {
  if (res.headersSent) return;
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(pagina(status, MENSAGENS[status] || 'Ocorreu um erro.'));
}

module.exports = { errorResponse };
