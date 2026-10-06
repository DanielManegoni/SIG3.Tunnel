'use strict';

const MESSAGES = {
  400: 'Bad request.',
  413: 'Payload too large.',
  429: 'Too many pending requests.',
  502: 'Tunnel disconnected.',
  503: 'Tunnel not connected.',
  504: 'Gateway timeout.',
};

function htmlPage(code, message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${code}</title>
  <style>
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      font-family: Georgia, 'Times New Roman', serif;
      background: #fff;
      color: #111;
      border-top: 3px solid #111;
    }
    .code {
      font-size: clamp(5rem, 18vw, 9rem);
      font-weight: 400;
      line-height: 1;
      letter-spacing: -0.03em;
    }
    .message {
      margin-top: 1.25rem;
      font-size: 0.875rem;
      color: #aaa;
      letter-spacing: 0.01em;
    }
    footer {
      position: fixed;
      bottom: 1.75rem;
      left: 0; right: 0;
      text-align: center;
      font-size: 0.7rem;
      color: #999;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
  </style>
</head>
<body>
  <span class="code">${code}</span>
  <p class="message">${message}</p>
  <footer>Avelor · sig3tunnel</footer>
</body>
</html>
`;
}

function jsonPage(code, message) {
  return JSON.stringify({ code, message, source: 'sig3-tunnel' }, null, 2) + '\n';
}

function xmlPage(code, message) {
  const msg = message
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
  return `<?xml version="1.0" encoding="UTF-8"?>
<error>
  <code>${code}</code>
  <message>${msg}</message>
</error>
<!-- Avelor · sig3tunnel -->
`;
}

function textPage(code, message) {
  return `${code} ${message}\n\n— Avelor · sig3tunnel\n`;
}

// Detect preferred format from URL extension first, then Accept header.
function detectFormat(url, accept) {
  const pathname = (url || '').split('?')[0];
  if (pathname.endsWith('.json')) return 'json';
  if (pathname.endsWith('.xml'))  return 'xml';
  if (pathname.endsWith('.txt'))  return 'txt';

  const a = accept || '';
  if (!a) return 'html';

  const FORMATS = {
    'text/html':        'html',
    'application/xhtml+xml': 'html',
    'application/json': 'json',
    'text/json':        'json',
    'application/xml':  'xml',
    'text/xml':         'xml',
    'text/plain':       'txt',
  };

  let best = null;
  let bestQ = -1;

  for (const part of a.split(',')) {
    const [rawType, ...params] = part.trim().split(';');
    const type = rawType.trim().toLowerCase();
    const qParam = params.find(p => p.trim().startsWith('q='));
    const q = qParam ? parseFloat(qParam.trim().slice(2)) : 1;

    const fmt = FORMATS[type];
    if (fmt && q > bestQ) {
      best  = fmt;
      bestQ = q;
    }
  }

  return best || 'html';
}

const CONTENT_TYPES = {
  html: 'text/html; charset=utf-8',
  json: 'application/json',
  xml:  'application/xml',
  txt:  'text/plain; charset=utf-8',
};

function errorResponse(res, status, req) {
  const message = MESSAGES[status] || 'An error occurred.';
  const format  = detectFormat(req.url || '', req.headers.accept || '');

  const body = format === 'json' ? jsonPage(status, message)
             : format === 'xml'  ? xmlPage(status, message)
             : format === 'txt'  ? textPage(status, message)
             :                     htmlPage(status, message);

  res.writeHead(status, { 'Content-Type': CONTENT_TYPES[format], 'Vary': 'Accept' });
  res.end(body);
}

module.exports = { errorResponse };
