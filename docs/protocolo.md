# Protocolo do túnel

Entre o relay (`src/relay.js`) e o SIG3 (`Services/Suporte/TunelSig3Tunnel.cs` no VSig.Web).
Mudou um lado, muda o outro e este arquivo. Os testes dos dois lados seguem o que está aqui.

## Conexão

O SIG3 abre um WebSocket em `wss://<relay>/_sig3/<nome>` com:

- `Authorization: Bearer <token>`: o token precisa ter escopo `<nome>` (ou `*`).
- `X-Sig3-Protocolo: 2`: opcional. Sem ele, o relay fala a versão 1.

Recusa fecha com código 1008 (`unauthorized`, `invalid path`, `name already in use`).
O relay manda ping a cada 30 s; sem pong até o próximo, derruba a conexão.

## Quem é atendido por qual túnel

Pelo `Host` do visitante: `tunel-<nome>.<domínio>` (ou o formato antigo `<nome>.tunel.<domínio>`).
O alvo da requisição precisa ser caminho de origem (`/x`); `//host/x` e URL absoluta dão 400.

## Só técnico do suporte entra num túnel

Toda requisição e todo upgrade para um túnel precisam de um destes, senão o relay responde 404
(antes de saber se o túnel existe):

- `X-Sig3-Chave: sig3t_...`: a chave do técnico (`sig3tunnel suporte emitir --nome <nome>`).
  A resposta traz, além dos cookies do SIG3, `Set-Cookie: sig3tec=<id>.<expira>.<assinatura>`
  (HttpOnly, 4 h, preso àquele túnel).
- o cookie `sig3tec` válido para aquele túnel. Técnico revogado perde o cookie na hora.

A chave e o cookie `sig3tec` nunca chegam ao SIG3 do cliente: o relay tira os dois antes de repassar.

## Requisição HTTP

Cabeçalhos repassados: os do visitante, com `x-forwarded-for` = IP do visitante (substitui o que
veio), `x-forwarded-host` = host público e `x-forwarded-proto` (padrão `https`).

**Versão 1 (texto):**
```
relay → SIG3   {"id", "method", "url", "headers", "body": "<base64>"}
SIG3 → relay   {"id", "status", "headers", "body": "<base64>"}
```

**Versão 2 (binário):** quadro único, nos dois sentidos:
```
36 bytes  id (UUID em ASCII)
 4 bytes  tamanho N do JSON (big-endian)
 N bytes  JSON: relay → SIG3 {"method", "url", "headers"}; SIG3 → relay {"status", "headers"}
 resto    corpo cru
```
O SIG3 só responde em binário a requisição que chegou em binário. O relay aceita as duas formas
de resposta de qualquer SIG3.

Nos `headers` de resposta, um valor pode ser texto ou lista de textos; `set-cookie` vai sempre
como lista (um item por cookie). O relay tira o `Domain=` de cada cookie e o `transfer-encoding`.

Só o túnel que recebeu a requisição pode respondê-la. Sem resposta em 95 s, o relay devolve 504;
o SIG3 desiste antes, em 90 s, e responde 502. A Cloudflare corta em 100 s.

## Upgrade de WebSocket (o `/_blazor`)

```
relay → SIG3   {"type": "upgrade", "id", "method", "url", "headers", "head": "<base64>"}
os dois lados  quadro binário: 36 bytes de id + bytes crus
os dois lados  {"type": "up-close", "id"}
```
O relay só aceita `Upgrade: websocket` (qualquer outro valor dá 400). O SIG3 abre um socket em
`127.0.0.1:<porta>`, repete o pedido de upgrade com `Host: localhost:<porta>` e liga os dois sentidos.
A primeira resposta dele tem de começar com `HTTP/1.1 101`, em até 30 s: qualquer outra coisa (ou o silêncio)
faz o relay derrubar o socket do navegador. O formato antigo de dados em texto (`{"type": "up-data", "id", "data"}`)
ainda é aceito pelo relay.

## Limites do relay

- Corpo da requisição: 10 MB (413).
- Requisições em espera: 256 no total, 64 por túnel (429).
- Upgrades abertos: 256 no total, 64 por túnel (429).

## Segurança

- **Raiz do relay:** `GET /` sem chave de técnico redireciona (302) para `https://bossoistec.com.br`
  (`SIG3TUNNEL_REDIRECT_RAIZ` troca o destino). Nenhuma página do relay mostra nome, versão ou estado.
  Qualquer outro caminho sem chave dá 404 (igual a túnel que não existe).
- **Bloqueio por IP** (em memória, some ao reiniciar):
  - chave de técnico errada: 20 erros em 15 min bloqueiam o IP por 15 min (429, mesmo com a chave certa);
  - token de túnel errado no WebSocket: 30 erros em 15 min bloqueiam por 10 min (fecha 1008 `rate limited`);
  - token de admin inválido: 10 erros em 15 min, 15 min de bloqueio;
    (token **expirado**, com assinatura certa, responde 401 `sessao_expirada` e não conta: é sessão que venceu, não invasão);
  - segredo de pedido errado: 10 erros em 15 min, 15 min de bloqueio;
  - API: no máximo 120 chamadas por minuto por IP.
  O IP é o `X-Real-IP`, só confiado quando a conexão vem do loopback (o nginx).
- **O SIG3 do cliente é entrada não confiável.** Mensagem malformada (JSON `null`, status fora de 200-599,
  cabeçalho com quebra de linha) não derruba o relay: a requisição recebe 502 e o fato vai para o log.
  `content-length` vem do corpo real; `connection`, `keep-alive`, `transfer-encoding` e afins são descartados.
  Mensagem de túnel acima de 64 MB fecha a conexão.
- **Admin:** só JWT do NewAdmin (HS256, perfil `admin`, com `exp`, emissor e audiência) e
  `SIG3TUNNEL_JWT_SECRET` com **no mínimo 32 caracteres** (menos que isso desliga o admin). "Liberado por" é o
  login do token. Aprovar, recusar, editar e excluir ficam no log com login e IP.
- **Cabeçalhos** nas respostas do próprio relay: `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Strict-Transport-Security`.
- **Pedido de outro site:** autorizado só pelo cookie, o pedido precisa nascer na própria página do túnel
  (`Sec-Fetch-Site`, `Sec-Fetch-Dest` e `Origin`); senão 403. Clicar num link (navegação GET) vindo de fora passa.
- **Chave revogada** derruba também os upgrades que o técnico já tinha abertos.
- **Servidor HTTP:** cabeçalhos em 20 s, pedido inteiro em 2 min, no máximo 100 cabeçalhos.
- **Disco:** pasta de dados `0700`, arquivos `0600`.
