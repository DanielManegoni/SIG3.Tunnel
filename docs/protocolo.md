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
O SIG3 abre um socket em `127.0.0.1:<porta>`, repete o pedido de upgrade com `Host: localhost:<porta>`
e liga os dois sentidos. O formato antigo de dados em texto (`{"type": "up-data", "id", "data"}`)
ainda é aceito pelo relay.

## Limites do relay

- Corpo da requisição: 10 MB (413).
- Requisições em espera: 256 no total, 64 por túnel (429).
- Upgrades abertos: 256 no total, 64 por túnel (429).
