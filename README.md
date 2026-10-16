# palta

Alternativa a Apache Guacamole: gateway web en Go y daemon de sesiones (reemplazo de guacd) en Rust, con funciones de PAM (Privileged Access Management).

Scope completo y roadmap: [docs/SCOPE.md](docs/SCOPE.md).

```
browser (xterm.js) ──WebSocket──▶ palta-gw (Go) ──PTP/TCP──▶ paltad (Rust) ──SSH──▶ host
                                      │                          └─ grabación asciicast
                                      ├─ auth: local (bcrypt + TOTP); OIDC más adelante
                                      ├─ bóveda de credenciales (AES-256-GCM)
                                      ├─ grants con TTL (acceso just-in-time)
                                      └─ auditoría de sesiones (SQLite)
                                      └─ compat: protocolo Guacamole → guacd legacy (WIP)
```

## Componentes

| Ruta | Qué es |
|---|---|
| `paltad/crates/palta-proto` | PTP (protocolo nativo) + codec del protocolo Guacamole |
| `paltad/crates/paltad` | Daemon: SSH (russh), VNC (cliente RFB propio), proxy al worker RDP, grabación asciicast y gráfica |
| `paltad/crates/palta-gfx` | Framebuffer y codificación de tiles PNG/JPEG (compartido por paltad y paltad-rdp) |
| `paltad/rdp` | `paltad-rdp`: worker RDP sobre IronRDP, un proceso por sesión, PTP por stdin/stdout (workspace propio) |
| `gateway/` | `palta-gw`: API REST + WS, auth, bóveda, store SQLite (sqlc), CLI; `palta-agent` |
| `gateway/internal/guac` | Codec Guacamole + handshake de cliente contra guacd |

## PTP (Palta Transport Protocol)

Sesiones gráficas (VNC y RDP): `paltad` mantiene el framebuffer remoto y manda operaciones de pantalla
(tamaño, imagen PNG/JPEG, copia, relleno, cursor, fin de frame); el navegador las dibuja en un canvas y confirma
cada frame, que es el control de flujo. Formato: `paltad/crates/palta-proto/src/gfx.rs`.


Frames `u32 len BE | u8 kind | payload`. `0x01` control en JSON, `0x02` salida, `0x03` entrada.
Para SSH se transmite el stream crudo de la PTY y lo renderiza el navegador; guacd, en cambio,
rasteriza la terminal en el servidor y manda imágenes.
Las credenciales viajan solo gateway → daemon (inyección), nunca al navegador.

## Probarlo

```sh
deploy/dev.sh          # sshd en podman + paltad + palta-gw (compila la UI si hace falta)
# http://127.0.0.1:8088  usuario admin / palta-admin-123
DEV=1 deploy/dev.sh    # gateway con -dev: sin autenticación
deploy/dev.sh stop
```

## UI (`web/`)

React 19 + Vite + bun, fork del front de ducktainer (kit `ui/`, store, router, i18n en/es). Marca DuckJump en
`assets/brand/` (logo, símbolo e ícono en SVG). Los tipos salen del contrato OpenAPI (`bun run gen-api`).

```sh
cd gateway && make web           # compila la UI dentro de internal/server/ui/dist (la embebe palta-gw)
cd web && bun run dev            # desarrollo con recarga, proxy de /api a :8088
```

Sin compilar la UI, el gateway sirve el visor PoC mínimo. La UI compilada se sirve con una CSP estricta
(sin orígenes externos).

Las grabaciones quedan en `.dev/rec/*.cast` (`asciinema play archivo.cast`).

### Sitio edge simulado

```sh
deploy/dev.sh && deploy/edge.sh   # red podman --internal con un sshd + palta-agent
# en la UI: edge-sshd (edge1). El host 10.89.50.10 solo es alcanzable vía túnel inverso.
deploy/edge.sh stop
```

El agente sale por WebSocket a `palta-gw -agent-listen` (yamux encima). paltad llega al host con un ticket de un
solo uso que canjea en el relay del gateway (`-relay-listen`). El agente solo hace dial a lo que permite su `-allow`.

## API

REST en `/api/v1`. Se autentica con `POST /api/v1/auth/login`, que deja la cookie `palta_session`, más
`POST /api/v1/auth/totp` si el usuario tiene TOTP. Todo request que modifica estado lleva el header
`X-Palta-Request` (cualquier valor) como defensa CSRF.

El contrato es [`gateway/openapi/openapi.yaml`](gateway/openapi/openapi.yaml) (OpenAPI 3.1). Se **genera** con
`make openapi` a partir de comentarios inline:

```go
// openapi:operation
// summary: Create a folder
// tags: [folders]
// requestBody: { schema: FolderRequest }
// responses:
//   '201': { description: Created, schema: Folder }
//   '409': Error

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request, p principal) error {
```

- El bloque va separado del handler por una línea en blanco; si no, gofmt lo reformatea.
- Método, path, roles, parámetros de path, header CSRF y errores 400/401/403/404 salen del router: no se repiten.
- `// openapi:schema Nombre` define un esquema. Si está justo encima de un struct, el generador exige que liste
  exactamente sus campos `json`.
- `go test ./...` falla si la spec quedó desactualizada.

```sh
cd gateway
make generate   # sqlc: internal/store/queries -> internal/store/db
make openapi    # comentarios -> openapi/openapi.yaml
make test
```

## Administración (CLI de arranque rápido)

```sh
export PALTA_MASTER_KEY=$(palta-gw keygen) PALTAD_TOKEN=...
palta-gw user   -name admin -password '...' -role superadmin
palta-gw secret -name web-root -user root -key-file ~/.ssh/id_ed25519
palta-gw conn   -name web1 -host 10.0.0.5 -secret web-root [-record-input]
palta-gw grant  -user ana -conn web1 -ttl 2h       # acceso just-in-time
palta-gw site   -name sucursal1                    # imprime el token del agente
palta-gw conn   -name pos1 -host 192.168.1.20 -secret web-root -site sucursal1
PALTA_AGENT_TOKEN=pat_... palta-agent -server wss://bastion:18443/agent/connect -allow 192.168.1.0/24:22
```

Lo mismo, y todo lo demás (grupos, carpetas, policies por grupo, carpeta o tag, auditoría), está en la API.
