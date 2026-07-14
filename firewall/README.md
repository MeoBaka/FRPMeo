# frp-firewall

A standalone access-control service for **frps**. frps calls it on every new
user connection through the `NewUserConn` HTTP plugin hook; the service checks
IP/CIDR + proxy + user rules and tells frps to **allow** or **reject** the
connection - before it ever reaches the tunneled service (RDP, etc.).

One instance can serve **many frps**: each frps points its `[[httpPlugins]]` at
a distinct path `/plugin/<id>`, and rules are stored per id under the data dir.
Rules named `global` apply to every frps.

## Build & run

```bash
cd firewall
go build -o frp-firewall.exe .
FW_LISTEN=127.0.0.1:9011 FW_DATA=./data FW_API_TOKEN=change-me ./frp-firewall.exe
```

| Env | Default | Meaning |
|---|---|---|
| `FW_LISTEN` | `:9001` | listen address |
| `FW_DATA` | `./data` | folder where rule files are saved (`<id>.json`) |
| `FW_API_TOKEN` | *(empty)* | if set, `/api/*` requires `Authorization: Bearer <token>` |
| `FW_ALLOW_IPS` | *(empty)* | comma-separated IP/CIDR of frps hosts allowed to call `/plugin` (no secret on the URL) |
| `FW_PLUGIN_TOKEN` | *(empty)* | optional shared secret in the path `/plugin/<token>/<id>` - use only over https |
| `FW_CORS_ORIGIN` | `*` | CORS origin for the web UI |

## Wire it into frps (multiple servers share one service)

```toml
# frps "tokyo"                         # frps "us" (another machine)
[[httpPlugins]]                        [[httpPlugins]]
name = "firewall"                      name = "firewall"
addr = "http://fw-host:9011"           addr = "http://fw-host:9011"
path = "/plugin/tokyo"                 path = "/plugin/us"
ops  = ["NewUserConn"]                 ops  = ["NewUserConn"]
```

## Rule model

Rules are evaluated **global first, then the server's**, top to bottom;
first match wins, otherwise the `default` policy applies (server default, else
global default, else `allow`).

```json
{
  "default": "deny",
  "rules": [
    { "id": "office", "action": "allow", "cidr": "1.2.3.0/24", "proxy": "rdp-*", "note": "office" },
    { "id": "admin",  "action": "allow", "user": "admin" },
    { "id": "badasn", "action": "deny",  "cidr": "45.0.0.0/8" }
  ]
}
```

- `cidr`: `1.2.3.0/24`, a single IP `1.2.3.4`, or `""`/`*` = any
- `proxy` / `user`: glob with `*` (e.g. `rdp-*`), or `""`/`*` = any
- `action`: `allow` | `deny`

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/servers` | list server ids + rule counts |
| GET | `/api/rules/{id}` | get a server's ruleset |
| PUT | `/api/rules/{id}` | replace a server's ruleset (create/edit) |
| POST | `/api/decide/{id}` | dry-run: body `{ip,proxy,user}` -> `{allow,reason}` |
| POST | `/plugin/{id}` | frp plugin endpoint (called by frps, not by you) |

## Locking down a shared service so outsiders can't fetch in

frp's httpPlugin can only vary `addr` / `path` / `tlsVerify` - it cannot send an
auth header, a signature, or a client cert, so there is no way to do frpc-style
token auth on the plugin call. Two practical options:

**Recommended - verify the caller by source IP (no secret on the URL):**
```bash
FW_ALLOW_IPS=10.0.0.5,10.0.0.6 ./frp-firewall.exe   # the frps hosts
```
```toml
[[httpPlugins]]
name = "firewall"
addr = "http://fw-host:9011"
path = "/plugin/tokyo"       # just the server id, nothing secret
ops  = ["NewUserConn"]
```
Any plugin call from an IP not in `FW_ALLOW_IPS` is rejected. TCP source spoofing
is impractical, so this is a solid gate for an internal service.

**Optional - shared secret in the path (only over https):**
```bash
FW_PLUGIN_TOKEN=<secret> ./frp-firewall.exe
```
```toml
path = "/plugin/<secret>/tokyo"   # token in the path
addr = "https://fw-host:9011"     # https so the path is NOT exposed on the wire
```
Only use this over https - on plain http the token is visible in the URL (logs,
sniffers). Prefer the source-IP method.

## Security

- Gate `/plugin` with `FW_ALLOW_IPS` (and/or a private network) - not a URL token.
- Protect `/api/*` + the web UI with `FW_API_TOKEN` and HTTPS - this is the
  control plane; whoever reaches it controls the firewall.
