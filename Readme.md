## prefix-proxy-go

A small Go reverse proxy that routes requests based on a specially formatted hostname. The hostname encodes the upstream scheme, IP address, and port. Example:

- Host: `http-10-0-0-123-3000.example.com` → Proxies to `http://10.0.0.123:3000`
- Host: `https-10-0-0-123-9443.example.com` → Proxies to `https://10.0.0.123:9443`

It also exposes an optional Ask endpoint for Caddy’s on-demand TLS to validate which domains are allowed.

### Features

- Scheme/IP/port parsing from the request Host
- Supports both HTTP and HTTPS upstreams (with optional TLS verification skip)
- Preserves and sets standard forward headers (`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`)
- WebSocket upgrade support (preserves Upgrade/Connection when needed)
- Health check endpoint at `/healthz`
- Minimal logging and robust error handling
- Optional Ask endpoint for Caddy on-demand TLS validation

## How it works

Incoming requests must target a host that matches:

```
^(http|https|htttps)-((?:[0-9]{1,3}-){3}[0-9]{1,3})-([0-9]{1,5})(?:\..+)?$
```

- Group 1: scheme (`http`, `https`, or the typo `htttps` which is normalized to `https`)
- Group 2: IPv4 in dashed form (e.g., `10-0-0-123` → `10.0.0.123`)
- Group 3: port (e.g., `3000`)

The proxy rewrites the request URL to the derived upstream and forwards the request, setting standard forward headers and removing hop-by-hop headers per RFC 7230, while keeping upgrade headers for WebSocket connections.

## Requirements

- Go 1.22+

## Build

```bash
go build -v -o prefix-proxy
```

Or run directly:

```bash
go run .
```

## Run

By default, the proxy listens on `:5670` and the Ask endpoint on `:5671`.

```bash
./prefix-proxy
```

Health check:

```bash
curl -sS http://127.0.0.1:5670/healthz
```

Quick local test against an upstream at `10.0.0.123:3000`:

```bash
curl -H "Host: http-10-0-0-123-3000.example.test" http://127.0.0.1:5670/
```

Note: The actual base domain is ignored by the proxy; only the prefix is used for routing.

## Environment variables

- `LISTEN_ADDR` (default `:5670`): Address for the main proxy server
- `ASK_LISTEN_ADDR` (default `:5671`): Address for the Ask endpoint server
- `READ_TIMEOUT` (default `15s`): Read timeout for servers (Go duration)
- `WRITE_TIMEOUT` (default `30s`): Write timeout for servers (Go duration)
- `IDLE_TIMEOUT` (default `60s`): Idle timeout for servers (Go duration)
- `UPSTREAM_TLS_INSECURE_SKIP_VERIFY` (default `true`): When `true`, skip TLS verification for HTTPS upstreams

Example:

```bash
LISTEN_ADDR=0.0.0.0:5670 \
ASK_LISTEN_ADDR=127.0.0.1:5671 \
READ_TIMEOUT=10s \
WRITE_TIMEOUT=20s \
IDLE_TIMEOUT=45s \
UPSTREAM_TLS_INSECURE_SKIP_VERIFY=false \
./prefix-proxy
```

## Caddy integration

The proxy is typically run behind Caddy, which terminates TLS and optionally performs authentication (e.g., via `oauth2-proxy`). Below is an example that:

- Uses `forward_auth` to protect endpoints with `oauth2-proxy` on `localhost:4180`
- Proxies all other traffic to this reverse proxy on `127.0.0.1:5670`
- Preserves `Host` and `X-Forwarded-Proto` so the backend can parse the scheme/IP/port

```caddy
*.example.com {
  handle /oauth2/* {
    reverse_proxy localhost:4180
  }

  handle {
    forward_auth localhost:4180 {
      uri /oauth2/auth
      copy_headers X-Auth-Request-Access-Token

      @bad status 4xx
      handle_response @bad {
        redir https://{host}/oauth2/start
      }
    }

    reverse_proxy http://127.0.0.1:5670 {
      header_up Host {host}
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-Proto {scheme}
    }
  }

  # Optional: on-demand TLS with Ask callback to restrict issuance
  tls {
    on_demand {
      ask http://127.0.0.1:5671/ask
    }
  }
}
```

Notes:

- The Ask endpoint returns 200 OK only for hosts that match the required prefix format. This helps ensure on-demand certificates are only issued for acceptable domains.
- Ensure `header_up Host {host}` is set so the backend can parse the incoming host prefix for routing.

## Systemd example

```ini
[Unit]
Description=prefix-proxy-go
After=network.target

[Service]
Type=simple
Environment=LISTEN_ADDR=:5670
Environment=ASK_LISTEN_ADDR=:5671
Environment=UPSTREAM_TLS_INSECURE_SKIP_VERIFY=true
WorkingDirectory=/opt/prefix-proxy-go
ExecStart=/opt/prefix-proxy-go/prefix-proxy
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

- 400 Bad Request: The `Host` does not match the required pattern. Ensure the format is `http-<ip-dashed>-<port>` or `https-<ip-dashed>-<port>`.
- 502 Bad Gateway: Upstream unreachable or TLS error. Verify the upstream IP/port is correct and reachable. For HTTPS upstreams, consider `UPSTREAM_TLS_INSECURE_SKIP_VERIFY=false` only when using valid certificates.
- WebSockets: Ensure clients and any upstream proxies include proper `Upgrade` and `Connection` headers; this proxy preserves them when upgrading.

## License

MIT


