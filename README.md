# devproxy

Serve a real hostname from your machine and split every request between your
local dev server and the real deployment.

```
browser ──► https://app.example.com
                     │  /etc/hosts → 127.0.0.1
                     ▼
                 devproxy :443
                     ├── /api ──────► real host, found via DNS
                     └── /    ──────► http://localhost:5173  (Vite)
```

The browser never leaves the real origin, so cookies, CORS and the OIDC redirect
URI keep working exactly as they do in production — while the frontend comes
from Vite, with HMR.

## The trick

`/etc/hosts` points the hostname at `127.0.0.1`, which would also trap the
proxy's own upstream calls in a loop. Node's `dns.resolve4()` queries the
configured nameservers directly and never reads `/etc/hosts`, so the proxy still
finds the real IP and connects to it with the original SNI and `Host` header.
Nothing is hardcoded, and a VPN's DNS still works — only the local override is
bypassed.

## Setup (once)

Needs **Node >= 22.18** and nothing else: the proxy is TypeScript that Node runs
directly by stripping the types, so there is no build step and no runtime
dependency to install.

```sh
brew install mkcert
mkcert -install                   # installs a local CA the browsers trust

cp devproxy.config.example.json devproxy.config.json   # then edit it
node ~/tools/devproxy/proxy.ts --certs
sudo node ~/tools/devproxy/proxy.ts --hosts-write
```

`devproxy.config.json` and `certs/` are gitignored — they hold your hostnames
and private keys, so they stay on your machine.

`--hosts-write` writes a marked block to `/etc/hosts` (backup:
`/etc/hosts.devproxy.bak`) and flushes the DNS cache. `--hosts-remove` takes it
back out — do that when you want the real site again.

## Daily use

```sh
cd ~/projects/my-app/frontend && pnpm dev          # terminal 1
node ~/tools/devproxy/proxy.ts                     # terminal 2
```

Then open <https://app.example.com>.

No `sudo`: macOS lets a normal user bind :80 and :443. Should yours refuse
(`EACCES`), run the proxy with `sudo` — it drops back to your user as soon as
the sockets are open. If something is off:

```sh
node ~/tools/devproxy/proxy.ts --doctor
```

which checks the hosts entries, certificate validity and coverage, port
availability, and that every target actually answers.

## Configuration

`devproxy.config.json` — JSON with comments allowed. One entry per hostname;
several hostnames share port 443 through SNI.

```jsonc
{
  "connectTimeoutMs": 15000,        // wait for the first byte; streams exempt after that
  "sites": [
    {
      "name": "my-app",
      "host": "app.example.com",
      "aliases": ["www.app.example.com"],
      "enabled": true,
      "listen": { "https": 443, "http": 80, "httpMode": "redirect" },
      "upstream": "https://app.example.com",
      "cookieDomain": "auto",
      "stripResponseHeaders": ["strict-transport-security"],
      "rules": [
        { "path": "/api", "target": "upstream" },
        { "path": "/",    "target": "http://localhost:5173" }
      ]
    }
  ]
}
```

### Rules

Ordered; **first match wins**, so specific paths go above the catch-all.

| key | meaning |
|---|---|
| `path` | prefix match on the path (`/api` matches `/api` and `/api/x`, not `/apix`) |
| `regex` | match the path with a regular expression instead |
| `methods` | `["GET","HEAD"]` — restrict the rule to these methods |
| `target` | `"upstream"`, a URL string, or a target object (below) |
| `stripPath` | drop the matched prefix before forwarding |
| `rewrite` | `{ "from": "^/old", "to": "/new" }` applied to the path |
| `headers` | extra request headers; `null` removes one |

### Targets

A string URL is enough. The object form adds:

| key | default | meaning |
|---|---|---|
| `url` | — | `http://` or `https://`, may include a base path |
| `resolve` | `dns` for real hosts, `system` for local ones | `dns` bypasses `/etc/hosts` |
| `ip` | — | pin an address and skip resolution entirely |
| `preserveHost` | `true` for real hosts, `false` for local | keep the browser's `Host` |
| `insecure` | `false` | accept an untrusted upstream certificate |
| `headers` | — | extra request headers for every rule using this target |

`preserveHost: false` also rewrites `Origin` and `Referer` to match, which is
what lets a local Vite accept the request: Vite refuses an unfamiliar `Host`
(`server.allowedHosts`) and validates the HMR WebSocket's `Origin`. Because the
proxy makes it look like a plain `localhost:5173` request, **no Vite config
change is needed** — HMR included.

### What the proxy rewrites

* **Request** — `Host` per `preserveHost`; `Origin`/`Referer` to match; adds
  `X-Forwarded-For/-Host/-Proto/-Port` and `X-Real-IP`; drops hop-by-hop headers.
* **Response** — `Location` back to the public origin; `Set-Cookie` gets `Secure`
  and loses a `Domain=` this origin would reject (a rejected `Domain` drops the
  whole cookie, which looks exactly like a broken login);
  `Access-Control-Allow-Origin` back to the public origin;
  `Strict-Transport-Security` removed, so the real hostname is not pinned to
  https long after you stop using the proxy.
* **Bodies are never touched**, so compression and streaming pass straight
  through.

## Authentication (OIDC)

If the deployed app signs in through an identity provider, the `redirect_uri`
registered there is the public origin — the exact origin this proxy serves, so
**nothing needs changing in the app registration**.

Your local dev server must use the same OIDC settings as the deployment, or the
real backend will reject its tokens. Put them in a local, gitignored env file
such as `frontend/.env.development.local` (`*.local` is gitignored, and it wins
over `.env.development`):

```sh
VITE_OIDC_ISSUER=https://idp.example.com/<tenant>/v2.0
VITE_OIDC_CLIENT_ID=<client-id>
VITE_OIDC_REDIRECT_URI=https://app.example.com/auth/callback
VITE_OIDC_SCOPE="openid email profile"
```

If you don't know the deployed values, they are in the shipped bundle:

```sh
curl -s https://app.example.com/ | grep -oE '/assets/[^"]+\.js' | head -1 |
  xargs -I{} curl -s "https://app.example.com{}" |
  grep -oE '"https://[^"]*"|"openid[^"]*"'
```

Delete the env file (and stop the proxy) to go back to your local auth stack.

`VITE_API_BASE` stays `/api`: same origin, and the proxy sends it to the real
backend.

## Troubleshooting

| symptom | cause |
|---|---|
| browser shows the real site, not yours | `/etc/hosts` block missing — `--doctor` |
| `502 cannot reach http://localhost:5173` | dev server not running |
| `502 cannot resolve <host>` | DNS cannot see the real host — VPN? |
| certificate warning | `mkcert -install` was never run, or the cert predates it |
| `port 443 needs root on this system` | run the proxy with `sudo` |
| `a loopback-only listener already answers here` | another process holds `127.0.0.1:<port>`; a wildcard bind does not collide with it but loses to it |
| 401s from the real API | local OIDC env differs from the deployment — see above |

## Adding another project

Append a site. Nothing else is per-project:

```jsonc
{
  "name": "admin",
  "host": "admin.example.com",
  "upstream": "https://admin.example.com",
  "rules": [
    { "path": "/api", "target": "upstream" },
    { "path": "/",    "target": "http://localhost:3000" }
  ]
}
```

Then `node proxy.ts --certs && sudo node proxy.ts --hosts-write`.

Run a single site with `--site admin`.

## Development

The types are checked by `tsc`, never used to build anything — Node strips them
at load time and ignores `tsconfig.json` entirely. So the checker is optional to
*run* the proxy and mandatory before trusting a change:

```sh
npm install        # typescript + @types/node, dev-only
npm run typecheck  # tsc, no emit
npm test           # node --test, no framework
npm run check      # both
```

Because Node does the stripping, every construct has to be erasable —
`erasableSyntaxOnly` enforces that, so `tsc` rejects an enum or a parameter
property rather than letting Node fail at runtime. Local imports carry their
real `.ts` extension for the same reason.

`proxy.ts` is the entry point: argument parsing and command dispatch. Everything
else lives in `src/`:

| file | what it owns |
|---|---|
| `types.ts` | the config schema (`Raw*`) and the normalized shapes |
| `constants.ts` | hop-by-hop header list, local-name and IP predicates, paths |
| `log.ts` | colour, verbosity, `die`, reading `code` off unknown errors |
| `config.ts` | JSON-with-comments parsing, defaults, validation |
| `resolve.ts` | the `/etc/hosts` bypass, the DNS cache, SNI naming |
| `match.ts` | rule matching and the outbound path |
| `rewrite.ts` | request and response header surgery |
| `proxy.ts` | the request path and the Upgrade path |
| `serve.ts` | binding ports, SNI cert selection, dropping root |
| `doctor.ts` | the `--doctor` checks |
| `certs.ts` | mkcert invocation |
| `hosts.ts` | the marked `/etc/hosts` block |

### Tests

`npm test` — 135 tests on the built-in runner, no test framework and no test
dependency. They fall into two kinds:

`test/unit/` imports the pure functions directly: rule matching and outbound
paths, every header and cookie rewrite, and the config layer's defaults. Its
fixtures are built by running the real `loadConfig` over a scratch file rather
than hand-assembling objects, so a fixture cannot drift from what the proxy
actually receives.

`test/integration/` starts real origin servers on ephemeral ports and drives a
real `node proxy.ts` child process, so argument parsing, config loading, port
binding, routing, streaming and the WebSocket splice are all covered end to end.
The origins record what they were sent, which is what the assertions read — a
test checks the header the proxy *forwarded*, not an echo the origin chose to
return. `test/integration/cli.test.ts` covers the refusals, which need a
subprocess because `die()` exits the process.

`test/integration/tls.test.ts` needs mkcert and its local CA to sign
certificates, and skips itself where those are missing. It puts two hostnames
with two different certificates on one port, so the SNI callback has to pick
the right one. Its assertions read the SAN, not the subject CN — current mkcert
leaves the CN empty.

