/**
 * End-to-end: a real `node proxy.ts` child process, two real origin servers,
 * and requests that arrive the way a browser's would.
 */

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { freePort, request, startProxy, upgrade } from "../helpers/harness.ts";
import { startOrigin } from "../helpers/origins.ts";
import type { ProxyHandle } from "../helpers/harness.ts";
import type { Origin } from "../helpers/origins.ts";

let upstream: Origin;
let local: Origin;
let proxy: ProxyHandle;
let port: number;
let strictPort: number;

before(async () => {
  upstream = await startOrigin();
  local = await startOrigin({ withUpgrade: true });
  port = await freePort();
  strictPort = await freePort();
  const deadPort = await freePort();

  const viaSystem = (url: string): Record<string, unknown> => ({ url, resolve: "system" });

  proxy = await startProxy(
    {
      connectTimeoutMs: 4000,
      sites: [
        {
          name: "main",
          host: "test.local",
          aliases: ["alias.test.local"],
          listen: { https: false, http: port },
          upstream: { ...viaSystem(upstream.url), preserveHost: true },
          rules: [
            { path: "/api", target: "upstream", headers: { "x-injected": "rule" } },
            { path: "/strip", target: viaSystem(upstream.url), stripPath: true },
            { path: "/base", target: viaSystem(`${upstream.url}/mounted`), stripPath: true },
            { regex: "^/re/[0-9]+$", target: viaSystem(upstream.url) },
            { path: "/onlypost", methods: ["POST"], target: viaSystem(upstream.url) },
            {
              path: "/rw",
              target: viaSystem(upstream.url),
              rewrite: { from: "^/rw/old", to: "/new" },
            },
            { path: "/dead", target: viaSystem(`http://127.0.0.1:${deadPort}`) },
            { path: "/", target: local.url },
          ],
        },
        {
          name: "strict",
          host: "strict.local",
          listen: { https: false, http: strictPort },
          rules: [{ path: "/api", target: viaSystem(upstream.url) }],
        },
      ],
    },
    { readyPort: port },
  );
});

after(async () => {
  await proxy?.stop();
  await upstream?.close();
  await local?.close();
});

describe("routing", () => {
  it("sends a matching prefix to the upstream, path intact", async () => {
    const res = await request({ port, path: "/api/users?x=1" });
    assert.equal(res.status, 200);
    assert.equal(upstream.last().url, "/api/users?x=1");
  });

  it("sends everything else to the local dev server", async () => {
    const res = await request({ port, path: "/some/page" });
    assert.equal(res.status, 200);
    assert.equal(local.last().url, "/some/page");
  });

  it("drops the matched prefix when stripPath is set", async () => {
    await request({ port, path: "/strip/deep/x" });
    assert.equal(upstream.last().url, "/deep/x");
  });

  it("prepends the target's base path", async () => {
    await request({ port, path: "/base/thing" });
    assert.equal(upstream.last().url, "/mounted/thing");
  });

  it("routes on a regex", async () => {
    await request({ port, path: "/re/42" });
    assert.equal(upstream.last().url, "/re/42");
  });

  it("falls through when the regex does not match", async () => {
    await request({ port, path: "/re/abc" });
    assert.equal(local.last().url, "/re/abc");
  });

  it("applies a path rewrite", async () => {
    await request({ port, path: "/rw/old/tail" });
    assert.equal(upstream.last().url, "/new/tail");
  });

  it("honours a method restriction in both directions", async () => {
    await request({ port, path: "/onlypost", method: "POST" });
    assert.equal(upstream.last().url, "/onlypost");
    await request({ port, path: "/onlypost", method: "GET" });
    assert.equal(local.last().url, "/onlypost", "GET should fall through to the catch-all");
  });

  it("answers 404 when no rule matches, listing the rules", async () => {
    const res = await request({ port: strictPort, host: "strict.local", path: "/nothing" });
    assert.equal(res.status, 404);
    assert.match(res.body, /no rule in site "strict"/);
  });

  it("answers 502 when the target refuses the connection", async () => {
    const res = await request({ port, path: "/dead" });
    assert.equal(res.status, 502);
    assert.match(res.body, /cannot reach/);
    assert.match(res.body, /Is the local dev server running\?/);
  });
});

describe("site selection", () => {
  it("accepts an alias as the same site", async () => {
    await request({ port, host: "alias.test.local", path: "/api/x" });
    assert.equal(upstream.last().url, "/api/x");
  });

  it("answers 421 for a host no site claims", async () => {
    const res = await request({ port: strictPort, host: "unknown.example", path: "/api" });
    assert.equal(res.status, 421);
    assert.match(res.body, /no site configured/);
  });
});

describe("request headers", () => {
  it("keeps the browser's Host for the upstream", async () => {
    await request({ port, path: "/api/h" });
    assert.equal(upstream.last().headers.host, `test.local:${port}`);
  });

  it("rewrites Host, Origin and Referer for the local dev server", async () => {
    await request({
      port,
      path: "/page",
      headers: {
        origin: `http://test.local:${port}`,
        referer: `http://test.local:${port}/from/here`,
      },
    });
    const seen = local.last().headers;
    assert.equal(seen.host, `127.0.0.1:${local.port}`);
    assert.equal(seen.origin, local.url);
    assert.equal(seen.referer, `${local.url}/from/here`);
  });

  it("adds the forwarding headers", async () => {
    await request({ port, path: "/api/h" });
    const seen = upstream.last().headers;
    assert.equal(seen["x-forwarded-host"], `test.local:${port}`);
    assert.equal(seen["x-forwarded-proto"], "http");
    assert.equal(seen["x-forwarded-port"], String(port));
    assert.equal(seen["x-real-ip"], "127.0.0.1");
  });

  it("appends to an existing X-Forwarded-For", async () => {
    await request({ port, path: "/api/h", headers: { "x-forwarded-for": "9.9.9.9" } });
    assert.match(String(upstream.last().headers["x-forwarded-for"]), /^9\.9\.9\.9, 127\.0\.0\.1$/);
  });

  it("injects a rule's configured headers", async () => {
    await request({ port, path: "/api/h" });
    assert.equal(upstream.last().headers["x-injected"], "rule");
  });

  it("does not forward hop-by-hop headers", async () => {
    await request({ port, path: "/api/h", headers: { te: "trailers" } });
    assert.equal(upstream.last().headers.te, undefined);
  });

  it("pipes the request body through", async () => {
    const res = await request({
      port,
      path: "/api/echobody",
      method: "POST",
      body: "hello-body",
      headers: { "content-type": "text/plain" },
    });
    assert.equal(res.body, "got:hello-body");
  });
});

describe("response rewriting", () => {
  it("rewrites Location back to the public origin", async () => {
    const res = await request({ port, path: "/api/redirect" });
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, `http://test.local:${port}/next?q=1#frag`);
  });

  it("keeps every cookie while fixing the Domain attribute", async () => {
    const res = await request({ port, path: "/api/cookie" });
    const cookies = res.headers["set-cookie"] ?? [];
    assert.equal(cookies.length, 3);
    const all = cookies.join(" | ");
    assert.doesNotMatch(all, /rejected\.example/, "a Domain this origin rejects must be dropped");
    assert.match(all, /Domain=\.test\.local/, "an acceptable Domain must survive");
    assert.doesNotMatch(all, /Secure/, "no Secure on a plain-http site");
  });

  it("strips HSTS but keeps other headers, and fixes CORS", async () => {
    const res = await request({ port, path: "/api/hsts" });
    assert.equal("strict-transport-security" in res.headers, false);
    assert.equal(res.headers["x-keep-me"], "yes");
    assert.equal(res.headers["access-control-allow-origin"], `http://test.local:${port}`);
  });

  it("passes a chunked response through whole", async () => {
    const res = await request({ port, path: "/api/stream" });
    assert.equal(res.body, "chunk1chunk2");
  });
});

describe("websocket upgrade", () => {
  it("completes the handshake and splices bytes both ways", async () => {
    const hs = await upgrade({ port, path: "/socket", payload: "ping" });
    assert.match(hs.statusLine, /^HTTP\/1\.1 101/);
    assert.match(hs.raw, /upgrade: websocket/i);
    assert.equal(hs.echoed, true, "the payload should come back through the splice");
  });

  it("routes the upgrade through the same rules, rewriting Host", async () => {
    await upgrade({ port, path: "/socket", payload: "x" });
    assert.equal(local.last().headers.host, `127.0.0.1:${local.port}`);
    assert.equal(local.last().url, "/socket");
  });
});
