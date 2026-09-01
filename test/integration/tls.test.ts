/**
 * The HTTPS listener: SNI certificate selection, the https-only rewrites, and
 * what plain HTTP does alongside it.
 *
 * Needs mkcert and its local CA to sign test certificates, so the whole suite
 * skips where those are absent. The handshakes here do not require the CA to be
 * trusted by the OS — the assertions are about which certificate is served.
 */

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { freePort, peerCertNames, request, startProxy, tlsRequest } from "../helpers/harness.ts";
import { startOrigin } from "../helpers/origins.ts";
import type { ProxyHandle } from "../helpers/harness.ts";
import type { Origin } from "../helpers/origins.ts";

/** mkcert present, with a CA it can sign with. */
function mkcertReady(): boolean {
  if (spawnSync("mkcert", ["-version"], { encoding: "utf8" }).error) return false;
  const root = spawnSync("mkcert", ["-CAROOT"], { encoding: "utf8" }).stdout?.trim();
  return !!root && fs.existsSync(path.join(root, "rootCA.pem"));
}

const HOST_A = "a.tlstest.localhost";
const HOST_B = "b.tlstest.localhost";

const ready = mkcertReady();
const skip = ready ? false : "needs mkcert with an installed local CA";

describe("https", { skip }, () => {
  let upstream: Origin;
  let proxy: ProxyHandle;
  let certDir: string;
  let httpsPort: number;
  let httpPort: number;

  before(async () => {
    certDir = fs.mkdtempSync(path.join(os.tmpdir(), "devproxy-certs-"));
    // A separate certificate per host, so a served CN proves which one SNI chose.
    for (const host of [HOST_A, HOST_B]) {
      const r = spawnSync(
        "mkcert",
        ["-cert-file", path.join(certDir, `${host}.pem`), "-key-file", path.join(certDir, `${host}-key.pem`), host],
        { encoding: "utf8" },
      );
      if (r.status !== 0) throw new Error(`mkcert failed for ${host}: ${r.stderr}`);
    }

    upstream = await startOrigin();
    httpsPort = await freePort();
    httpPort = await freePort();

    const target = { url: upstream.url, resolve: "system", preserveHost: true };
    proxy = await startProxy(
      {
        certDir,
        sites: [
          {
            name: "a",
            host: HOST_A,
            // Both sites share one https port: SNI is what tells them apart.
            listen: { https: httpsPort, http: httpPort },
            rules: [{ path: "/", target }],
          },
          {
            name: "b",
            host: HOST_B,
            listen: { https: httpsPort, http: false },
            rules: [{ path: "/", target }],
          },
        ],
      },
      { readyPort: httpsPort },
    );
  });

  after(async () => {
    await proxy?.stop();
    await upstream?.close();
    if (certDir) fs.rmSync(certDir, { recursive: true, force: true });
  });

  it("serves the certificate matching the requested SNI name", async () => {
    assert.deepEqual(await peerCertNames(httpsPort, HOST_A), [HOST_A]);
    assert.deepEqual(
      await peerCertNames(httpsPort, HOST_B),
      [HOST_B],
      "one port, two hostnames, two certificates",
    );
  });

  it("serves both hostnames over that one port", async () => {
    assert.equal((await tlsRequest({ port: httpsPort, servername: HOST_A, path: "/x" })).status, 200);
    assert.equal((await tlsRequest({ port: httpsPort, servername: HOST_B, path: "/x" })).status, 200);
  });

  it("routes to the site the SNI name belongs to", async () => {
    await tlsRequest({ port: httpsPort, servername: HOST_B, path: "/from-b" });
    assert.equal(upstream.last().url, "/from-b");
    assert.equal(upstream.last().headers.host, `${HOST_B}:${httpsPort}`);
  });

  it("reports https in the forwarding headers", async () => {
    await tlsRequest({ port: httpsPort, servername: HOST_A, path: "/h" });
    const seen = upstream.last().headers;
    assert.equal(seen["x-forwarded-proto"], "https");
    assert.equal(seen["x-forwarded-port"], String(httpsPort));
  });

  it("adds Secure to every cookie", async () => {
    const res = await tlsRequest({ port: httpsPort, servername: HOST_A, path: "/cookie" });
    const cookies = res.headers["set-cookie"] ?? [];
    assert.equal(cookies.length, 3);
    assert.ok(
      cookies.every((c) => /;\s*Secure/i.test(c)),
      `every cookie should be Secure: ${cookies.join(" | ")}`,
    );
  });

  it("rewrites Location to the https public origin", async () => {
    const res = await tlsRequest({ port: httpsPort, servername: HOST_A, path: "/redirect" });
    assert.equal(res.headers.location, `https://${HOST_A}:${httpsPort}/next?q=1#frag`);
  });

  it("redirects plain http to the https origin, keeping path and query", async () => {
    const res = await request({ port: httpPort, host: HOST_A, path: "/deep/path?q=1" });
    assert.equal(res.status, 308);
    assert.equal(res.headers.location, `https://${HOST_A}:${httpsPort}/deep/path?q=1`);
  });
});
