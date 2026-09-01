import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  forwardHeaders,
  responseHeaders,
  rewriteCookies,
  rewriteLocation,
  swapOrigin,
} from "../../src/rewrite.ts";
import { ruleAt, siteWith } from "../helpers/fixtures.ts";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import type { Site } from "../../src/types.ts";

/** Only the parts of a request the rewriting actually reads. */
const req = (headers: IncomingHttpHeaders, method = "GET"): IncomingMessage =>
  ({ method, headers, url: "/", socket: { remoteAddress: "1.2.3.4" } }) as IncomingMessage;

/** A site on https://test.local whose one rule keeps the browser's Host. */
const upstreamSite = (extra: Record<string, unknown> = {}): Site =>
  siteWith(
    [{ path: "/", target: { url: "http://127.0.0.1:9001", preserveHost: true, resolve: "system" } }],
    extra,
  );

/** A site whose one rule addresses a local dev server in its own terms. */
const localSite = (extra: Record<string, unknown> = {}): Site =>
  siteWith([{ path: "/", target: "http://localhost:5173" }], extra);

describe("forwardHeaders — Host", () => {
  it("keeps the browser's Host when preserveHost is on", () => {
    const site = upstreamSite();
    const h = forwardHeaders(req({ host: "test.local" }), site, ruleAt(site, 0), true, "1.2.3.4");
    assert.equal(h.host, "test.local");
  });

  it("replaces Host with the target's own when preserveHost is off", () => {
    const site = localSite();
    const h = forwardHeaders(req({ host: "test.local" }), site, ruleAt(site, 0), true, "1.2.3.4");
    assert.equal(h.host, "localhost:5173");
  });

  it("defaults preserveHost from whether the target is local", () => {
    assert.equal(localSite().rules[0]?.target.preserveHost, false);
    assert.equal(upstreamSite().rules[0]?.target.preserveHost, true);
  });
});

describe("forwardHeaders — Origin and Referer", () => {
  it("rewrites both to the target when Host is replaced", () => {
    const site = localSite();
    const h = forwardHeaders(
      req({
        host: "test.local",
        origin: "https://test.local",
        referer: "https://test.local/deep/page?q=1",
      }),
      site,
      ruleAt(site, 0),
      true,
      "1.2.3.4",
    );
    assert.equal(h.origin, "http://localhost:5173");
    assert.equal(h.referer, "http://localhost:5173/deep/page?q=1");
  });

  it("leaves both alone when the browser's Host is preserved", () => {
    const site = upstreamSite();
    const h = forwardHeaders(
      req({ host: "test.local", origin: "https://test.local", referer: "https://test.local/p" }),
      site,
      ruleAt(site, 0),
      true,
      "1.2.3.4",
    );
    assert.equal(h.origin, "https://test.local");
    assert.equal(h.referer, "https://test.local/p");
  });

  it("leaves a foreign Origin alone even when rewriting", () => {
    const site = localSite();
    const h = forwardHeaders(
      req({ host: "test.local", origin: "https://elsewhere.example" }),
      site,
      ruleAt(site, 0),
      true,
      "1.2.3.4",
    );
    assert.equal(h.origin, "https://elsewhere.example");
  });
});

describe("forwardHeaders — forwarding and hop-by-hop", () => {
  it("adds the X-Forwarded set and X-Real-IP", () => {
    const site = upstreamSite();
    const h = forwardHeaders(req({ host: "test.local" }), site, ruleAt(site, 0), true, "1.2.3.4");
    assert.equal(h["x-forwarded-for"], "1.2.3.4");
    assert.equal(h["x-forwarded-host"], "test.local");
    assert.equal(h["x-forwarded-proto"], "https");
    assert.equal(h["x-forwarded-port"], "443");
    assert.equal(h["x-real-ip"], "1.2.3.4");
  });

  it("appends to an existing X-Forwarded-For chain", () => {
    const site = upstreamSite();
    const h = forwardHeaders(
      req({ host: "test.local", "x-forwarded-for": "9.9.9.9" }),
      site,
      ruleAt(site, 0),
      true,
      "1.2.3.4",
    );
    assert.equal(h["x-forwarded-for"], "9.9.9.9, 1.2.3.4");
  });

  it("reports http when the request did not arrive over TLS", () => {
    const site = upstreamSite({ listen: { https: false, http: 8080 } });
    const h = forwardHeaders(req({ host: "test.local" }), site, ruleAt(site, 0), false, "1.2.3.4");
    assert.equal(h["x-forwarded-proto"], "http");
    assert.equal(h["x-forwarded-port"], "8080");
  });

  it("drops every hop-by-hop header it was given", () => {
    const site = upstreamSite();
    const h = forwardHeaders(
      req({
        host: "test.local",
        connection: "keep-alive",
        te: "trailers",
        trailer: "X-Thing",
        upgrade: "h2c",
        "keep-alive": "timeout=5",
        "transfer-encoding": "chunked",
        "proxy-authorization": "Basic x",
      }),
      site,
      ruleAt(site, 0),
      true,
      "1.2.3.4",
    );
    for (const k of [
      "connection",
      "te",
      "trailer",
      "upgrade",
      "keep-alive",
      "transfer-encoding",
      "proxy-authorization",
    ]) {
      assert.equal(h[k], undefined, `${k} should not be forwarded`);
    }
  });
});

describe("forwardHeaders — configured overrides", () => {
  it("lets a rule header beat a target header", () => {
    const site = siteWith([
      {
        path: "/",
        headers: { "x-who": "rule" },
        target: { url: "http://127.0.0.1:9001", resolve: "system", headers: { "x-who": "target" } },
      },
    ]);
    const h = forwardHeaders(req({ host: "test.local" }), site, ruleAt(site, 0), true, "1.2.3.4");
    assert.equal(h["x-who"], "rule");
  });

  it("removes a header set to null", () => {
    const site = siteWith([
      { path: "/", headers: { "user-agent": null }, target: "http://localhost:5173" },
    ]);
    const h = forwardHeaders(
      req({ host: "test.local", "user-agent": "curl" }),
      site,
      ruleAt(site, 0),
      true,
      "1.2.3.4",
    );
    assert.equal("user-agent" in h, false);
  });

  it("matches header names case-insensitively", () => {
    const site = siteWith([
      { path: "/", headers: { "X-Mixed-Case": "yes" }, target: "http://localhost:5173" },
    ]);
    const h = forwardHeaders(req({ host: "test.local" }), site, ruleAt(site, 0), true, "1.2.3.4");
    assert.equal(h["x-mixed-case"], "yes");
  });
});

describe("swapOrigin", () => {
  it("swaps only a leading match", () => {
    assert.equal(swapOrigin("http://a/x", "http://a", "http://b"), "http://b/x");
    assert.equal(swapOrigin("http://c/x", "http://a", "http://b"), "http://c/x");
  });
});

describe("rewriteLocation", () => {
  const site = upstreamSite();
  const target = ruleAt(site, 0).target;

  it("points a redirect at the target back to the public origin", () => {
    assert.equal(
      rewriteLocation("http://127.0.0.1:9001/next?q=1#frag", site, target),
      "https://test.local/next?q=1#frag",
    );
  });

  it("normalizes our own hostname on another scheme", () => {
    assert.equal(rewriteLocation("http://test.local/next", site, target), "https://test.local/next");
  });

  it("leaves a relative Location alone", () => {
    assert.equal(rewriteLocation("/already/relative", site, target), "/already/relative");
  });

  it("leaves an unrelated host alone", () => {
    assert.equal(
      rewriteLocation("https://idp.example.com/authorize", site, target),
      "https://idp.example.com/authorize",
    );
  });

  it("removes the target's base path", () => {
    const mounted = siteWith([
      { path: "/", target: { url: "http://127.0.0.1:9001/mounted", resolve: "system" } },
    ]);
    assert.equal(
      rewriteLocation("http://127.0.0.1:9001/mounted/deep", mounted, ruleAt(mounted, 0).target),
      "https://test.local/deep",
    );
  });
});

describe("rewriteCookies", () => {
  const cookies = (site: Site, values: string[]): string => rewriteCookies(values, site).join(" | ");

  it("keeps a Domain the browser would accept on this origin", () => {
    assert.match(cookies(upstreamSite(), ["a=1; Domain=.test.local"]), /Domain=\.test\.local/);
  });

  it("drops a Domain the browser would reject", () => {
    const out = cookies(upstreamSite(), ["a=1; Domain=rejected.example"]);
    assert.doesNotMatch(out, /Domain=/);
    assert.match(out, /a=1/, "the cookie itself must survive");
  });

  it("adds Secure on an https site", () => {
    assert.match(cookies(upstreamSite(), ["a=1; Path=/"]), /; Secure/);
  });

  it("does not double an existing Secure", () => {
    const out = cookies(upstreamSite(), ["a=1; Secure"]);
    assert.equal(out.match(/Secure/g)?.length, 1);
  });

  it("adds no Secure on a plain-http site", () => {
    const http = upstreamSite({ listen: { https: false, http: 8080 } });
    assert.doesNotMatch(cookies(http, ["a=1; Path=/"]), /Secure/);
  });

  it("leaves Set-Cookie untouched when cookieDomain is false", () => {
    const site = upstreamSite({ cookieDomain: false });
    assert.match(cookies(site, ["a=1; Domain=rejected.example"]), /Domain=rejected\.example/);
  });

  it("forces an explicit cookieDomain", () => {
    const site = upstreamSite({ cookieDomain: "forced.test.local" });
    assert.match(cookies(site, ["a=1; Domain=whatever.example"]), /Domain=forced\.test\.local/);
  });

  it("rewrites every cookie in the list", () => {
    const out = rewriteCookies(["a=1", "b=2", "c=3"], upstreamSite());
    assert.equal(out.length, 3);
    assert.ok(out.every((v) => v.includes("Secure")));
  });
});

describe("responseHeaders", () => {
  const site = upstreamSite();
  const target = ruleAt(site, 0).target;
  const run = (h: IncomingHttpHeaders): ReturnType<typeof responseHeaders> =>
    responseHeaders(h, site, target);

  it("strips Strict-Transport-Security by default", () => {
    const out = run({ "strict-transport-security": "max-age=1", "x-keep": "yes" });
    assert.equal("strict-transport-security" in out, false);
    assert.equal(out["x-keep"], "yes");
  });

  it("honours a custom stripResponseHeaders list", () => {
    const custom = upstreamSite({ stripResponseHeaders: ["X-Secret"] });
    const out = responseHeaders(
      { "x-secret": "no", "strict-transport-security": "max-age=1" },
      custom,
      ruleAt(custom, 0).target,
    );
    assert.equal("x-secret" in out, false);
    assert.equal(
      out["strict-transport-security"],
      "max-age=1",
      "an explicit list replaces the default",
    );
  });

  it("drops hop-by-hop response headers", () => {
    const out = run({ connection: "close", "transfer-encoding": "chunked", "content-type": "text/html" });
    assert.equal("connection" in out, false);
    assert.equal("transfer-encoding" in out, false);
    assert.equal(out["content-type"], "text/html");
  });

  it("rewrites Location", () => {
    const out = run({ location: "http://127.0.0.1:9001/x" });
    assert.equal(out.location, "https://test.local/x");
  });

  it("rewrites Access-Control-Allow-Origin to the public origin", () => {
    const out = run({ "access-control-allow-origin": "http://127.0.0.1:9001" });
    assert.equal(out["access-control-allow-origin"], "https://test.local");
  });

  it("leaves a wildcard Access-Control-Allow-Origin alone", () => {
    assert.equal(run({ "access-control-allow-origin": "*" })["access-control-allow-origin"], "*");
  });

  it("handles Set-Cookie as an array", () => {
    const out = run({ "set-cookie": ["a=1", "b=2"] });
    assert.equal((out["set-cookie"] as string[]).length, 2);
  });
});
