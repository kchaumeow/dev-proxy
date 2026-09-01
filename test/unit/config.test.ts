import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { stripJsonComments } from "../../src/config.ts";
import { load, oneRule, site, siteWith } from "../helpers/fixtures.ts";

describe("stripJsonComments", () => {
  it("removes line comments", () => {
    assert.equal(JSON.parse(stripJsonComments('{"a":1 // note\n}')).a, 1);
  });

  it("removes block comments, including across lines", () => {
    assert.equal(JSON.parse(stripJsonComments('{/* one\ntwo */"a":1}')).a, 1);
  });

  it("leaves // inside a string alone, so URLs survive", () => {
    const out = JSON.parse(stripJsonComments('{"url":"http://localhost:5173/x"}'));
    assert.equal(out.url, "http://localhost:5173/x");
  });

  it("respects escaped quotes when tracking strings", () => {
    const out = JSON.parse(stripJsonComments('{"a":"say \\"hi\\" // not a comment"}'));
    assert.equal(out.a, 'say "hi" // not a comment');
  });

  it("preserves newlines so error line numbers stay usable", () => {
    assert.equal(stripJsonComments("{\n// x\n}").split("\n").length, 3);
  });
});

describe("config defaults", () => {
  it("defaults the top-level connect timeout", () => {
    assert.equal(load({ sites: [{ host: "a.test", rules: [{ path: "/", target: "http://l:1" }] }] })
      .connectTimeoutMs, 15000);
  });

  it("keeps an explicit connect timeout", () => {
    const c = load({
      connectTimeoutMs: 2000,
      sites: [{ host: "a.test", rules: [{ path: "/", target: "http://l:1" }] }],
    });
    assert.equal(c.connectTimeoutMs, 2000);
  });

  it("defaults ports, http mode, cookie handling and HSTS stripping", () => {
    const s = siteWith([{ path: "/", target: "http://localhost:1" }]);
    assert.equal(s.httpsPort, 443);
    assert.equal(s.httpPort, 80);
    assert.equal(s.httpMode, "redirect");
    assert.equal(s.cookieDomain, "auto");
    assert.deepEqual(s.stripResponseHeaders, ["strict-transport-security"]);
    assert.equal(s.enabled, true);
  });

  it("names a site after its host when no name is given", () => {
    assert.equal(site({ sites: [{ host: "A.Test", rules: [{ path: "/", target: "http://l:1" }] }] })
      .name, "a.test");
  });

  it("lowercases host and aliases", () => {
    const s = site({
      sites: [
        { host: "A.Test", aliases: ["WWW.A.Test"], rules: [{ path: "/", target: "http://l:1" }] },
      ],
    });
    assert.deepEqual(s.allHosts, ["a.test", "www.a.test"]);
  });

  it("can be disabled", () => {
    assert.equal(siteWith([{ path: "/", target: "http://l:1" }], { enabled: false }).enabled, false);
  });
});

describe("publicOrigin", () => {
  const origin = (listen: unknown): string =>
    siteWith([{ path: "/", target: "http://l:1" }], { listen }).publicOrigin;

  it("omits the port when https is on 443", () => {
    assert.equal(origin({ https: 443 }), "https://test.local");
  });

  it("includes a non-default https port", () => {
    assert.equal(origin({ https: 8443 }), "https://test.local:8443");
  });

  it("falls back to http when https is disabled", () => {
    assert.equal(origin({ https: false, http: 80 }), "http://test.local");
    assert.equal(origin({ https: false, http: 8080 }), "http://test.local:8080");
  });

  it("treats listen:false as no listener at all", () => {
    const s = siteWith([{ path: "/", target: "http://l:1" }], { listen: { http: false } });
    assert.equal(s.httpPort, null);
  });
});

describe("host routing table", () => {
  it("maps every host and alias to its site", () => {
    const c = load({
      sites: [
        { name: "one", host: "one.test", aliases: ["alias.test"], rules: [{ path: "/", target: "http://l:1" }] },
        { name: "two", host: "two.test", rules: [{ path: "/", target: "http://l:2" }] },
      ],
    });
    assert.equal(c.byHost.get("one.test")?.name, "one");
    assert.equal(c.byHost.get("alias.test")?.name, "one");
    assert.equal(c.byHost.get("two.test")?.name, "two");
    assert.equal(c.byHost.get("nope.test"), undefined);
  });
});

describe("target parsing", () => {
  it("reads scheme, host and port from a URL string", () => {
    const t = oneRule({ path: "/", target: "https://api.example.com:8443/base/" }).target;
    assert.equal(t.secure, true);
    assert.equal(t.hostname, "api.example.com");
    assert.equal(t.port, 8443);
    assert.equal(t.basePath, "/base", "a trailing slash is not a base path");
  });

  it("defaults the port from the scheme", () => {
    assert.equal(oneRule({ path: "/", target: "https://a.example.com" }).target.port, 443);
    assert.equal(oneRule({ path: "/", target: "http://a.example.com" }).target.port, 80);
  });

  it("has no base path for a bare origin", () => {
    assert.equal(oneRule({ path: "/", target: "https://a.example.com/" }).target.basePath, "");
  });

  it("resolves real hosts through DNS to bypass /etc/hosts", () => {
    assert.equal(oneRule({ path: "/", target: "https://real.example.com" }).target.resolve, "dns");
  });

  it("uses the system resolver for local names and literal IPs", () => {
    assert.equal(oneRule({ path: "/", target: "http://localhost:5173" }).target.resolve, "system");
    assert.equal(oneRule({ path: "/", target: "http://127.0.0.1:5173" }).target.resolve, "system");
    assert.equal(oneRule({ path: "/", target: "http://app.localhost" }).target.resolve, "system");
  });

  it("lets an explicit resolve mode win", () => {
    const t = oneRule({ path: "/", target: { url: "http://localhost:1", resolve: "dns" } }).target;
    assert.equal(t.resolve, "dns");
  });

  it("pins an address when ip is given", () => {
    const t = oneRule({ path: "/", target: { url: "https://a.example.com", ip: "10.0.0.1" } }).target;
    assert.equal(t.ip, "10.0.0.1");
  });

  it("carries the insecure flag", () => {
    const t = oneRule({ path: "/", target: { url: "https://a.example.com", insecure: true } }).target;
    assert.equal(t.insecure, true);
  });

  it("keeps the written url as the label", () => {
    assert.equal(oneRule({ path: "/", target: "http://localhost:5173" }).target.label,
      "http://localhost:5173");
  });

  it("unbrackets an IPv6 host", () => {
    assert.equal(oneRule({ path: "/", target: "http://[::1]:5173" }).target.hostname, "::1");
  });
});

describe('the "upstream" shorthand', () => {
  it("points at the very same target object the site defined", () => {
    const s = siteWith([{ path: "/api", target: "upstream" }, { path: "/", target: "http://l:1" }], {
      upstream: "https://api.example.com",
    });
    assert.equal(s.rules[0]?.target, s.upstreamTarget, "identity is what the logger keys off");
    assert.equal(s.rules[0]?.target.hostname, "api.example.com");
  });

  it("is null when the site declares no upstream", () => {
    assert.equal(siteWith([{ path: "/", target: "http://l:1" }]).upstreamTarget, null);
  });
});

describe("rule parsing", () => {
  it("uppercases the method list", () => {
    assert.deepEqual(oneRule({ path: "/", methods: ["get", "Head"], target: "http://l:1" }).methods,
      ["GET", "HEAD"]);
  });

  it("compiles a regex and labels it distinctly", () => {
    const r = oneRule({ regex: "^/x/[0-9]+$", target: "http://l:1" });
    assert.ok(r.regex instanceof RegExp);
    assert.equal(r.label, "~^/x/[0-9]+$");
    assert.equal(r.path, null);
  });

  it("labels a path rule with the path", () => {
    assert.equal(oneRule({ path: "/api", target: "http://l:1" }).label, "/api");
  });

  it("defaults stripPath and rewrite to off", () => {
    const r = oneRule({ path: "/", target: "http://l:1" });
    assert.equal(r.stripPath, false);
    assert.equal(r.rewrite, null);
  });
});

describe("certificate paths", () => {
  it("derives cert and key names from the host inside certDir", () => {
    const s = siteWith([{ path: "/", target: "http://l:1" }], { certDir: "/tmp/devproxy-certs" });
    assert.equal(s.cert, path.join("/tmp/devproxy-certs", "test.local.pem"));
    assert.equal(s.key, path.join("/tmp/devproxy-certs", "test.local-key.pem"));
  });

  it("accepts explicit filenames", () => {
    const s = siteWith([{ path: "/", target: "http://l:1" }], {
      certDir: "/tmp/devproxy-certs",
      cert: "custom.pem",
      key: "custom-key.pem",
    });
    assert.equal(s.cert, path.join("/tmp/devproxy-certs", "custom.pem"));
  });
});
