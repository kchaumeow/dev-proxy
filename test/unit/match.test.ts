import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { outboundPath, pathMatches, ruleMatches } from "../../src/match.ts";
import { oneRule, siteWith } from "../helpers/fixtures.ts";
import type { IncomingMessage } from "node:http";

const url = (p: string): URL => new URL(p, "https://test.local");
const req = (method = "GET"): IncomingMessage => ({ method }) as IncomingMessage;

describe("pathMatches", () => {
  it("matches everything for the catch-all", () => {
    assert.equal(pathMatches("/", "/anything"), true);
    assert.equal(pathMatches(null, "/anything"), true);
  });

  it("matches the prefix itself and its subpaths", () => {
    assert.equal(pathMatches("/api", "/api"), true);
    assert.equal(pathMatches("/api", "/api/users"), true);
  });

  it("does not match a longer sibling segment", () => {
    assert.equal(pathMatches("/api", "/apix"), false);
    assert.equal(pathMatches("/api", "/apiv2/users"), false);
  });

  it("ignores a trailing slash on the prefix", () => {
    assert.equal(pathMatches("/api/", "/api/users"), true);
  });
});

describe("ruleMatches", () => {
  it("applies a regex against the pathname", () => {
    const rule = oneRule({ regex: "^/re/[0-9]+$", target: "http://localhost:1" });
    assert.equal(ruleMatches(rule, req(), url("/re/42")), true);
    assert.equal(ruleMatches(rule, req(), url("/re/abc")), false);
  });

  it("restricts a rule to the listed methods", () => {
    const rule = oneRule({ path: "/x", methods: ["post"], target: "http://localhost:1" });
    assert.equal(ruleMatches(rule, req("POST"), url("/x")), true);
    assert.equal(ruleMatches(rule, req("GET"), url("/x")), false);
  });

  it("ignores the query string when matching", () => {
    const rule = oneRule({ path: "/api", target: "http://localhost:1" });
    assert.equal(ruleMatches(rule, req(), url("/api/x?path=/other")), true);
  });
});

describe("rule order", () => {
  it("keeps config order so the first match wins", () => {
    const s = siteWith([
      { path: "/api", target: "http://localhost:1" },
      { path: "/", target: "http://localhost:2" },
    ]);
    const first = s.rules.find((r) => ruleMatches(r, req(), url("/api/x")));
    assert.equal(first?.target.port, 1);
  });
});

describe("outboundPath", () => {
  it("passes the path and query through untouched by default", () => {
    const rule = oneRule({ path: "/api", target: "http://localhost:1" });
    assert.equal(outboundPath(rule, url("/api/users?x=1&y=2")), "/api/users?x=1&y=2");
  });

  it("drops the matched prefix with stripPath", () => {
    const rule = oneRule({ path: "/api", stripPath: true, target: "http://localhost:1" });
    assert.equal(outboundPath(rule, url("/api/users")), "/users");
  });

  it("leaves a root path behind when stripPath eats everything", () => {
    const rule = oneRule({ path: "/api", stripPath: true, target: "http://localhost:1" });
    assert.equal(outboundPath(rule, url("/api")), "/");
  });

  it("never strips the catch-all", () => {
    const rule = oneRule({ path: "/", stripPath: true, target: "http://localhost:1" });
    assert.equal(outboundPath(rule, url("/whatever")), "/whatever");
  });

  it("applies a rewrite to the path", () => {
    const rule = oneRule({
      path: "/rw",
      rewrite: { from: "^/rw/old", to: "/new" },
      target: "http://localhost:1",
    });
    assert.equal(outboundPath(rule, url("/rw/old/tail")), "/new/tail");
  });

  it("prepends the target's base path", () => {
    const rule = oneRule({ path: "/base", target: "http://localhost:1/mounted" });
    assert.equal(outboundPath(rule, url("/base/thing")), "/mounted/base/thing");
  });

  it("strips the prefix before adding the base path", () => {
    const rule = oneRule({ path: "/base", stripPath: true, target: "http://localhost:1/mounted" });
    assert.equal(outboundPath(rule, url("/base/thing")), "/mounted/thing");
  });
});
