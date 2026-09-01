/**
 * The command line surface, and every error the config layer can refuse with.
 *
 * These run the real binary in a child process because `die()` exits the
 * process — there is no in-process way to observe it.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runCli, runCliWithConfig } from "../helpers/harness.ts";

const valid = {
  sites: [{ name: "a", host: "a.test", rules: [{ path: "/", target: "http://localhost:1" }] }],
};

describe("--help", () => {
  it("prints usage and exits cleanly", async () => {
    const r = await runCli(["--help"]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /devproxy — serve a real hostname/);
    assert.match(r.stdout, /--doctor/);
    assert.match(r.stdout, /node proxy\.ts/, "the help text should name the real entry point");
  });

  it("is also reachable as -h", async () => {
    assert.equal((await runCli(["-h"])).code, 0);
  });
});

describe("argument errors", () => {
  it("refuses an unknown option", async () => {
    const r = await runCli(["--definitely-not-an-option"]);
    assert.equal(r.code, 1);
    assert.match(r.output, /unknown option "--definitely-not-an-option"/);
    assert.match(r.output, /--help/);
  });

  it("refuses a site filter that matches nothing", async () => {
    const r = await runCliWithConfig(valid, ["--site", "nope"]);
    assert.equal(r.code, 1);
    assert.match(r.output, /no enabled site matches "nope"/);
  });
});

describe("config errors", () => {
  it("reports a missing config file", async () => {
    const r = await runCli(["-c", "/nonexistent/devproxy.config.json"]);
    assert.equal(r.code, 1);
    assert.match(r.output, /config not found/);
  });

  it("reports invalid JSON", async () => {
    const r = await runCliWithConfig("{ not json ]");
    assert.equal(r.code, 1);
    assert.match(r.output, /config is not valid JSON/);
  });

  it("reports a config with no sites", async () => {
    const r = await runCliWithConfig({ sites: [] });
    assert.equal(r.code, 1);
    assert.match(r.output, /config has no sites/);
  });

  it("reports a site with no host", async () => {
    const r = await runCliWithConfig({ sites: [{ name: "x", rules: [] }] });
    assert.equal(r.code, 1);
    assert.match(r.output, /site 1 has no "host"/);
  });

  it("reports a site with no rules", async () => {
    const r = await runCliWithConfig({ sites: [{ host: "a.test", rules: [] }] });
    assert.equal(r.code, 1);
    assert.match(r.output, /site "a\.test" has no rules/);
  });

  it("reports a rule with neither path nor regex", async () => {
    const r = await runCliWithConfig({
      sites: [{ host: "a.test", rules: [{ target: "http://localhost:1" }] }],
    });
    assert.equal(r.code, 1);
    assert.match(r.output, /rule 1 needs a "path" or a "regex"/);
  });

  it("reports a rule with no target url", async () => {
    const r = await runCliWithConfig({ sites: [{ host: "a.test", rules: [{ path: "/" }] }] });
    assert.equal(r.code, 1);
    assert.match(r.output, /a rule has no target url/);
  });

  it("reports a target with an unusable scheme", async () => {
    const r = await runCliWithConfig({
      sites: [{ host: "a.test", rules: [{ path: "/", target: "ftp://example.com" }] }],
    });
    assert.equal(r.code, 1);
    assert.match(r.output, /must be http: or https:/);
  });

  it("reports a target url that will not parse", async () => {
    const r = await runCliWithConfig({
      sites: [{ host: "a.test", rules: [{ path: "/", target: "not a url" }] }],
    });
    assert.equal(r.code, 1);
    assert.match(r.output, /invalid target url/);
  });

  it('reports a rule targeting "upstream" when the site defines none', async () => {
    const r = await runCliWithConfig({
      sites: [{ host: "a.test", rules: [{ path: "/", target: "upstream" }] }],
    });
    assert.equal(r.code, 1);
    assert.match(r.output, /targets "upstream" but the site defines no upstream/);
  });

  it("reports two sites claiming the same host", async () => {
    const r = await runCliWithConfig({
      sites: [
        { name: "one", host: "same.test", rules: [{ path: "/", target: "http://localhost:1" }] },
        { name: "two", host: "same.test", rules: [{ path: "/", target: "http://localhost:2" }] },
      ],
    });
    assert.equal(r.code, 1);
    assert.match(r.output, /two sites both claim host "same\.test"/);
  });

  it("catches an alias colliding with another site's host", async () => {
    const r = await runCliWithConfig({
      sites: [
        { name: "one", host: "one.test", rules: [{ path: "/", target: "http://localhost:1" }] },
        {
          name: "two",
          host: "two.test",
          aliases: ["one.test"],
          rules: [{ path: "/", target: "http://localhost:2" }],
        },
      ],
    });
    assert.equal(r.code, 1);
    assert.match(r.output, /two sites both claim host "one\.test"/);
  });
});

describe("--hosts", () => {
  it("prints a marked block with both address families", async () => {
    const r = await runCliWithConfig(
      {
        sites: [
          {
            host: "a.test",
            aliases: ["www.a.test"],
            rules: [{ path: "/", target: "http://localhost:1" }],
          },
        ],
      },
      ["--hosts"],
    );
    assert.equal(r.code, 0);
    assert.match(r.stdout, /# >>> devproxy >>>/);
    assert.match(r.stdout, /# <<< devproxy <<</);
    assert.match(r.stdout, /127\.0\.0\.1\ta\.test/);
    assert.match(r.stdout, /127\.0\.0\.1\twww\.a\.test/);
    assert.match(r.stdout, /::1\t\ta\.test/);
  });

  it("omits a disabled site", async () => {
    const r = await runCliWithConfig(
      {
        sites: [
          { host: "on.test", rules: [{ path: "/", target: "http://localhost:1" }] },
          {
            host: "off.test",
            enabled: false,
            rules: [{ path: "/", target: "http://localhost:2" }],
          },
        ],
      },
      ["--hosts"],
    );
    assert.match(r.stdout, /on\.test/);
    assert.doesNotMatch(r.stdout, /off\.test/);
  });
});

describe("--doctor", () => {
  it("reports each check and fails when a target is unreachable", async () => {
    const r = await runCliWithConfig(
      {
        sites: [
          {
            name: "unreachable",
            host: "doctor.test",
            listen: { https: false, http: 18099 },
            rules: [{ path: "/", target: { url: "http://127.0.0.1:1", resolve: "system" } }],
          },
        ],
      },
      ["--doctor"],
    );
    assert.equal(r.code, 1, "an unreachable target must fail the exit code");
    assert.match(r.stdout, /devproxy doctor/);
    assert.match(r.stdout, /\/etc\/hosts — doctor\.test/);
    assert.match(r.stdout, /problem/);
  });

  it("accepts a site filter", async () => {
    const r = await runCliWithConfig(
      {
        sites: [
          { name: "one", host: "one.test", rules: [{ path: "/", target: "http://localhost:1" }] },
          { name: "two", host: "two.test", rules: [{ path: "/", target: "http://localhost:2" }] },
        ],
      },
      ["--doctor", "--site", "two"],
    );
    assert.match(r.stdout, /two\.test/);
    assert.doesNotMatch(r.stdout, /one\.test/);
  });
});
