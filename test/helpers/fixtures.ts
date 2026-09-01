/**
 * Normalized config objects for the unit tests.
 *
 * These go through the real loadConfig rather than being hand-built, so a
 * fixture can never drift from what the proxy actually receives — and every
 * default under test is the one the config layer applied.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../../src/config.ts";
import type { Config, Rule, Site } from "../../src/types.ts";

/** Writes a config to a scratch file, loads it, and cleans up. */
export function load(raw: unknown): Config {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "devproxy-fixture-"));
  const file = path.join(dir, "devproxy.config.json");
  fs.writeFileSync(file, typeof raw === "string" ? raw : JSON.stringify(raw));
  try {
    return loadConfig(file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The first site of a single-site config. */
export function site(raw: unknown): Site {
  const first = load(raw).sites[0];
  if (!first) throw new Error("fixture produced no sites");
  return first;
}

/** A site whose rules are exactly the ones given. */
export function siteWith(rules: unknown[], extra: Record<string, unknown> = {}): Site {
  return site({
    sites: [{ name: "fixture", host: "test.local", certDir: "unused", rules, ...extra }],
  });
}

export function ruleAt(s: Site, index: number): Rule {
  const r = s.rules[index];
  if (!r) throw new Error(`site has no rule at index ${index}`);
  return r;
}

/** A single-rule site, for the many tests that only need one target. */
export function oneRule(rule: unknown, extra: Record<string, unknown> = {}): Rule {
  return ruleAt(siteWith([rule], extra), 0);
}
