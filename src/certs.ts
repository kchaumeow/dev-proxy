/**
 * Certificate creation, delegated to mkcert so the CA is one the browsers on
 * this machine already trust.
 */

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { die, green, say } from "./log.ts";
import type { Config } from "./types.ts";

export function makeCerts(config: Config, filter: string | null): void {
  const probe = spawnSync("mkcert", ["-version"], { encoding: "utf8" });
  if (probe.error) die("mkcert is not installed — brew install mkcert && mkcert -install");

  const root = spawnSync("mkcert", ["-CAROOT"], { encoding: "utf8" }).stdout?.trim();
  if (!root || !fs.existsSync(path.join(root, "rootCA.pem"))) {
    die("mkcert has no local CA yet — run: mkcert -install");
  }

  for (const site of config.sites) {
    if (filter && site.name !== filter && site.host !== filter) continue;
    if (!site.httpsPort) continue;

    if (fs.existsSync(site.cert) && fs.existsSync(site.key)) {
      say(`${green("✓")} ${site.host} — certificate already present`);
      continue;
    }

    fs.mkdirSync(path.dirname(site.cert), { recursive: true });
    const args = ["-cert-file", site.cert, "-key-file", site.key, ...site.allHosts];
    const r = spawnSync("mkcert", args, { stdio: "inherit" });
    if (r.status !== 0) die(`mkcert failed for ${site.host}`);

    // mkcert runs as root under sudo; keep the files usable by the real user.
    if (process.env.SUDO_UID) {
      for (const f of [site.cert, site.key]) {
        fs.chownSync(f, Number(process.env.SUDO_UID), Number(process.env.SUDO_GID));
      }
    }
    say(`${green("✓")} ${site.host} — certificate written to ${site.cert}`);
  }
}
