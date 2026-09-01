/**
 * The /etc/hosts block — the one piece of system state this tool changes, and
 * the reason the browser reaches the proxy instead of the real deployment.
 */

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { HOSTS_FILE, MARK_END, MARK_START } from "./constants.ts";
import { die, green, say } from "./log.ts";
import type { Config } from "./types.ts";

/** Every name → 127.0.0.1 mapping currently in the file, comments removed. */
export function hostsEntries(): Map<string, string> {
  const map = new Map<string, string>();
  if (!fs.existsSync(HOSTS_FILE)) return map;
  for (const line of fs.readFileSync(HOSTS_FILE, "utf8").split("\n")) {
    const clean = line.replace(/#.*$/, "").trim();
    if (!clean) continue;
    const [ip, ...names] = clean.split(/\s+/);
    if (!ip) continue;
    for (const n of names) map.set(n.toLowerCase(), ip);
  }
  return map;
}

/** The marked block this config needs, v4 then v6. */
export function hostsBlock(config: Config): string {
  const enabled = config.sites.filter((s) => s.enabled);
  const v4 = enabled.flatMap((s) => s.allHosts.map((h) => `127.0.0.1\t${h}`));
  const v6 = enabled.flatMap((s) => s.allHosts.map((h) => `::1\t\t${h}`));
  return [MARK_START, ...v4, ...v6, MARK_END].join("\n");
}

/**
 * Replaces the marked block, leaving the rest of the file alone. Passing null
 * removes it. Always leaves a backup, because this file matters.
 */
export function rewriteHostsFile(nextBlock: string | null): void {
  if (process.getuid?.() !== 0) die(`editing ${HOSTS_FILE} needs root — rerun with sudo`);

  const current = fs.readFileSync(HOSTS_FILE, "utf8");
  const stripped = current.replace(
    new RegExp(`\\n?${MARK_START}[\\s\\S]*?${MARK_END}\\n?`, "g"),
    "\n",
  );
  const next = nextBlock ? `${stripped.replace(/\n+$/, "")}\n\n${nextBlock}\n` : stripped;

  fs.copyFileSync(HOSTS_FILE, `${HOSTS_FILE}.devproxy.bak`);
  fs.writeFileSync(HOSTS_FILE, next);

  // macOS caches negative lookups too, so the flush is not optional.
  spawnSync("dscacheutil", ["-flushcache"], { stdio: "ignore" });
  spawnSync("killall", ["-HUP", "mDNSResponder"], { stdio: "ignore" });

  say(
    `${green("✓")} ${HOSTS_FILE} updated (backup: ${HOSTS_FILE}.devproxy.bak), DNS cache flushed`,
  );
}
