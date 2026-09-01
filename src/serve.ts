/**
 * Binding the ports and keeping them served.
 *
 * One HTTPS port can carry many hostnames, so certificates are selected per
 * handshake through SNI rather than per listener.
 */

import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import type { SecureContext } from "node:tls";
import { entryHint } from "./constants.ts";
import { bold, blue, dim, die, errCode, magenta, say, warn } from "./log.ts";
import { onRequest, onUpgrade } from "./proxy.ts";
import type { Config, LoadedCert, Site } from "./types.ts";

function loadSecureContext(site: Site): LoadedCert {
  for (const f of [site.cert, site.key]) {
    if (!fs.existsSync(f)) {
      die(`site "${site.name}": missing ${f}\n  run:  node ${entryHint()} --certs`);
    }
  }
  const cert = fs.readFileSync(site.cert);
  const key = fs.readFileSync(site.key);
  return { context: tls.createSecureContext({ cert, key }), cert, key };
}

/** Groups the sites that share a port, skipping the ones that disabled it. */
function groupByPort(sites: Site[], pick: (s: Site) => number | null): Map<number, Site[]> {
  const out = new Map<number, Site[]>();
  for (const s of sites) {
    const port = pick(s);
    if (!port) continue;
    const group = out.get(port);
    if (group) group.push(s);
    else out.set(port, [s]);
  }
  return out;
}

function listen(server: net.Server, port: number, label: string): Promise<void> {
  return new Promise((resolve) => {
    server.on("error", (err: Error) => {
      const code = errCode(err);
      if (code === "EADDRINUSE") {
        die(
          `port ${port} is already in use — stop whatever is on it, ` +
            `or change "listen" in the config`,
        );
      }
      if (code === "EACCES") {
        die(`port ${port} needs root: run with sudo, or set "listen" above 1024 in the config`);
      }
      die(`${label}: ${err.message}`);
    });
    server.listen(port, "0.0.0.0", () => resolve());
  });
}

/**
 * Root is only needed to bind :80/:443. Once that is done we hand the process
 * back to the invoking user so nothing it touches later runs privileged.
 */
function dropPrivileges(): void {
  if (process.getuid?.() !== 0 || !process.env.SUDO_UID) return;
  try {
    process.setgid?.(Number(process.env.SUDO_GID));
    process.setuid?.(Number(process.env.SUDO_UID));
    say(dim(`   dropped root → uid ${process.getuid?.()}`));
  } catch (e) {
    warn(`could not drop root privileges: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function buildHttpsServer(group: Site[]): https.Server {
  const contexts = new Map<string, SecureContext>();
  let fallback: LoadedCert | null = null;
  for (const site of group) {
    const loaded = loadSecureContext(site);
    for (const h of site.allHosts) contexts.set(h, loaded.context);
    fallback ??= loaded;
  }
  if (!fallback) die("internal: an https port was grouped with no site");
  // A const, so the narrowing survives into the SNI callback below.
  const base = fallback;

  return https.createServer({
    cert: base.cert,
    key: base.key,
    // One port can serve many hostnames; SNI decides which cert to present.
    SNICallback: (servername, cb) =>
      cb(null, contexts.get(String(servername).toLowerCase()) ?? base.context),
  });
}

function describe(sites: Site[]): void {
  say("");
  for (const site of sites) {
    say(`${bold(site.publicOrigin)}  ${dim(`(${site.name})`)}`);
    for (const rule of site.rules) {
      const kind = rule.target === site.upstreamTarget ? magenta("upstream") : blue("local");
      say(`   ${String(rule.label).padEnd(14)} ${dim("→")} ${kind} ${rule.target.label}`);
    }
    if (site.httpPort) {
      say(dim(`   :${site.httpPort} ${site.httpMode === "redirect" ? "→ https" : "→ proxied"}`));
    }
  }
  say("");
  say(dim("ctrl-c to stop"));
}

export async function run(config: Config, filter: string | null): Promise<void> {
  const sites = config.sites.filter(
    (s) => s.enabled && (!filter || s.name === filter || s.host === filter),
  );
  if (!sites.length) die(`no enabled site matches "${filter}"`);

  const servers: net.Server[] = [];

  for (const [port, group] of groupByPort(sites, (s) => s.httpsPort)) {
    const server = buildHttpsServer(group);
    server.on("request", (req, res) => void onRequest(config, true, req, res));
    server.on("upgrade", (req, socket, head) => void onUpgrade(config, true, req, socket, head));
    await listen(server, port, `https:${port}`);
    servers.push(server);
  }

  for (const port of groupByPort(sites, (s) => s.httpPort).keys()) {
    const server = http.createServer();
    server.on("request", (req, res) => void onRequest(config, false, req, res));
    server.on("upgrade", (req, socket, head) => void onUpgrade(config, false, req, socket, head));
    await listen(server, port, `http:${port}`);
    servers.push(server);
  }

  dropPrivileges();
  describe(sites);

  const stop = (): void => {
    say("");
    for (const s of servers) s.close();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
