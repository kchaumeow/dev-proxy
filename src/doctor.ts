/**
 * `--doctor`: check everything that has to be true before the proxy can work,
 * in the order it has to be true, and say how to fix whatever is not.
 */

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { X509Certificate } from "node:crypto";
import { entryHint, isLocalName } from "./constants.ts";
import { bold, cli, dim, errLabel, green, red, say, tick } from "./log.ts";
import { hostsEntries } from "./hosts.ts";
import { sniName, tryResolveHost } from "./resolve.ts";
import type { Config, Site, Target } from "./types.ts";

interface Probe {
  ok: boolean;
  msg?: string | undefined;
}

interface TlsProbe extends Probe {
  authorized?: boolean | undefined;
  subject?: string | undefined;
}

interface PortStatus {
  free: boolean;
  code?: string | undefined;
}

/** Knocks on a port and reports whether anything answers. */
function tcpProbe(host: string, port: number, timeoutMs = 3000): Promise<Probe> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const done = (ok: boolean, msg?: string): void => {
      socket.destroy();
      resolve({ ok, msg });
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => done(true));
    socket.on("timeout", () => done(false, "timed out"));
    socket.on("error", (e) => done(false, errLabel(e)));
  });
}

/** Whether this process could bind the port itself. */
function portFree(port: number): Promise<PortStatus> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", (e) => resolve({ free: false, code: errLabel(e) }));
    server.once("listening", () => server.close(() => resolve({ free: true })));
    server.listen(port, "0.0.0.0");
  });
}

/** Completes a handshake to see whether the upstream's certificate is trusted. */
function tlsProbe(
  address: string,
  port: number,
  servername: string | undefined,
  timeoutMs = 5000,
): Promise<TlsProbe> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: address,
        port,
        ...(servername ? { servername } : {}),
        // Reporting "not trusted" is the point; failing the handshake is not.
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        socket.destroy();
        // A certificate may carry several CN attributes; the first is the one
        // worth showing.
        const cn = cert?.subject?.CN;
        resolve({ ok: true, authorized, subject: Array.isArray(cn) ? cn[0] : cn });
      },
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve({ ok: false, msg: "timed out" });
    });
    socket.on("error", (e) => resolve({ ok: false, msg: errLabel(e) }));
  });
}

/** Counts problems so the exit code can mean something. */
interface Tally {
  problems: number;
}

function checkHosts(site: Site, hosts: Map<string, string>, tally: Tally): void {
  for (const host of site.allHosts) {
    const ip = hosts.get(host);
    const ok = ip === "127.0.0.1" || ip === "::1";
    say(`  ${tick(ok)} /etc/hosts — ${host} → ${ip ?? red("not mapped")}`);
    if (!ok) {
      tally.problems++;
      say(dim(`      fix: sudo node ${entryHint()} --hosts-write`));
    }
  }
}

function checkCertificate(site: Site, tally: Tally): void {
  if (!site.httpsPort) return;

  if (!fs.existsSync(site.cert) || !fs.existsSync(site.key)) {
    say(`  ${tick(false)} certificate — missing ${path.basename(site.cert)}`);
    say(dim(`      fix: node ${entryHint()} --certs`));
    tally.problems++;
    return;
  }

  try {
    const x = new X509Certificate(fs.readFileSync(site.cert));
    const expires = new Date(x.validTo);
    const live = expires > new Date();
    const names = (x.subjectAltName ?? "")
      .split(",")
      .map((s) => s.trim().replace(/^DNS:/, "").toLowerCase());
    const covers = site.allHosts.every((h) => names.includes(h));
    say(
      `  ${tick(live && covers)} certificate — ${covers ? "covers" : red("does not cover")} ` +
        `${site.allHosts.join(", ")}, ` +
        `${live ? `valid until ${expires.toISOString().slice(0, 10)}` : red("EXPIRED")}`,
    );
    if (!live || !covers) tally.problems++;
  } catch (e) {
    say(`  ${tick(false)} certificate — unreadable: ${errLabel(e)}`);
    tally.problems++;
  }
}

async function checkPorts(site: Site, tally: Tally): Promise<void> {
  const ports = [site.httpsPort, site.httpPort].filter((p): p is number => p !== null);
  for (const port of ports) {
    const { free, code } = await portFree(port);
    // Binding 0.0.0.0 succeeds even when another process holds 127.0.0.1 on
    // the same port — and that one wins for browser traffic. So also knock.
    const answered = await tcpProbe("127.0.0.1", port, 700);
    const ok = free && !answered.ok;

    let detail: string;
    if (!free) {
      detail =
        code === "EACCES"
          ? "needs root on this system — run the proxy with sudo"
          : `${code} (something else is listening)`;
    } else if (answered.ok) {
      detail = "a loopback-only listener already answers here and would win";
    } else {
      detail = "free";
    }

    say(`  ${tick(ok)} port ${port} — ${detail}`);
    if (!ok) tally.problems++;
  }
}

async function checkTarget(t: Target, tally: Tally): Promise<void> {
  const resolved = await tryResolveHost(t);
  if ("error" in resolved) {
    say(`  ${tick(false)} ${t.label} — ${resolved.error}`);
    tally.problems++;
    return;
  }
  const address = resolved.address;
  const via = t.resolve === "dns" ? dim(` (DNS: ${address})`) : "";

  const probe = await tcpProbe(address, t.port);
  if (!probe.ok) {
    say(`  ${tick(false)} ${t.label}${via} — ${probe.msg}`);
    say(
      dim(
        isLocalName(t.hostname)
          ? "      is the dev server running?"
          : "      is the host reachable (VPN)?",
      ),
    );
    tally.problems++;
    return;
  }

  if (!t.secure) {
    say(`  ${tick(true)} ${t.label}${via} — reachable`);
    return;
  }

  const h = await tlsProbe(address, t.port, sniName(t));
  const ok = h.ok && (h.authorized === true || t.insecure || cli.insecure);
  const state = h.ok
    ? `TLS ${h.authorized ? "valid" : red("not trusted")}${h.subject ? dim(` (CN=${h.subject})`) : ""}`
    : h.msg;
  say(`  ${tick(ok)} ${t.label}${via} — ${state}`);
  if (!ok) tally.problems++;
}

export async function doctor(config: Config, filter: string | null): Promise<void> {
  const sites = config.sites.filter((s) => !filter || s.name === filter || s.host === filter);
  const hosts = hostsEntries();
  const tally: Tally = { problems: 0 };

  say(bold(`\ndevproxy doctor  ${dim(config.file)}\n`));

  for (const site of sites) {
    say(bold(`\n${site.name}  ${dim(site.publicOrigin)}`));

    checkHosts(site, hosts, tally);
    checkCertificate(site, tally);
    await checkPorts(site, tally);

    // Rules often share a target; check each one once.
    const targets = new Map<string, Target>();
    for (const rule of site.rules) targets.set(rule.target.label, rule.target);
    for (const t of targets.values()) await checkTarget(t, tally);
  }

  say("");
  if (tally.problems) {
    say(red(`${tally.problems} problem${tally.problems === 1 ? "" : "s"} above.`));
    process.exitCode = 1;
  } else {
    say(green("all checks passed."));
  }
}
