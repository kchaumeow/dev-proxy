#!/usr/bin/env node
/**
 * devproxy — a configurable local reverse proxy for developing against a real
 * deployment.
 *
 * It serves a public hostname (say app.example.com) from your machine
 * and splits every request between your local dev server and the real remote
 * host, per an ordered rule list. The browser stays on the real origin, so
 * cookies, CORS, and OIDC redirect URIs all keep working while the frontend
 * comes from Vite.
 *
 * The one trick that makes this possible: /etc/hosts points the hostname at
 * 127.0.0.1, which would also trap the proxy's own upstream calls in a loop.
 * Node's dns.resolve4() talks to the configured DNS servers directly and never
 * reads /etc/hosts, so the proxy can still find the real IP — and connects to
 * it with the original SNI and Host header. No hardcoded addresses.
 *
 * Zero dependencies. Node >= 18.
 */

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import dnsp from "node:dns/promises";
import fs from "node:fs";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOSTS_FILE = "/etc/hosts";
const MARK_START = "# >>> devproxy >>>";
const MARK_END = "# <<< devproxy <<<";

// Hop-by-hop headers belong to a single connection and must never be forwarded
// (RFC 9110 7.6.1). Passing transfer-encoding on in particular corrupts the
// response, because Node has already decoded the chunking for us.
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const LOCAL_NAMES = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"]);

/* ------------------------------------------------------------------ output */

const TTY = process.stdout.isTTY;
const c = (code) => (s) => (TTY ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const dim = c(2);
const bold = c(1);
const red = c(31);
const green = c(32);
const yellow = c(33);
const blue = c(34);
const magenta = c(35);
const cyan = c(36);

let CLI = { verbose: false, quiet: false, insecure: false };

const say = (...a) => !CLI.quiet && console.log(...a);
const warn = (...a) => console.warn(yellow("!"), ...a);
const fail = (...a) => console.error(red("✗"), ...a);

function die(msg) {
  fail(msg);
  process.exit(1);
}

/* ------------------------------------------------------------------ config */

/**
 * Strips // and /* *\/ comments from JSON so the config file can explain
 * itself. String contents (and thus every "http://..." URL) are left alone.
 */
function stripJsonComments(src) {
  let out = "";
  let inString = false;
  let inLine = false;
  let inBlock = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    const next = src[i + 1];
    if (inLine) {
      if (ch === "\n") {
        inLine = false;
        out += ch;
      }
      continue;
    }
    if (inBlock) {
      if (ch === "*" && next === "/") {
        inBlock = false;
        i++;
      }
      continue;
    }
    if (inString) {
      out += ch;
      if (ch === "\\") {
        out += next ?? "";
        i++;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLine = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlock = true;
      i++;
      continue;
    }
    out += ch;
  }
  return out;
}

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj ?? {})) out[k.toLowerCase()] = v;
  return out;
}

const isLocalName = (h) => LOCAL_NAMES.has(h) || h.endsWith(".localhost");

function loadConfig(file) {
  if (!fs.existsSync(file)) die(`config not found: ${file}`);
  let raw;
  try {
    raw = JSON.parse(stripJsonComments(fs.readFileSync(file, "utf8")));
  } catch (e) {
    die(`config is not valid JSON (${file}): ${e.message}`);
  }
  const dir = path.dirname(file);
  const sites = (raw.sites ?? []).map((s, i) => normalizeSite(s, i, dir, raw));
  if (!sites.length) die(`config has no sites: ${file}`);
  const byHost = new Map();
  for (const site of sites) {
    for (const h of site.allHosts) {
      if (byHost.has(h)) die(`two sites both claim host "${h}"`);
      byHost.set(h, site);
    }
  }
  return {
    file,
    sites,
    byHost,
    connectTimeoutMs: raw.connectTimeoutMs ?? 15000,
  };
}

/** A target is where a matched request is sent: a URL plus how to reach it. */
function parseTarget(spec, site) {
  if (spec === "upstream") {
    if (!site.upstreamTarget)
      die(`site "${site.name}": a rule targets "upstream" but the site defines no upstream`);
    return site.upstreamTarget;
  }
  const o = typeof spec === "string" ? { url: spec } : { ...(spec ?? {}) };
  if (!o.url) die(`site "${site.name}": a rule has no target url`);
  let url;
  try {
    url = new URL(o.url);
  } catch {
    return die(`site "${site.name}": invalid target url "${o.url}"`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:")
    die(`site "${site.name}": target "${o.url}" must be http: or https:`);
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const secure = url.protocol === "https:";
  const local = isLocalName(hostname);
  return {
    label: o.url,
    secure,
    hostname,
    port: Number(url.port) || (secure ? 443 : 80),
    basePath: url.pathname.replace(/\/+$/, ""),
    ip: o.ip ?? null,
    // /etc/hosts points the site's own domain at us, so anything still using
    // that domain has to be resolved through DNS or the proxy calls itself.
    // Literal IPs and local names never need it.
    resolve: o.resolve ?? (local || net.isIP(hostname) ? "system" : "dns"),
    // Real upstreams need the browser's Host (vhost routing, CORS checks and
    // cookie domains all key off it). Local dev servers usually reject an
    // unfamiliar Host — Vite's server.allowedHosts — and never need it.
    preserveHost: o.preserveHost ?? !local,
    insecure: o.insecure ?? false,
    headers: lowerKeys(o.headers),
  };
}

function parseRule(raw, site, idx) {
  if (!raw || typeof raw !== "object") die(`site "${site.name}": rule ${idx + 1} is not an object`);
  if (raw.path == null && !raw.regex)
    die(`site "${site.name}": rule ${idx + 1} needs a "path" or a "regex"`);
  return {
    path: raw.path ?? null,
    regex: raw.regex ? new RegExp(raw.regex) : null,
    methods: raw.methods ? raw.methods.map((m) => m.toUpperCase()) : null,
    // stripPath drops the matched prefix, for an upstream mounted elsewhere.
    stripPath: raw.stripPath === true,
    rewrite: raw.rewrite ? { from: new RegExp(raw.rewrite.from), to: raw.rewrite.to } : null,
    headers: lowerKeys(raw.headers),
    target: parseTarget(raw.target, site),
    label: raw.regex ? `~${raw.regex}` : raw.path,
  };
}

function normalizeSite(raw, idx, dir, root) {
  if (!raw.host) die(`site ${idx + 1} has no "host"`);
  const site = {};
  site.host = String(raw.host).toLowerCase();
  site.name = raw.name ?? site.host;
  site.enabled = raw.enabled !== false;
  site.aliases = (raw.aliases ?? []).map((h) => String(h).toLowerCase());
  site.allHosts = [site.host, ...site.aliases];

  const listen = raw.listen ?? {};
  site.httpsPort = listen.https === false ? null : Number(listen.https ?? 443);
  site.httpPort = listen.http === false ? null : Number(listen.http ?? 80);
  // What plain HTTP does: send the browser to https (default) or proxy as-is.
  site.httpMode = listen.httpMode ?? "redirect";

  const certDir = path.resolve(dir, raw.certDir ?? root.certDir ?? "certs");
  site.cert = path.resolve(certDir, raw.cert ?? `${site.host}.pem`);
  site.key = path.resolve(certDir, raw.key ?? `${site.host}-key.pem`);

  site.publicOrigin = site.httpsPort
    ? `https://${site.host}${site.httpsPort === 443 ? "" : `:${site.httpsPort}`}`
    : `http://${site.host}${site.httpPort === 80 ? "" : `:${site.httpPort}`}`;

  // "auto" keeps a Domain= the browser would accept on this origin and drops
  // one it would reject; false leaves Set-Cookie untouched; a string forces it.
  site.cookieDomain = raw.cookieDomain ?? "auto";
  // HSTS from the real host would outlive this session and force https on the
  // hostname long after the proxy is gone, so it goes by default.
  site.stripResponseHeaders = (raw.stripResponseHeaders ?? ["strict-transport-security"]).map((h) =>
    h.toLowerCase(),
  );

  site.upstreamTarget = null;
  if (raw.upstream) {
    if (raw.upstream === "upstream") die(`site "${site.name}": upstream cannot be "upstream"`);
    site.upstreamTarget = parseTarget(raw.upstream, site);
  }
  site.rules = (raw.rules ?? []).map((r, i) => parseRule(r, site, i));
  if (!site.rules.length) die(`site "${site.name}" has no rules`);
  return site;
}

/* --------------------------------------------------------------- resolving */

const dnsCache = new Map(); // hostname -> { address, expires }
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

/**
 * Returns the address to connect to. For "dns" targets this deliberately uses
 * dns.resolve4/6, which query the configured nameservers and ignore
 * /etc/hosts — the whole reason the proxy can serve a hostname it also calls.
 * A VPN's DNS still works; only the local override is bypassed.
 */
async function resolveHost(target) {
  if (target.ip) return target.ip;
  if (target.resolve === "system") return target.hostname;

  const hit = dnsCache.get(target.hostname);
  if (hit && hit.expires > Date.now()) return hit.address;

  let address;
  let ttl = 60;
  try {
    const [a] = await dnsp.resolve4(target.hostname, { ttl: true });
    if (a) ({ address, ttl } = a);
  } catch {
    /* fall through to v6 */
  }
  if (!address) {
    const [a] = await dnsp.resolve6(target.hostname, { ttl: true });
    if (a) ({ address, ttl } = a);
  }
  if (!address) throw new Error(`no A/AAAA record for ${target.hostname}`);

  dnsCache.set(target.hostname, {
    address,
    expires: Date.now() + Math.min(Math.max(ttl, 10), 300) * 1000,
  });
  if (!hit) say(dim(`   dns  ${target.hostname} → ${address}`));
  return address;
}

const targetOrigin = (t) =>
  `${t.secure ? "https" : "http"}://${t.hostname}${
    t.port === (t.secure ? 443 : 80) ? "" : `:${t.port}`
  }`;

const targetHostHeader = (t) =>
  `${t.hostname}${t.port === (t.secure ? 443 : 80) ? "" : `:${t.port}`}`;

/* ---------------------------------------------------------------- matching */

function pathMatches(prefix, pathname) {
  if (!prefix || prefix === "/") return true;
  const p = prefix.replace(/\/+$/, "");
  return pathname === p || pathname.startsWith(p + "/");
}

function ruleMatches(rule, req, url) {
  if (rule.methods && !rule.methods.includes(req.method)) return false;
  if (rule.regex) return rule.regex.test(url.pathname);
  return pathMatches(rule.path, url.pathname);
}

/** The path sent upstream: prefix stripped, regex rewrite applied, base added. */
function outboundPath(rule, url) {
  let pathname = url.pathname;
  if (rule.stripPath && rule.path && rule.path !== "/") {
    const p = rule.path.replace(/\/+$/, "");
    pathname = pathname.slice(p.length) || "/";
    if (!pathname.startsWith("/")) pathname = "/" + pathname;
  }
  if (rule.rewrite) pathname = pathname.replace(rule.rewrite.from, rule.rewrite.to);
  if (rule.target.basePath) pathname = rule.target.basePath + pathname;
  return pathname + url.search;
}

/* --------------------------------------------------------------- rewriting */

function forwardHeaders(req, site, rule, secure, remoteAddr) {
  const t = rule.target;
  const h = { ...req.headers };
  for (const k of Object.keys(h)) if (HOP_BY_HOP.has(k)) delete h[k];

  const clientHost = req.headers.host ?? site.host;
  h.host = t.preserveHost ? clientHost : targetHostHeader(t);

  // Origin and Referer follow Host: a dev server that validates them shouldn't
  // see a public origin it knows nothing about, while a real upstream must see
  // exactly the origin the browser is on or its CORS check fails.
  if (!t.preserveHost) {
    const from = site.publicOrigin;
    const to = targetOrigin(t);
    if (h.origin && h.origin === from) h.origin = to;
    if (h.referer && h.referer.startsWith(from)) h.referer = to + h.referer.slice(from.length);
  }

  h["x-forwarded-for"] = req.headers["x-forwarded-for"]
    ? `${req.headers["x-forwarded-for"]}, ${remoteAddr}`
    : remoteAddr;
  h["x-forwarded-host"] = clientHost;
  h["x-forwarded-proto"] = secure ? "https" : "http";
  h["x-forwarded-port"] = String(secure ? site.httpsPort : site.httpPort);
  h["x-real-ip"] = remoteAddr;

  Object.assign(h, t.headers, rule.headers);
  // An explicit null in the config means "do not send this header at all".
  for (const [k, v] of Object.entries(h)) if (v === null) delete h[k];
  return h;
}

function swapOrigin(value, from, to) {
  return value.startsWith(from) ? to + value.slice(from.length) : value;
}

/** Sends a redirect back to the public origin instead of leaking the target. */
function rewriteLocation(loc, site, t) {
  let u;
  try {
    u = new URL(loc);
  } catch {
    return loc; // relative Location — already correct
  }
  const host = u.hostname.toLowerCase();
  const port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
  const isTarget = host === t.hostname && port === t.port;
  const isOurs = site.allHosts.includes(host); // same name, other scheme/port
  if (!isTarget && !isOurs) return loc;
  let pathname = u.pathname;
  if (t.basePath && pathname.startsWith(t.basePath)) pathname = pathname.slice(t.basePath.length) || "/";
  return `${site.publicOrigin}${pathname}${u.search}${u.hash}`;
}

const cookieDomainAccepted = (host, attr) => {
  const d = attr.trim().replace(/^\./, "").toLowerCase();
  return host === d || host.endsWith("." + d);
};

/**
 * A Domain= the browser rejects silently drops the whole cookie, which looks
 * exactly like a broken login. Dropping the attribute instead makes the cookie
 * host-only for this origin, which is what a dev session wants.
 */
function rewriteCookies(values, site, t) {
  const forceSecure = !!site.httpsPort;
  return values.map((raw) => {
    let out = raw;
    if (site.cookieDomain !== false) {
      const current = /;\s*domain=([^;]*)/i.exec(out)?.[1];
      const wanted =
        site.cookieDomain === "auto"
          ? current && cookieDomainAccepted(site.host, current)
            ? current.trim()
            : null
          : site.cookieDomain;
      out = out.replace(/;\s*domain=[^;]*/gi, "");
      if (wanted) out += `; Domain=${wanted}`;
    }
    if (forceSecure && !/;\s*secure\s*(;|$)/i.test(out)) out += "; Secure";
    return out;
  });
}

function responseHeaders(upstream, site, t) {
  const out = {};
  for (const [k, v] of Object.entries(upstream.headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    if (site.stripResponseHeaders.includes(key)) continue;
    out[key] = v;
  }
  if (out.location) out.location = rewriteLocation(String(out.location), site, t);
  if (out["set-cookie"])
    out["set-cookie"] = rewriteCookies([out["set-cookie"]].flat(), site, t);
  const acao = out["access-control-allow-origin"];
  if (acao && acao !== "*")
    out["access-control-allow-origin"] = swapOrigin(String(acao), targetOrigin(t), site.publicOrigin);
  return out;
}

/* ------------------------------------------------------------------ proxying */

function statusColor(code) {
  if (code >= 500) return red;
  if (code >= 400) return yellow;
  if (code >= 300) return cyan;
  return green;
}

function logRequest(site, rule, req, status, ms, note) {
  if (CLI.quiet) return;
  const via = rule ? (rule.target === site.upstreamTarget ? magenta("upstream") : blue("local")) : dim("—");
  const where = rule ? dim(` ${rule.target.label}`) : "";
  console.log(
    `${statusColor(status)(String(status).padEnd(3))} ${req.method.padEnd(6)} ${req.url}  ${dim("⇢")} ${via}${where} ${dim(`${ms}ms`)}${note ? ` ${red(note)}` : ""}`,
  );
}

function sendError(res, status, title, detail) {
  if (res.headersSent) return res.destroy();
  const body = `devproxy: ${title}\n\n${detail ?? ""}\n`;
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

function pickSite(config, req) {
  const host = String(req.headers.host ?? "").split(":")[0].toLowerCase();
  return config.byHost.get(host) ?? (config.sites.length === 1 ? config.sites[0] : null);
}

async function onRequest(config, secure, req, res) {
  const started = Date.now();
  const site = pickSite(config, req);
  if (!site) {
    logRequest({}, null, req, 421, 0);
    return sendError(res, 421, `no site configured for host "${req.headers.host}"`,
      `Configured hosts: ${[...config.byHost.keys()].join(", ")}`);
  }

  if (!secure && site.httpsPort && site.httpMode === "redirect") {
    const location = `${site.publicOrigin}${req.url}`;
    res.writeHead(308, { location, "content-length": 0 });
    logRequest(site, null, req, 308, Date.now() - started);
    return res.end();
  }

  let url;
  try {
    url = new URL(req.url, site.publicOrigin);
  } catch {
    return sendError(res, 400, `cannot parse request path "${req.url}"`);
  }

  const rule = site.rules.find((r) => ruleMatches(r, req, url));
  if (!rule) {
    logRequest(site, null, req, 404, Date.now() - started);
    return sendError(res, 404, `no rule in site "${site.name}" matches ${url.pathname}`,
      `Rules: ${site.rules.map((r) => `${r.label} → ${r.target.label}`).join("\n       ")}`);
  }

  const t = rule.target;
  let address;
  try {
    address = await resolveHost(t);
  } catch (e) {
    logRequest(site, rule, req, 502, Date.now() - started, "dns");
    return sendError(res, 502, `cannot resolve ${t.hostname}`, e.message);
  }

  const lib = t.secure ? https : http;
  const proxyReq = lib.request({
    host: address,
    port: t.port,
    method: req.method,
    path: outboundPath(rule, url),
    headers: forwardHeaders(req, site, rule, secure, req.socket.remoteAddress ?? "127.0.0.1"),
    agent: t.secure ? httpsAgent : httpAgent,
    setHost: false,
    ...(t.secure
      ? {
          // Connecting by IP, so SNI has to be named explicitly or the real
          // host serves the wrong certificate (or none).
          servername: net.isIP(t.hostname) ? undefined : t.hostname,
          rejectUnauthorized: !(t.insecure || CLI.insecure),
        }
      : {}),
  });

  if (CLI.verbose) {
    say(dim(`   → ${t.secure ? "https" : "http"}://${address}:${t.port}${outboundPath(rule, url)}`));
  }

  // A connect/idle limit until the response starts; cleared afterwards so
  // streaming responses (SSE, long polls) are never cut off.
  proxyReq.setTimeout(config.connectTimeoutMs, () => {
    proxyReq.destroy(new Error(`no response within ${config.connectTimeoutMs}ms`));
  });

  proxyReq.on("response", (upstream) => {
    proxyReq.setTimeout(0);
    logRequest(site, rule, req, upstream.statusCode, Date.now() - started);
    res.writeHead(upstream.statusCode, responseHeaders(upstream, site, t));
    upstream.pipe(res);
    res.on("close", () => upstream.destroy());
  });

  proxyReq.on("error", (err) => {
    logRequest(site, rule, req, 502, Date.now() - started, err.code ?? "error");
    sendError(res, 502, `cannot reach ${t.label}`,
      `${err.message}\n\nTried ${t.secure ? "https" : "http"}://${address}:${t.port} (rule ${rule.label}).` +
        (isLocalName(t.hostname) ? "\nIs the local dev server running?" : ""));
  });

  req.on("error", () => proxyReq.destroy());
  res.on("close", () => proxyReq.destroy());
  req.pipe(proxyReq);
}

/** WebSocket and other Upgrade requests: same routing, raw socket splice. */
async function onUpgrade(config, secure, req, clientSocket, head) {
  const site = pickSite(config, req);
  const url = site ? new URL(req.url, site.publicOrigin) : null;
  const rule = site?.rules.find((r) => ruleMatches(r, req, url));
  if (!rule) return clientSocket.destroy();

  const t = rule.target;
  let address;
  try {
    address = await resolveHost(t);
  } catch {
    return clientSocket.destroy();
  }

  const lib = t.secure ? https : http;
  const proxyReq = lib.request({
    host: address,
    port: t.port,
    method: req.method,
    path: outboundPath(rule, url),
    headers: {
      ...forwardHeaders(req, site, rule, secure, req.socket.remoteAddress ?? "127.0.0.1"),
      connection: "Upgrade",
      upgrade: req.headers.upgrade,
    },
    // Never pool an upgraded connection: it stops being HTTP after the 101.
    agent: false,
    setHost: false,
    ...(t.secure
      ? {
          servername: net.isIP(t.hostname) ? undefined : t.hostname,
          rejectUnauthorized: !(t.insecure || CLI.insecure),
        }
      : {}),
  });

  proxyReq.on("upgrade", (upstreamRes, upstreamSocket, upstreamHead) => {
    if (!CLI.quiet)
      console.log(
        `${green("101")} ${req.method.padEnd(6)} ${req.url}  ${dim("⇢")} ${blue("ws")} ${dim(t.label)}`,
      );
    clientSocket.setNoDelay(true);
    upstreamSocket.setNoDelay(true);
    const lines = [`HTTP/1.1 101 ${upstreamRes.statusMessage || "Switching Protocols"}`];
    for (const [k, v] of Object.entries(upstreamRes.headers)) {
      for (const one of [].concat(v)) lines.push(`${k}: ${one}`);
    }
    clientSocket.write(lines.join("\r\n") + "\r\n\r\n");
    if (upstreamHead?.length) clientSocket.write(upstreamHead);
    if (head?.length) upstreamSocket.write(head);
    upstreamSocket.pipe(clientSocket);
    clientSocket.pipe(upstreamSocket);
    const bye = () => {
      upstreamSocket.destroy();
      clientSocket.destroy();
    };
    upstreamSocket.on("error", bye).on("close", bye);
    clientSocket.on("error", bye).on("close", bye);
  });

  proxyReq.on("response", (upstreamRes) => {
    // Upstream declined the upgrade — pass its answer through and hang up.
    clientSocket.write(`HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage}\r\n\r\n`);
    clientSocket.destroy();
  });
  proxyReq.on("error", (err) => {
    if (!CLI.quiet) warn(`upgrade to ${t.label} failed: ${err.message}`);
    clientSocket.destroy();
  });
  clientSocket.on("error", () => proxyReq.destroy());
  proxyReq.end();
}

/* ----------------------------------------------------------------- serving */

function loadSecureContext(site) {
  for (const f of [site.cert, site.key]) {
    if (!fs.existsSync(f))
      die(
        `site "${site.name}": missing ${f}\n` +
          `  run:  node ${path.relative(process.cwd(), fileURLToPath(import.meta.url))} --certs`,
      );
  }
  const cert = fs.readFileSync(site.cert);
  const key = fs.readFileSync(site.key);
  return { context: tls.createSecureContext({ cert, key }), cert, key };
}

function groupBy(sites, pick) {
  const out = new Map();
  for (const s of sites) {
    const port = pick(s);
    if (!port) continue;
    if (!out.has(port)) out.set(port, []);
    out.get(port).push(s);
  }
  return out;
}

function listen(server, port, label) {
  return new Promise((resolve) => {
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE")
        die(`port ${port} is already in use — stop whatever is on it, or change "listen" in the config`);
      if (err.code === "EACCES")
        die(`port ${port} needs root: run with sudo, or set "listen" above 1024 in the config`);
      die(`${label}: ${err.message}`);
    });
    server.listen(port, "0.0.0.0", resolve);
  });
}

/**
 * Root is only needed to bind :80/:443. Once that is done we hand the process
 * back to the invoking user so nothing it touches later runs privileged.
 */
function dropPrivileges() {
  if (process.getuid?.() !== 0 || !process.env.SUDO_UID) return;
  try {
    process.setgid(Number(process.env.SUDO_GID));
    process.setuid(Number(process.env.SUDO_UID));
    say(dim(`   dropped root → uid ${process.getuid()}`));
  } catch (e) {
    warn(`could not drop root privileges: ${e.message}`);
  }
}

async function run(config, filter) {
  const sites = config.sites.filter(
    (s) => s.enabled && (!filter || s.name === filter || s.host === filter),
  );
  if (!sites.length) die(`no enabled site matches "${filter}"`);

  const servers = [];
  for (const [port, group] of groupBy(sites, (s) => s.httpsPort)) {
    const contexts = new Map();
    for (const site of group) {
      const loaded = loadSecureContext(site);
      for (const h of site.allHosts) contexts.set(h, loaded.context);
      site.loadedCert = loaded;
    }
    const fallback = group[0].loadedCert;
    const server = https.createServer({
      cert: fallback.cert,
      key: fallback.key,
      // One port can serve many hostnames; SNI decides which cert to present.
      SNICallback: (servername, cb) =>
        cb(null, contexts.get(String(servername).toLowerCase()) ?? fallback.context),
    });
    server.on("request", (req, res) => onRequest(config, true, req, res));
    server.on("upgrade", (req, socket, head) => onUpgrade(config, true, req, socket, head));
    await listen(server, port, `https:${port}`);
    servers.push(server);
  }

  for (const port of groupBy(sites, (s) => s.httpPort).keys()) {
    const server = http.createServer();
    server.on("request", (req, res) => onRequest(config, false, req, res));
    server.on("upgrade", (req, socket, head) => onUpgrade(config, false, req, socket, head));
    await listen(server, port, `http:${port}`);
    servers.push(server);
  }

  dropPrivileges();

  say("");
  for (const site of sites) {
    say(`${bold(site.publicOrigin)}  ${dim(`(${site.name})`)}`);
    for (const rule of site.rules) {
      const kind = rule.target === site.upstreamTarget ? magenta("upstream") : blue("local");
      say(`   ${String(rule.label).padEnd(14)} ${dim("→")} ${kind} ${rule.target.label}`);
    }
    if (site.httpPort) say(dim(`   :${site.httpPort} ${site.httpMode === "redirect" ? "→ https" : "→ proxied"}`));
  }
  say("");
  say(dim("ctrl-c to stop"));

  const stop = () => {
    say("");
    for (const s of servers) s.close();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

/* ----------------------------------------------------------------- doctor */

const tick = (ok) => (ok ? green("✓") : red("✗"));

function tcpProbe(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const done = (ok, msg) => {
      socket.destroy();
      resolve({ ok, msg });
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => done(true));
    socket.on("timeout", () => done(false, "timed out"));
    socket.on("error", (e) => done(false, e.code ?? e.message));
  });
}

function portFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", (e) => resolve({ free: false, code: e.code }));
    server.once("listening", () => server.close(() => resolve({ free: true })));
    server.listen(port, "0.0.0.0");
  });
}

function tlsProbe(address, port, servername, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: address, port, servername, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      socket.destroy();
      resolve({ ok: true, authorized, subject: cert?.subject?.CN, issuer: cert?.issuer?.O });
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve({ ok: false, msg: "timed out" });
    });
    socket.on("error", (e) => resolve({ ok: false, msg: e.code ?? e.message }));
  });
}

function hostsEntries() {
  const map = new Map();
  if (!fs.existsSync(HOSTS_FILE)) return map;
  for (const line of fs.readFileSync(HOSTS_FILE, "utf8").split("\n")) {
    const clean = line.replace(/#.*$/, "").trim();
    if (!clean) continue;
    const [ip, ...names] = clean.split(/\s+/);
    for (const n of names) map.set(n.toLowerCase(), ip);
  }
  return map;
}

async function doctor(config, filter) {
  const sites = config.sites.filter((s) => !filter || s.name === filter || s.host === filter);
  const hosts = hostsEntries();
  let problems = 0;
  const bad = () => problems++;

  say(bold(`\ndevproxy doctor  ${dim(config.file)}\n`));

  for (const site of sites) {
    say(bold(`\n${site.name}  ${dim(site.publicOrigin)}`));

    for (const host of site.allHosts) {
      const ip = hosts.get(host);
      const ok = ip === "127.0.0.1" || ip === "::1";
      say(`  ${tick(ok)} /etc/hosts — ${host} → ${ip ?? red("not mapped")}`);
      if (!ok) {
        bad();
        say(dim(`      fix: sudo node proxy.mjs --hosts-write`));
      }
    }

    if (site.httpsPort) {
      const haveCert = fs.existsSync(site.cert) && fs.existsSync(site.key);
      if (!haveCert) {
        say(`  ${tick(false)} certificate — missing ${path.basename(site.cert)}`);
        say(dim(`      fix: node proxy.mjs --certs`));
        bad();
      } else {
        try {
          const x = new X509Certificate(fs.readFileSync(site.cert));
          const expires = new Date(x.validTo);
          const live = expires > new Date();
          const names = (x.subjectAltName ?? "")
            .split(",")
            .map((s) => s.trim().replace(/^DNS:/, "").toLowerCase());
          const covers = site.allHosts.every((h) => names.includes(h));
          say(`  ${tick(live && covers)} certificate — ${covers ? "covers" : red("does not cover")} ${site.allHosts.join(", ")}, ${live ? `valid until ${expires.toISOString().slice(0, 10)}` : red("EXPIRED")}`);
          if (!live || !covers) bad();
        } catch (e) {
          say(`  ${tick(false)} certificate — unreadable: ${e.message}`);
          bad();
        }
      }
    }

    for (const port of [site.httpsPort, site.httpPort].filter(Boolean)) {
      const { free, code } = await portFree(port);
      // Binding 0.0.0.0 succeeds even when another process holds 127.0.0.1 on
      // the same port — and that one wins for browser traffic. So also knock.
      const answered = await tcpProbe("127.0.0.1", port, 700);
      const ok = free && !answered.ok;
      say(
        `  ${tick(ok)} port ${port} — ${
          !free
            ? code === "EACCES"
              ? "needs root on this system — run the proxy with sudo"
              : `${code} (something else is listening)`
            : answered.ok
              ? "a loopback-only listener already answers here and would win"
              : "free"
        }`,
      );
      if (!ok) bad();
    }

    const targets = new Map();
    for (const rule of site.rules) targets.set(rule.target.label, rule.target);
    for (const t of targets.values()) {
      let address;
      try {
        address = await resolveHost(t);
      } catch (e) {
        say(`  ${tick(false)} ${t.label} — ${e.message}`);
        bad();
        continue;
      }
      const via = t.resolve === "dns" ? dim(` (DNS: ${address})`) : "";
      const probe = await tcpProbe(address, t.port);
      if (!probe.ok) {
        say(`  ${tick(false)} ${t.label}${via} — ${probe.msg}`);
        say(dim(isLocalName(t.hostname) ? "      is the dev server running?" : "      is the host reachable (VPN)?"));
        bad();
        continue;
      }
      if (t.secure) {
        const h = await tlsProbe(address, t.port, net.isIP(t.hostname) ? undefined : t.hostname);
        const ok = h.ok && (h.authorized || t.insecure || CLI.insecure);
        say(`  ${tick(ok)} ${t.label}${via} — ${h.ok ? `TLS ${h.authorized ? "valid" : red("not trusted")}${h.subject ? dim(` (CN=${h.subject})`) : ""}` : h.msg}`);
        if (!ok) bad();
      } else {
        say(`  ${tick(true)} ${t.label}${via} — reachable`);
      }
    }
  }

  say("");
  if (problems) {
    say(red(`${problems} problem${problems === 1 ? "" : "s"} above.`));
    process.exitCode = 1;
  } else {
    say(green("all checks passed."));
  }
}

/* ------------------------------------------------------------------ certs */

function makeCerts(config, filter) {
  const probe = spawnSync("mkcert", ["-version"], { encoding: "utf8" });
  if (probe.error) die("mkcert is not installed — brew install mkcert && mkcert -install");

  const root = spawnSync("mkcert", ["-CAROOT"], { encoding: "utf8" }).stdout?.trim();
  if (!root || !fs.existsSync(path.join(root, "rootCA.pem")))
    die("mkcert has no local CA yet — run: mkcert -install");

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
      for (const f of [site.cert, site.key])
        fs.chownSync(f, Number(process.env.SUDO_UID), Number(process.env.SUDO_GID));
    }
    say(`${green("✓")} ${site.host} — certificate written to ${site.cert}`);
  }
}

/* ------------------------------------------------------------------ hosts */

function hostsBlock(config) {
  const lines = config.sites
    .filter((s) => s.enabled)
    .flatMap((s) => s.allHosts.map((h) => `127.0.0.1\t${h}`));
  const v6 = config.sites
    .filter((s) => s.enabled)
    .flatMap((s) => s.allHosts.map((h) => `::1\t\t${h}`));
  return [MARK_START, ...lines, ...v6, MARK_END].join("\n");
}

function rewriteHostsFile(nextBlock) {
  if (process.getuid?.() !== 0) die(`editing ${HOSTS_FILE} needs root — rerun with sudo`);
  const current = fs.readFileSync(HOSTS_FILE, "utf8");
  const stripped = current.replace(
    new RegExp(`\\n?${MARK_START}[\\s\\S]*?${MARK_END}\\n?`, "g"),
    "\n",
  );
  const next = nextBlock ? `${stripped.replace(/\n+$/, "")}\n\n${nextBlock}\n` : stripped;
  fs.copyFileSync(HOSTS_FILE, `${HOSTS_FILE}.devproxy.bak`);
  fs.writeFileSync(HOSTS_FILE, next);
  spawnSync("dscacheutil", ["-flushcache"], { stdio: "ignore" });
  spawnSync("killall", ["-HUP", "mDNSResponder"], { stdio: "ignore" });
  say(`${green("✓")} ${HOSTS_FILE} updated (backup: ${HOSTS_FILE}.devproxy.bak), DNS cache flushed`);
}

/* ------------------------------------------------------------------- main */

const HELP = `
devproxy — serve a real hostname from your machine, split between a local dev
server and the real deployment.

  node proxy.mjs [options]

  -c, --config <file>   config file (default: devproxy.config.json next to this script)
  -s, --site <name>     only this site (name or host)
      --doctor          check hosts file, certificates, ports and targets, then exit
      --certs           create any missing certificates with mkcert, then exit
      --hosts           print the /etc/hosts lines this config needs
      --hosts-write     add or update the devproxy block in /etc/hosts (needs sudo)
      --hosts-remove    remove the devproxy block from /etc/hosts (needs sudo)
      --insecure        do not verify upstream TLS certificates
  -v, --verbose         log the outbound URL of every request
  -q, --quiet           errors only
  -h, --help            this text

First run:
  brew install mkcert && mkcert -install
  node proxy.mjs --certs
  sudo node proxy.mjs --hosts-write    # the only step that needs root
  node proxy.mjs
`;

function parseArgv(argv) {
  const opts = {
    config: path.join(HERE, "devproxy.config.json"),
    site: null,
    command: "run",
    verbose: false,
    quiet: false,
    insecure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-c" || a === "--config") opts.config = path.resolve(argv[++i] ?? "");
    else if (a === "-s" || a === "--site") opts.site = argv[++i] ?? null;
    else if (a === "--doctor") opts.command = "doctor";
    else if (a === "--certs") opts.command = "certs";
    else if (a === "--hosts") opts.command = "hosts";
    else if (a === "--hosts-write") opts.command = "hosts-write";
    else if (a === "--hosts-remove") opts.command = "hosts-remove";
    else if (a === "-v" || a === "--verbose") opts.verbose = true;
    else if (a === "-q" || a === "--quiet") opts.quiet = true;
    else if (a === "--insecure") opts.insecure = true;
    else if (a === "-h" || a === "--help") opts.command = "help";
    else die(`unknown option "${a}" — try --help`);
  }
  return opts;
}

const opts = parseArgv(process.argv.slice(2));
CLI = { verbose: opts.verbose, quiet: opts.quiet, insecure: opts.insecure };

if (opts.command === "help") {
  console.log(HELP);
  process.exit(0);
}

const config = loadConfig(opts.config);

switch (opts.command) {
  case "doctor":
    await doctor(config, opts.site);
    break;
  case "certs":
    makeCerts(config, opts.site);
    break;
  case "hosts":
    console.log(hostsBlock(config));
    break;
  case "hosts-write":
    rewriteHostsFile(hostsBlock(config));
    break;
  case "hosts-remove":
    rewriteHostsFile(null);
    break;
  default:
    await run(config, opts.site);
}
