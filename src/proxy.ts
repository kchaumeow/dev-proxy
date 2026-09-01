/**
 * The request path: pick a site, pick a rule, resolve the target, stream it
 * through. Also the Upgrade path, which routes identically but splices raw
 * sockets once the 101 comes back.
 */

import http from "node:http";
import https from "node:https";
import type { ClientRequest, IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import { isLocalName } from "./constants.ts";
import { blue, cli, dim, errCode, green, magenta, red, say, statusColor, warn } from "./log.ts";
import { findRule, outboundPath } from "./match.ts";
import { resolveHost, sniName } from "./resolve.ts";
import { forwardHeaders, responseHeaders } from "./rewrite.ts";
import type { Config, Rule, Site, Target } from "./types.ts";

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

function logRequest(
  site: Site | null,
  rule: Rule | null,
  req: IncomingMessage,
  status: number,
  ms: number,
  note?: string,
): void {
  if (cli.quiet) return;
  const via = rule
    ? rule.target === site?.upstreamTarget
      ? magenta("upstream")
      : blue("local")
    : dim("—");
  const where = rule ? dim(` ${rule.target.label}`) : "";
  const method = (req.method ?? "?").padEnd(6);
  console.log(
    `${statusColor(status)(String(status).padEnd(3))} ${method} ${req.url}  ${dim("⇢")} ` +
      `${via}${where} ${dim(`${ms}ms`)}${note ? ` ${red(note)}` : ""}`,
  );
}

export function sendError(
  res: ServerResponse,
  status: number,
  title: string,
  detail?: string,
): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  const body = `devproxy: ${title}\n\n${detail ?? ""}\n`;
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

/**
 * Which site a request belongs to. A single-site config answers to anything,
 * so the proxy still works when reached by IP or through a tunnel.
 */
export function pickSite(config: Config, req: IncomingMessage): Site | null {
  const host = String(req.headers.host ?? "")
    .split(":")[0]
    ?.toLowerCase();
  if (host) {
    const match = config.byHost.get(host);
    if (match) return match;
  }
  return config.sites.length === 1 ? (config.sites[0] ?? null) : null;
}

/** The request options shared by the normal and the Upgrade path. */
function outboundOptions(
  t: Target,
  address: string,
  method: string,
  path: string,
  headers: http.OutgoingHttpHeaders,
  agent: http.Agent | false,
): https.RequestOptions {
  const servername = sniName(t);
  return {
    host: address,
    port: t.port,
    method,
    path,
    headers,
    agent,
    // The Host header is built by forwardHeaders; Node must not overwrite it.
    setHost: false,
    ...(t.secure
      ? {
          // Connecting by IP, so SNI has to be named explicitly or the real
          // host serves the wrong certificate (or none).
          ...(servername ? { servername } : {}),
          rejectUnauthorized: !(t.insecure || cli.insecure),
        }
      : {}),
  };
}

const requestFor = (t: Target, options: https.RequestOptions): ClientRequest =>
  (t.secure ? https : http).request(options);

/**
 * Node types both ends of an upgrade as a bare Duplex, but a TCP socket is what
 * actually turns up — and Nagle's algorithm adds latency to every small WS frame.
 */
function disableNagle(s: Duplex): void {
  const maybe = s as Duplex & { setNoDelay?: (on: boolean) => void };
  maybe.setNoDelay?.(true);
}

export async function onRequest(
  config: Config,
  secure: boolean,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const started = Date.now();

  const site = pickSite(config, req);
  if (!site) {
    logRequest(null, null, req, 421, 0);
    return sendError(
      res,
      421,
      `no site configured for host "${req.headers.host}"`,
      `Configured hosts: ${[...config.byHost.keys()].join(", ")}`,
    );
  }

  if (!secure && site.httpsPort && site.httpMode === "redirect") {
    const location = `${site.publicOrigin}${req.url}`;
    res.writeHead(308, { location, "content-length": 0 });
    logRequest(site, null, req, 308, Date.now() - started);
    res.end();
    return;
  }

  let url: URL;
  try {
    url = new URL(req.url ?? "/", site.publicOrigin);
  } catch {
    return sendError(res, 400, `cannot parse request path "${req.url}"`);
  }

  const rule = findRule(site, req, url);
  if (!rule) {
    logRequest(site, null, req, 404, Date.now() - started);
    return sendError(
      res,
      404,
      `no rule in site "${site.name}" matches ${url.pathname}`,
      `Rules: ${site.rules.map((r) => `${r.label} → ${r.target.label}`).join("\n       ")}`,
    );
  }

  const t = rule.target;
  let address: string;
  try {
    address = await resolveHost(t);
  } catch (e) {
    logRequest(site, rule, req, 502, Date.now() - started, "dns");
    return sendError(
      res,
      502,
      `cannot resolve ${t.hostname}`,
      e instanceof Error ? e.message : String(e),
    );
  }

  const path = outboundPath(rule, url);
  const proxyReq = requestFor(
    t,
    outboundOptions(
      t,
      address,
      req.method ?? "GET",
      path,
      forwardHeaders(req, site, rule, secure, req.socket.remoteAddress ?? "127.0.0.1"),
      t.secure ? httpsAgent : httpAgent,
    ),
  );

  if (cli.verbose) {
    say(dim(`   → ${t.secure ? "https" : "http"}://${address}:${t.port}${path}`));
  }

  // A connect/idle limit until the response starts; cleared afterwards so
  // streaming responses (SSE, long polls) are never cut off.
  proxyReq.setTimeout(config.connectTimeoutMs, () => {
    proxyReq.destroy(new Error(`no response within ${config.connectTimeoutMs}ms`));
  });

  proxyReq.on("response", (upstream: IncomingMessage) => {
    proxyReq.setTimeout(0);
    const status = upstream.statusCode ?? 502;
    logRequest(site, rule, req, status, Date.now() - started);
    res.writeHead(status, responseHeaders(upstream.headers, site, t));
    upstream.pipe(res);
    res.on("close", () => upstream.destroy());
  });

  proxyReq.on("error", (err: Error) => {
    logRequest(site, rule, req, 502, Date.now() - started, errCode(err) ?? "error");
    sendError(
      res,
      502,
      `cannot reach ${t.label}`,
      `${err.message}\n\nTried ${t.secure ? "https" : "http"}://${address}:${t.port} ` +
        `(rule ${rule.label}).` +
        (isLocalName(t.hostname) ? "\nIs the local dev server running?" : ""),
    );
  });

  req.on("error", () => proxyReq.destroy());
  res.on("close", () => proxyReq.destroy());
  req.pipe(proxyReq);
}

/** WebSocket and other Upgrade requests: same routing, raw socket splice. */
export async function onUpgrade(
  config: Config,
  secure: boolean,
  req: IncomingMessage,
  clientSocket: Duplex,
  head: Buffer,
): Promise<void> {
  const site = pickSite(config, req);
  if (!site) {
    clientSocket.destroy();
    return;
  }

  let url: URL;
  try {
    url = new URL(req.url ?? "/", site.publicOrigin);
  } catch {
    clientSocket.destroy();
    return;
  }

  const rule = findRule(site, req, url);
  if (!rule) {
    clientSocket.destroy();
    return;
  }

  const t = rule.target;
  let address: string;
  try {
    address = await resolveHost(t);
  } catch {
    clientSocket.destroy();
    return;
  }

  const proxyReq = requestFor(
    t,
    outboundOptions(
      t,
      address,
      req.method ?? "GET",
      outboundPath(rule, url),
      {
        ...forwardHeaders(req, site, rule, secure, req.socket.remoteAddress ?? "127.0.0.1"),
        connection: "Upgrade",
        upgrade: req.headers.upgrade,
      },
      // Never pool an upgraded connection: it stops being HTTP after the 101.
      false,
    ),
  );

  type UpgradeArgs = [res: IncomingMessage, socket: Duplex, head: Buffer];
  proxyReq.on("upgrade", (...[upstreamRes, upstreamSocket, upstreamHead]: UpgradeArgs) => {
    if (!cli.quiet) {
      console.log(
        `${green("101")} ${(req.method ?? "?").padEnd(6)} ${req.url}  ${dim("⇢")} ` +
          `${blue("ws")} ${dim(t.label)}`,
      );
    }
    disableNagle(clientSocket);
    disableNagle(upstreamSocket);

    // Node hands back the parsed 101; the client is still waiting for the raw
    // bytes, so they have to be written out again by hand.
    const lines = [`HTTP/1.1 101 ${upstreamRes.statusMessage || "Switching Protocols"}`];
    for (const [k, v] of Object.entries(upstreamRes.headers)) {
      for (const one of [v].flat()) if (one != null) lines.push(`${k}: ${one}`);
    }
    clientSocket.write(lines.join("\r\n") + "\r\n\r\n");
    if (upstreamHead?.length) clientSocket.write(upstreamHead);
    if (head?.length) upstreamSocket.write(head);

    upstreamSocket.pipe(clientSocket);
    clientSocket.pipe(upstreamSocket);
    const bye = (): void => {
      upstreamSocket.destroy();
      clientSocket.destroy();
    };
    upstreamSocket.on("error", bye).on("close", bye);
    clientSocket.on("error", bye).on("close", bye);
  });

  proxyReq.on("response", (upstreamRes: IncomingMessage) => {
    // Upstream declined the upgrade — pass its answer through and hang up.
    clientSocket.write(
      `HTTP/1.1 ${upstreamRes.statusCode ?? 502} ${upstreamRes.statusMessage ?? ""}\r\n\r\n`,
    );
    clientSocket.destroy();
  });

  proxyReq.on("error", (err: Error) => {
    if (!cli.quiet) warn(`upgrade to ${t.label} failed: ${err.message}`);
    clientSocket.destroy();
  });
  clientSocket.on("error", () => proxyReq.destroy());
  proxyReq.end();
}
