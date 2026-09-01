/**
 * Header surgery in both directions.
 *
 * The browser must keep believing it is talking to the public origin, and each
 * target must keep believing it is being addressed the way it expects. Bodies
 * are never touched, so compression and streaming pass straight through.
 */

import type { IncomingHttpHeaders, IncomingMessage, OutgoingHttpHeaders } from "node:http";
import { HOP_BY_HOP } from "./constants.ts";
import { targetHostHeader, targetOrigin } from "./resolve.ts";
import type { Rule, Site, Target } from "./types.ts";

/**
 * Headers mid-edit. Wider than Node's outgoing type because a config override
 * may be `null` ("drop this header"), which is resolved before returning.
 */
type DraftHeaders = Record<string, string | string[] | number | null | undefined>;

function finalize(draft: DraftHeaders): OutgoingHttpHeaders {
  const out: OutgoingHttpHeaders = {};
  // An explicit null in the config means "do not send this header at all".
  for (const [k, v] of Object.entries(draft)) if (v != null) out[k] = v;
  return out;
}

export function forwardHeaders(
  req: IncomingMessage,
  site: Site,
  rule: Rule,
  secure: boolean,
  remoteAddr: string,
): OutgoingHttpHeaders {
  const t = rule.target;
  const h: DraftHeaders = { ...req.headers };
  for (const k of Object.keys(h)) if (HOP_BY_HOP.has(k)) delete h[k];

  const clientHost = req.headers.host ?? site.host;
  h.host = t.preserveHost ? clientHost : targetHostHeader(t);

  // Origin and Referer follow Host: a dev server that validates them shouldn't
  // see a public origin it knows nothing about, while a real upstream must see
  // exactly the origin the browser is on or its CORS check fails.
  if (!t.preserveHost) {
    const from = site.publicOrigin;
    const to = targetOrigin(t);
    const { origin, referer } = req.headers;
    if (origin && origin === from) h.origin = to;
    if (referer && referer.startsWith(from)) h.referer = to + referer.slice(from.length);
  }

  const forwardedFor = req.headers["x-forwarded-for"];
  h["x-forwarded-for"] = forwardedFor ? `${forwardedFor}, ${remoteAddr}` : remoteAddr;
  h["x-forwarded-host"] = clientHost;
  h["x-forwarded-proto"] = secure ? "https" : "http";
  h["x-forwarded-port"] = String(secure ? site.httpsPort : site.httpPort);
  h["x-real-ip"] = remoteAddr;

  // Target headers first, then the rule's — the more specific one wins.
  Object.assign(h, t.headers, rule.headers);
  return finalize(h);
}

export function swapOrigin(value: string, from: string, to: string): string {
  return value.startsWith(from) ? to + value.slice(from.length) : value;
}

/** Sends a redirect back to the public origin instead of leaking the target. */
export function rewriteLocation(loc: string, site: Site, t: Target): string {
  let u: URL;
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
  if (t.basePath && pathname.startsWith(t.basePath)) {
    pathname = pathname.slice(t.basePath.length) || "/";
  }
  return `${site.publicOrigin}${pathname}${u.search}${u.hash}`;
}

const cookieDomainAccepted = (host: string, attr: string): boolean => {
  const d = attr.trim().replace(/^\./, "").toLowerCase();
  return host === d || host.endsWith("." + d);
};

/**
 * A Domain= the browser rejects silently drops the whole cookie, which looks
 * exactly like a broken login. Dropping the attribute instead makes the cookie
 * host-only for this origin, which is what a dev session wants.
 */
export function rewriteCookies(values: string[], site: Site): string[] {
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

export function responseHeaders(
  upstreamHeaders: IncomingHttpHeaders,
  site: Site,
  t: Target,
): OutgoingHttpHeaders {
  const out: OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(upstreamHeaders)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    if (site.stripResponseHeaders.includes(key)) continue;
    out[key] = v;
  }

  const location = out.location;
  if (typeof location === "string") out.location = rewriteLocation(location, site, t);

  const setCookie = out["set-cookie"];
  if (setCookie) out["set-cookie"] = rewriteCookies([setCookie].flat().map(String), site);

  const acao = out["access-control-allow-origin"];
  if (acao && acao !== "*") {
    out["access-control-allow-origin"] = swapOrigin(
      String(acao),
      targetOrigin(t),
      site.publicOrigin,
    );
  }
  return out;
}
