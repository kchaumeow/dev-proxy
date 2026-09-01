/**
 * Reading devproxy.config.json and turning it into the normalized `Config` the
 * rest of the proxy uses. Every default is applied here, so no other module
 * needs to know what a missing field means.
 */

import fs from "node:fs";
import path from "node:path";
import { die } from "./log.ts";
import { isIpLiteral, isLocalName } from "./constants.ts";
import type {
  Config,
  HeaderOverrides,
  RawConfig,
  RawRule,
  RawSite,
  RawTarget,
  RawTargetSpec,
  Rule,
  Site,
  Target,
} from "./types.ts";

/**
 * Strips // and block comments from JSON so the config file can explain
 * itself. String contents (and thus every "http://..." URL) are left alone.
 */
export function stripJsonComments(src: string): string {
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

/** Headers are matched case-insensitively everywhere, so normalize on the way in. */
function lowerKeys(obj: HeaderOverrides | undefined): HeaderOverrides {
  const out: HeaderOverrides = {};
  for (const [k, v] of Object.entries(obj ?? {})) out[k.toLowerCase()] = v;
  return out;
}

/** A target is where a matched request is sent: a URL plus how to reach it. */
export function parseTarget(spec: RawTargetSpec | undefined, site: Site): Target {
  if (spec === "upstream") {
    if (!site.upstreamTarget) {
      die(`site "${site.name}": a rule targets "upstream" but the site defines no upstream`);
    }
    return site.upstreamTarget;
  }
  const o: RawTarget = typeof spec === "string" ? { url: spec } : { ...(spec ?? {}) };
  if (!o.url) die(`site "${site.name}": a rule has no target url`);

  let url: URL;
  try {
    url = new URL(o.url);
  } catch {
    return die(`site "${site.name}": invalid target url "${o.url}"`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    die(`site "${site.name}": target "${o.url}" must be http: or https:`);
  }

  // An IPv6 hostname arrives bracketed from the URL parser; net/dns want it bare.
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
    resolve: o.resolve ?? (local || isIpLiteral(hostname) ? "system" : "dns"),
    // Real upstreams need the browser's Host (vhost routing, CORS checks and
    // cookie domains all key off it). Local dev servers usually reject an
    // unfamiliar Host — Vite's server.allowedHosts — and never need it.
    preserveHost: o.preserveHost ?? !local,
    insecure: o.insecure ?? false,
    headers: lowerKeys(o.headers),
  };
}

function parseRule(raw: RawRule | undefined, site: Site, idx: number): Rule {
  if (!raw || typeof raw !== "object") {
    die(`site "${site.name}": rule ${idx + 1} is not an object`);
  }
  if (raw.path == null && !raw.regex) {
    die(`site "${site.name}": rule ${idx + 1} needs a "path" or a "regex"`);
  }
  return {
    path: raw.path ?? null,
    regex: raw.regex ? new RegExp(raw.regex) : null,
    methods: raw.methods ? raw.methods.map((m) => m.toUpperCase()) : null,
    stripPath: raw.stripPath === true,
    rewrite: raw.rewrite ? { from: new RegExp(raw.rewrite.from), to: raw.rewrite.to } : null,
    headers: lowerKeys(raw.headers),
    target: parseTarget(raw.target, site),
    label: raw.regex ? `~${raw.regex}` : (raw.path ?? "/"),
  };
}

function normalizeSite(raw: RawSite, idx: number, dir: string, root: RawConfig): Site {
  if (!raw.host) die(`site ${idx + 1} has no "host"`);

  const host = String(raw.host).toLowerCase();
  const aliases = (raw.aliases ?? []).map((h) => String(h).toLowerCase());
  const listen = raw.listen ?? {};
  const httpsPort = listen.https === false ? null : Number(listen.https ?? 443);
  const httpPort = listen.http === false ? null : Number(listen.http ?? 80);

  const certDir = path.resolve(dir, raw.certDir ?? root.certDir ?? "certs");

  // `site` is assembled in two steps because parseTarget needs a Site to name
  // in its error messages, and an "upstream" rule needs upstreamTarget to
  // already be set. Neither reads the rules, so the order is safe.
  const site: Site = {
    host,
    name: raw.name ?? host,
    enabled: raw.enabled !== false,
    aliases,
    allHosts: [host, ...aliases],
    httpsPort,
    httpPort,
    // What plain HTTP does: send the browser to https (default) or proxy as-is.
    httpMode: listen.httpMode ?? "redirect",
    cert: path.resolve(certDir, raw.cert ?? `${host}.pem`),
    key: path.resolve(certDir, raw.key ?? `${host}-key.pem`),
    publicOrigin: httpsPort
      ? `https://${host}${httpsPort === 443 ? "" : `:${httpsPort}`}`
      : `http://${host}${httpPort === 80 ? "" : `:${httpPort}`}`,
    // "auto" keeps a Domain= the browser would accept on this origin and drops
    // one it would reject; false leaves Set-Cookie untouched; a string forces it.
    cookieDomain: raw.cookieDomain ?? "auto",
    // HSTS from the real host would outlive this session and force https on the
    // hostname long after the proxy is gone, so it goes by default.
    stripResponseHeaders: (raw.stripResponseHeaders ?? ["strict-transport-security"]).map((h) =>
      h.toLowerCase(),
    ),
    upstreamTarget: null,
    rules: [],
  };

  if (raw.upstream) {
    if (raw.upstream === "upstream") die(`site "${site.name}": upstream cannot be "upstream"`);
    site.upstreamTarget = parseTarget(raw.upstream, site);
  }
  site.rules = (raw.rules ?? []).map((r, i) => parseRule(r, site, i));
  if (!site.rules.length) die(`site "${site.name}" has no rules`);
  return site;
}

export function loadConfig(file: string): Config {
  if (!fs.existsSync(file)) die(`config not found: ${file}`);

  let raw: RawConfig;
  try {
    // The file is user-written JSON, so this cast is a claim, not a proof —
    // normalizeSite and parseTarget do the field-level checking that follows.
    raw = JSON.parse(stripJsonComments(fs.readFileSync(file, "utf8"))) as RawConfig;
  } catch (e) {
    die(`config is not valid JSON (${file}): ${e instanceof Error ? e.message : String(e)}`);
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    die(`config must be a JSON object (${file})`);
  }

  const dir = path.dirname(file);
  const sites = (raw.sites ?? []).map((s, i) => normalizeSite(s, i, dir, raw));
  if (!sites.length) die(`config has no sites: ${file}`);

  const byHost = new Map<string, Site>();
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
