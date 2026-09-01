/**
 * Deciding which rule handles a request, and what path it gets forwarded to.
 */

import type { IncomingMessage } from "node:http";
import type { Rule, Site } from "./types.ts";

/** Prefix match on path segments: /api matches /api and /api/x, never /apix. */
export function pathMatches(prefix: string | null, pathname: string): boolean {
  if (!prefix || prefix === "/") return true;
  const p = prefix.replace(/\/+$/, "");
  return pathname === p || pathname.startsWith(p + "/");
}

export function ruleMatches(rule: Rule, req: IncomingMessage, url: URL): boolean {
  if (rule.methods && (!req.method || !rule.methods.includes(req.method))) return false;
  if (rule.regex) return rule.regex.test(url.pathname);
  return pathMatches(rule.path, url.pathname);
}

/** Ordered: first match wins, so specific paths belong above the catch-all. */
export const findRule = (site: Site, req: IncomingMessage, url: URL): Rule | undefined =>
  site.rules.find((r) => ruleMatches(r, req, url));

/** The path sent upstream: prefix stripped, regex rewrite applied, base added. */
export function outboundPath(rule: Rule, url: URL): string {
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
