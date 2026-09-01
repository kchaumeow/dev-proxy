/**
 * Finding the address to connect to — the piece the whole proxy depends on.
 */

import dnsp from "node:dns/promises";
import { isIpLiteral } from "./constants.ts";
import { dim, errMessage, say } from "./log.ts";
import type { Target } from "./types.ts";

interface CacheEntry {
  address: string;
  expires: number;
}

const dnsCache = new Map<string, CacheEntry>();

/** Keeps a record's own TTL, clamped so neither extreme is honoured literally. */
const TTL_MIN_SECONDS = 10;
const TTL_MAX_SECONDS = 300;

/**
 * Returns the address to connect to. For "dns" targets this deliberately uses
 * dns.resolve4/6, which query the configured nameservers and ignore
 * /etc/hosts — the whole reason the proxy can serve a hostname it also calls.
 * A VPN's DNS still works; only the local override is bypassed.
 */
export async function resolveHost(target: Target): Promise<string> {
  if (target.ip) return target.ip;
  if (target.resolve === "system") return target.hostname;

  const hit = dnsCache.get(target.hostname);
  if (hit && hit.expires > Date.now()) return hit.address;

  let address: string | undefined;
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
    expires: Date.now() + Math.min(Math.max(ttl, TTL_MIN_SECONDS), TTL_MAX_SECONDS) * 1000,
  });
  // Only the first lookup is worth a line; the refreshes are noise.
  if (!hit) say(dim(`   dns  ${target.hostname} → ${address}`));
  return address;
}

/** Same as resolveHost, but reports the failure instead of throwing. */
export async function tryResolveHost(
  target: Target,
): Promise<{ address: string } | { error: string }> {
  try {
    return { address: await resolveHost(target) };
  } catch (e) {
    return { error: errMessage(e) };
  }
}

const isDefaultPort = (t: Target): boolean => t.port === (t.secure ? 443 : 80);

/** The target's own origin, used when rewriting Origin/Referer away from ours. */
export const targetOrigin = (t: Target): string =>
  `${t.secure ? "https" : "http"}://${t.hostname}${isDefaultPort(t) ? "" : `:${t.port}`}`;

/** The Host header a target expects when it is not given the browser's. */
export const targetHostHeader = (t: Target): string =>
  `${t.hostname}${isDefaultPort(t) ? "" : `:${t.port}`}`;

/**
 * SNI has to be a name, never an address: connecting by IP means the real host
 * only serves the right certificate if we tell it which name we asked for.
 */
export const sniName = (t: Target): string | undefined =>
  isIpLiteral(t.hostname) ? undefined : t.hostname;
