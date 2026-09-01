/** Fixed values and the handful of predicates that read them. */

import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const HOSTS_FILE = "/etc/hosts";
export const MARK_START = "# >>> devproxy >>>";
export const MARK_END = "# <<< devproxy <<<";

/** The repository root: this file lives in src/, one level down. */
export const PROJECT_ROOT = path.resolve(fileURLToPath(import.meta.url), "..", "..");

/** The entry script, as a path worth printing in a "run this" hint. */
export const ENTRY = path.join(PROJECT_ROOT, "proxy.ts");
export const entryHint = (): string => path.relative(process.cwd(), ENTRY) || "proxy.ts";

/**
 * Hop-by-hop headers belong to a single connection and must never be forwarded
 * (RFC 9110 7.6.1). Passing transfer-encoding on in particular corrupts the
 * response, because Node has already decoded the chunking for us.
 */
export const HOP_BY_HOP: ReadonlySet<string> = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const LOCAL_NAMES: ReadonlySet<string> = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
  "host.docker.internal",
]);

/**
 * A local name never needs the DNS bypass (nothing in /etc/hosts points it at
 * us) and never wants the browser's Host header.
 */
export const isLocalName = (host: string): boolean =>
  LOCAL_NAMES.has(host) || host.endsWith(".localhost");

/** A literal IP address needs no resolution and no SNI name. */
export const isIpLiteral = (host: string): boolean => net.isIP(host) !== 0;
