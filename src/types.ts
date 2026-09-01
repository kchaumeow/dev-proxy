/**
 * The shapes the proxy works with.
 *
 * Two layers live here. The `Raw*` interfaces describe the JSON a user writes
 * in devproxy.config.json — everything optional, because everything has a
 * default. The rest describe what `loadConfig` hands back: defaults resolved,
 * paths made absolute, regexes compiled, ports turned into numbers. Nothing
 * downstream of config.ts ever sees a `Raw*` value.
 */

import type { SecureContext } from "node:tls";

/** How the address for a target is found. `dns` is what bypasses /etc/hosts. */
export type ResolveMode = "dns" | "system";

/** What plain HTTP does when the site also serves HTTPS. */
export type HttpMode = "redirect" | "proxy";

/**
 * `false` leaves Set-Cookie alone; `"auto"` keeps a Domain= the browser would
 * accept on this origin and drops one it would reject; any other string forces
 * that Domain=. The `string & {}` arm keeps "auto" in editor completions
 * instead of collapsing the whole union to `string`.
 */
export type CookieDomain = false | "auto" | (string & {});

/**
 * Header overrides from the config. An explicit `null` means "do not send this
 * header at all", which is why the value type is wider than Node's.
 */
export type HeaderOverrides = Record<string, string | string[] | null>;

/* ---------------------------------------------------------- the config file */

export interface RawTarget {
  url?: string;
  ip?: string;
  resolve?: ResolveMode;
  preserveHost?: boolean;
  insecure?: boolean;
  headers?: HeaderOverrides;
}

/** A target is either the literal string "upstream", a URL, or the long form. */
export type RawTargetSpec = string | RawTarget;

export interface RawRewrite {
  from: string;
  to: string;
}

export interface RawRule {
  path?: string;
  regex?: string;
  methods?: string[];
  stripPath?: boolean;
  rewrite?: RawRewrite;
  headers?: HeaderOverrides;
  target?: RawTargetSpec;
}

export interface RawListen {
  https?: number | false;
  http?: number | false;
  httpMode?: HttpMode;
}

export interface RawSite {
  name?: string;
  host?: string;
  aliases?: string[];
  enabled?: boolean;
  listen?: RawListen;
  certDir?: string;
  cert?: string;
  key?: string;
  upstream?: RawTargetSpec;
  cookieDomain?: CookieDomain;
  stripResponseHeaders?: string[];
  rules?: RawRule[];
}

export interface RawConfig {
  connectTimeoutMs?: number;
  certDir?: string;
  sites?: RawSite[];
}

/* ------------------------------------------------------------- what we build */

/** Where a matched request is sent, plus everything about how to get there. */
export interface Target {
  /** The URL as written in the config — what shows up in logs and errors. */
  label: string;
  secure: boolean;
  hostname: string;
  port: number;
  /** A base path from the target URL, prepended to every outbound path. */
  basePath: string;
  ip: string | null;
  resolve: ResolveMode;
  preserveHost: boolean;
  insecure: boolean;
  headers: HeaderOverrides;
}

export interface Rewrite {
  from: RegExp;
  to: string;
}

export interface Rule {
  path: string | null;
  regex: RegExp | null;
  methods: string[] | null;
  /** Drop the matched prefix before forwarding, for an upstream mounted elsewhere. */
  stripPath: boolean;
  rewrite: Rewrite | null;
  headers: HeaderOverrides;
  target: Target;
  /** How the rule is named in logs: the path, or `~` plus the regex. */
  label: string;
}

export interface Site {
  host: string;
  name: string;
  enabled: boolean;
  aliases: string[];
  /** `host` followed by every alias — the names this site answers to. */
  allHosts: string[];
  httpsPort: number | null;
  httpPort: number | null;
  httpMode: HttpMode;
  cert: string;
  key: string;
  /** The origin the browser is on, and the one every rewrite points back to. */
  publicOrigin: string;
  cookieDomain: CookieDomain;
  stripResponseHeaders: string[];
  upstreamTarget: Target | null;
  rules: Rule[];
}

export interface Config {
  file: string;
  sites: Site[];
  /** Every host and alias, mapped to the site that claims it. */
  byHost: Map<string, Site>;
  connectTimeoutMs: number;
}

/** A site's key pair, read once and reused for every TLS handshake. */
export interface LoadedCert {
  context: SecureContext;
  cert: Buffer;
  key: Buffer;
}

export interface CliFlags {
  verbose: boolean;
  quiet: boolean;
  insecure: boolean;
}
