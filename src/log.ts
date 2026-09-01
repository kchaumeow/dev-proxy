/**
 * Terminal output, colour, and the two ways this process reports trouble:
 * `warn`/`fail` for something survivable, `die` for something fatal.
 */

import type { CliFlags } from "./types.ts";

const TTY = process.stdout.isTTY;

/** Wraps a string in an ANSI colour, or leaves it alone when piped to a file. */
const c =
  (code: number) =>
  (s: string | number): string =>
    TTY ? `\x1b[${code}m${s}\x1b[0m` : String(s);

export const dim = c(2);
export const bold = c(1);
export const red = c(31);
export const green = c(32);
export const yellow = c(33);
export const blue = c(34);
export const magenta = c(35);
export const cyan = c(36);

/**
 * Flags every module reads. A single frozen-identity object rather than a
 * re-exported `let`, so importers keep seeing updates after `setCli`.
 */
export const cli: CliFlags = { verbose: false, quiet: false, insecure: false };

export function setCli(next: CliFlags): void {
  Object.assign(cli, next);
}

export const say = (...a: unknown[]): void => {
  if (!cli.quiet) console.log(...a);
};

export const warn = (...a: unknown[]): void => console.warn(yellow("!"), ...a);
export const fail = (...a: unknown[]): void => console.error(red("✗"), ...a);

/** Reports a fatal problem and leaves. The `never` return lets callers `return die(...)`. */
export function die(msg: string): never {
  fail(msg);
  process.exit(1);
}

export const tick = (ok: boolean): string => (ok ? green("✓") : red("✗"));

export function statusColor(code: number): (s: string | number) => string {
  if (code >= 500) return red;
  if (code >= 400) return yellow;
  if (code >= 300) return cyan;
  return green;
}

/* --------------------------------------------------- reading unknown errors */

/**
 * A `catch` binding is `unknown`, and Node's useful detail lives on `.code`
 * (ENOTFOUND, EADDRINUSE, ECONNREFUSED) rather than in the message.
 */
export function errCode(e: unknown): string | undefined {
  if (!(e instanceof Error)) return undefined;
  const { code } = e as Error & { code?: unknown };
  return typeof code === "string" ? code : undefined;
}

export function errMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/** What to show a user: the errno if there is one, else the message. */
export const errLabel = (e: unknown): string => errCode(e) ?? errMessage(e);
