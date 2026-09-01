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
 * No runtime dependencies: Node strips the types and runs this file directly.
 * TypeScript is a dev-time checker only — `npm run typecheck`. Node >= 22.18.
 *
 * This file is the entry point; everything it calls lives in src/.
 */

import path from "node:path";
import { PROJECT_ROOT } from "./src/constants.ts";
import { die, setCli } from "./src/log.ts";
import { loadConfig } from "./src/config.ts";
import { doctor } from "./src/doctor.ts";
import { makeCerts } from "./src/certs.ts";
import { hostsBlock, rewriteHostsFile } from "./src/hosts.ts";
import { run } from "./src/serve.ts";

const HELP = `
devproxy — serve a real hostname from your machine, split between a local dev
server and the real deployment.

  node proxy.ts [options]

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
  node proxy.ts --certs
  sudo node proxy.ts --hosts-write     # the only step that needs root
  node proxy.ts
`;

/** A union rather than an enum: enums are not erasable, so Node cannot run them. */
type Command = "run" | "doctor" | "certs" | "hosts" | "hosts-write" | "hosts-remove" | "help";

interface Options {
  config: string;
  site: string | null;
  command: Command;
  verbose: boolean;
  quiet: boolean;
  insecure: boolean;
}

export function parseArgv(argv: string[]): Options {
  const opts: Options = {
    config: path.join(PROJECT_ROOT, "devproxy.config.json"),
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
setCli({ verbose: opts.verbose, quiet: opts.quiet, insecure: opts.insecure });

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
  case "run":
    await run(config, opts.site);
    break;
}
