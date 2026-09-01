/**
 * Running the real proxy in a child process and talking to it.
 *
 * The integration tests drive `node proxy.ts` rather than importing its
 * internals, so argument parsing, config loading, port binding and the request
 * path are all covered by the same assertions.
 */

import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { ChildProcess } from "node:child_process";
import type { AddressInfo } from "node:net";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PROJECT_ROOT = path.resolve(HERE, "..", "..");
export const ENTRY = path.join(PROJECT_ROOT, "proxy.ts");

/** Asks the OS for a port nothing is using. */
export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

/** Resolves once something accepts a connection on the port, or throws. */
async function waitForPort(port: number, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const open = await new Promise<boolean>((resolve) => {
      const socket = net.connect({ host: "127.0.0.1", port });
      const done = (ok: boolean): void => {
        socket.destroy();
        resolve(ok);
      };
      socket.setTimeout(400);
      socket.on("connect", () => done(true));
      socket.on("timeout", () => done(false));
      socket.on("error", () => done(false));
    });
    if (open) return;
    if (Date.now() > deadline) throw new Error(`nothing listening on ${port} after ${timeoutMs}ms`);
    await new Promise((r) => setTimeout(r, 60));
  }
}

export interface ProxyHandle {
  /** The config as written to disk, for tests that want to read it back. */
  configPath: string;
  log: () => string;
  stop: () => Promise<void>;
}

export interface StartOptions {
  /** Extra CLI arguments, e.g. ["-v"] or ["--insecure"]. */
  args?: string[];
  /** A port the proxy must be listening on before the promise resolves. */
  readyPort: number;
}

/**
 * Writes the config to a scratch directory, starts the proxy, and waits until
 * it is actually accepting connections.
 */
export async function startProxy(
  config: unknown,
  options: StartOptions,
): Promise<ProxyHandle> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "devproxy-test-"));
  const configPath = path.join(dir, "devproxy.config.json");
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

  let output = "";
  const child: ChildProcess = spawn(
    process.execPath,
    [ENTRY, "-c", configPath, ...(options.args ?? [])],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  child.stdout?.on("data", (d: Buffer) => (output += d.toString()));
  child.stderr?.on("data", (d: Buffer) => (output += d.toString()));

  const exited = new Promise<number>((resolve) => child.on("exit", (code) => resolve(code ?? -1)));

  try {
    await Promise.race([
      waitForPort(options.readyPort),
      exited.then((code) => {
        throw new Error(`proxy exited early (code ${code}):\n${output}`);
      }),
    ]);
  } catch (e) {
    child.kill("SIGKILL");
    fs.rmSync(dir, { recursive: true, force: true });
    throw e;
  }

  return {
    configPath,
    log: () => output,
    stop: async () => {
      child.kill("SIGTERM");
      await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
      if (child.exitCode === null) child.kill("SIGKILL");
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/* ---------------------------------------------------------------- the CLI */

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
  /** Both streams interleaved, for a single assertion on user-visible text. */
  output: string;
}

/**
 * Runs the CLI to completion. This is the only way to test the `die` paths:
 * die() exits the process, so it cannot be exercised in-process.
 */
export function runCli(args: string[]): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [ENTRY, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr?.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("exit", (code) =>
      resolve({ code: code ?? -1, stdout, stderr, output: stdout + stderr }),
    );
  });
}

/** A config on disk in a scratch directory, plus the way to remove it. */
export interface ConfigFile {
  path: string;
  remove: () => void;
}

export function writeConfigFile(raw: unknown): ConfigFile {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "devproxy-cli-"));
  const file = path.join(dir, "devproxy.config.json");
  fs.writeFileSync(file, typeof raw === "string" ? raw : JSON.stringify(raw, null, 2));
  return { path: file, remove: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/** Runs the CLI against a throwaway config, cleaning it up afterwards. */
export async function runCliWithConfig(raw: unknown, args: string[] = []): Promise<CliResult> {
  const config = writeConfigFile(raw);
  try {
    return await runCli(["-c", config.path, ...args]);
  } finally {
    config.remove();
  }
}

/* ------------------------------------------------------------------ clients */

export interface Response {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface RequestOptions {
  port: number;
  path?: string;
  method?: string;
  /** The Host the browser would send; the proxy routes on it. */
  host?: string;
  headers?: http.OutgoingHttpHeaders;
  body?: string;
}

/** A plain HTTP request with an explicit Host, the way a browser would arrive. */
export function request(options: RequestOptions): Promise<Response> {
  const { port, path: p = "/", method = "GET", host = "test.local", headers = {}, body } = options;
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: p,
        method,
        // setHost:false so the Host below is sent verbatim, port included.
        setHost: false,
        headers: { host: `${host}:${port}`, ...headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (d: Buffer) => chunks.push(d));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** The same, over TLS, without requiring the mkcert CA to be trusted here. */
export function tlsRequest(options: RequestOptions & { servername: string }): Promise<Response> {
  const { port, path: p = "/", method = "GET", servername, headers = {} } = options;
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: "127.0.0.1",
        port,
        path: p,
        method,
        servername,
        rejectUnauthorized: false,
        setHost: false,
        headers: { host: `${servername}:${port}`, ...headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (d: Buffer) => chunks.push(d));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

/**
 * The DNS names on the certificate served for a given SNI name.
 *
 * A bare handshake, because a pooled HTTP socket does not reliably retain the
 * peer certificate. The names come from the SAN rather than the subject CN:
 * mkcert leaves the CN empty and puts the hostname only in subjectAltName.
 */
export function peerCertNames(port: number, servername: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: "127.0.0.1", port, servername, rejectUnauthorized: false },
      () => {
        const san = socket.getPeerCertificate()?.subjectaltname ?? "";
        socket.destroy();
        resolve(
          san
            .split(",")
            .map((entry) => entry.trim().replace(/^DNS:/, "").toLowerCase())
            .filter(Boolean),
        );
      },
    );
    socket.setTimeout(5000, () => {
      socket.destroy();
      reject(new Error(`TLS handshake to ${servername}:${port} timed out`));
    });
    socket.on("error", reject);
  });
}

export interface Handshake {
  raw: string;
  statusLine: string;
  echoed: boolean;
}

/**
 * Drives a real Upgrade: sends the handshake, writes a payload once the 101
 * arrives, and resolves when the payload comes back through the splice.
 */
export function upgrade(options: {
  port: number;
  host?: string;
  path?: string;
  payload?: string;
}): Promise<Handshake> {
  const { port, host = "test.local", path: p = "/socket", payload = "ping" } = options;
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(
        `GET ${p} HTTP/1.1\r\n` +
          `Host: ${host}:${port}\r\n` +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
          "Sec-WebSocket-Version: 13\r\n\r\n",
      );
    });

    let raw = "";
    let sent = false;
    const finish = (): void => {
      socket.destroy();
      resolve({
        raw,
        statusLine: raw.split("\r\n")[0] ?? "",
        echoed: raw.includes(`echo:${payload}`),
      });
    };

    socket.on("data", (d: Buffer) => {
      raw += d.toString();
      if (!sent && raw.includes("\r\n\r\n")) {
        sent = true;
        socket.write(payload);
      }
      if (raw.includes(`echo:${payload}`)) finish();
    });
    socket.on("error", () => finish());
    setTimeout(finish, 3000);
  });
}
