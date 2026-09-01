/**
 * Fake origin servers to proxy at.
 *
 * One stands in for the real deployment, one for a local dev server. Both
 * record every request they receive, so a test can assert on exactly what the
 * proxy forwarded rather than on an echo the origin chose to send back.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";

export interface Received {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface Origin {
  port: number;
  /** http://127.0.0.1:<port> — what a rule's target url should be. */
  url: string;
  /** Every request this origin saw, oldest first. */
  seen: Received[];
  last: () => Received;
  close: () => Promise<void>;
}

export interface OriginOptions {
  /** Answer Upgrade requests with a 101 and echo whatever arrives after it. */
  withUpgrade?: boolean;
}

/**
 * Paths with behaviour beyond "200 and record it":
 *   /cookie    three Set-Cookie headers, one with a Domain the proxy must drop
 *   /redirect  302 to an absolute URL on this origin, for Location rewriting
 *   /hsts      HSTS + a header to keep + an ACAO to rewrite
 *   /stream    two chunks, written apart in time
 *   /echobody  replies with the request body it read
 */
export function startOrigin(options: OriginOptions = {}): Promise<Origin> {
  const seen: Received[] = [];

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (d: Buffer) => chunks.push(d));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString();
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });

      const pathname = new URL(req.url ?? "/", "http://placeholder").pathname;
      const port = (server.address() as AddressInfo).port;

      if (pathname.endsWith("/cookie")) {
        res.writeHead(200, {
          "set-cookie": [
            "a=1; Path=/; Domain=rejected.example; HttpOnly",
            "b=2; Path=/; Domain=.test.local",
            "c=3; Path=/",
          ],
        });
        res.end("cookies");
        return;
      }
      if (pathname.endsWith("/redirect")) {
        res.writeHead(302, { location: `http://127.0.0.1:${port}/next?q=1#frag` });
        res.end();
        return;
      }
      if (pathname.endsWith("/hsts")) {
        res.writeHead(200, {
          "strict-transport-security": "max-age=31536000",
          "x-keep-me": "yes",
          "access-control-allow-origin": `http://127.0.0.1:${port}`,
        });
        res.end("hsts");
        return;
      }
      if (pathname.endsWith("/stream")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.write("chunk1");
        setTimeout(() => res.end("chunk2"), 60);
        return;
      }
      if (pathname.endsWith("/echobody")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end(`got:${body}`);
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });

  if (options.withUpgrade) {
    server.on("upgrade", (req: http.IncomingMessage, socket: Duplex, head: Buffer) => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: "" });
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `X-Echo-Host: ${req.headers.host}\r\n\r\n`,
      );
      if (head.length) socket.write(head);
      socket.on("data", (d: Buffer) => socket.write(Buffer.concat([Buffer.from("echo:"), d])));
      socket.on("error", () => socket.destroy());
    });
  }

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        port,
        url: `http://127.0.0.1:${port}`,
        seen,
        last: () => {
          const l = seen.at(-1);
          if (!l) throw new Error("origin received no requests");
          return l;
        },
        close: () =>
          new Promise((done) => {
            server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}
