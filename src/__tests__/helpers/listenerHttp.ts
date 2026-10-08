/**
 * Requests to a composed callback listener over a real socket, one fresh
 * connection each, with the method, path, `Host`, body and local address
 * under the test's control; and the small probes the listener tests share.
 */

import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';

export interface Reply {
  readonly status: number;
  readonly body: string;
  readonly headers: http.IncomingHttpHeaders;
}

export interface Send {
  readonly method?: string;
  /** The address connected to. Default `127.0.0.1`. */
  readonly address?: string;
  /** The `Host` header. Default `<address>:<port>`, bracketed for IPv6. */
  readonly host?: string;
  /** A urlencoded body (POST). */
  readonly form?: Record<string, string | readonly string[]>;
  readonly body?: string;
  readonly contentType?: string;
  /** More request headers. */
  readonly headers?: Record<string, string>;
  /** The client's own address: a non-loopback one makes a network peer. */
  readonly localAddress?: string;
}

export const authorityOf = (address: string, port: number): string =>
  address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`;

export function formBody(
  fields: Record<string, string | readonly string[]>,
): string {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(fields)) {
    for (const one of typeof value === 'string' ? [value] : value) {
      params.append(name, one);
    }
  }
  return params.toString();
}

export function send(
  port: number,
  path: string,
  options: Send = {},
): Promise<Reply> {
  const address = options.address ?? '127.0.0.1';
  const body =
    options.form !== undefined ? formBody(options.form) : options.body;
  const headers: Record<string, string> = {
    Host: options.host ?? authorityOf(address, port),
    ...options.headers,
  };
  if (body !== undefined) {
    headers['Content-Type'] =
      options.contentType ?? 'application/x-www-form-urlencoded';
    headers['Content-Length'] = String(Buffer.byteLength(body));
  }
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: address,
        port,
        path,
        method: options.method ?? (body === undefined ? 'GET' : 'POST'),
        agent: false,
        headers,
        ...(options.localAddress === undefined
          ? {}
          : { localAddress: options.localAddress }),
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          text += chunk;
        });
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body: text,
            headers: res.headers,
          }),
        );
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

/** The form token in a served paste page, else `undefined`. */
export function formTokenIn(body: string): string | undefined {
  const marker = 'name="form_token" value="';
  const at = body.indexOf(marker);
  if (at < 0) return undefined;
  const end = body.indexOf('"', at + marker.length);
  return end < 0 ? undefined : body.slice(at + marker.length, end);
}

/** Whether `port` can be bound on `address` right now. */
export function bindable(
  port: number,
  address = '127.0.0.1',
): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, address, () => s.close(() => resolve(true)));
  });
}

/** Whether a TCP connection to `address:port` is accepted. */
export function connects(address: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: address, port });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

/** Whether this machine can bind `::1` at all (IPv6 may be disabled). */
export function hasIpv6Loopback(): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(0, '::1', () => s.close(() => resolve(true)));
  });
}

/** A non-loopback IPv4 address of this machine, if it has one. */
export function externalIpv4(): string | undefined {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return entry.address;
    }
  }
  return undefined;
}

export interface LogLine {
  readonly level: 'debug' | 'info' | 'warn' | 'error';
  readonly message: string;
  readonly meta: unknown;
}

/** A logger keeping every line, and the reasons of the refusals it saw. */
export function capturingLogger(): {
  logger: ILogger;
  lines: LogLine[];
  reasons: () => unknown[];
  text: () => string;
} {
  const lines: LogLine[] = [];
  const at =
    (level: LogLine['level']) =>
    (message: string, meta?: unknown): void => {
      lines.push({ level, message, meta });
    };
  return {
    logger: {
      debug: at('debug'),
      info: at('info'),
      warn: at('warn'),
      error: at('error'),
    },
    lines,
    reasons: () =>
      lines
        .filter((line) => line.level === 'warn')
        .map((line) => (line.meta as { reason?: unknown } | undefined)?.reason),
    text: () =>
      lines
        .map((line) => `${line.message} ${JSON.stringify(line.meta ?? null)}`)
        .join('\n'),
  };
}
