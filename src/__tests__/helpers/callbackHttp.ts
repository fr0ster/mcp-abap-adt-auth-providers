/**
 * Requests to a local callback server, one fresh connection each (no pooled
 * socket a released scope may have cut), with the `Host` header and the
 * address to connect to under the test's control.
 */

import http from 'node:http';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';

export interface Reply {
  status: number;
  body: string;
}

export interface CallbackRequest {
  /** The address connected to. Default `127.0.0.1`. */
  address?: string;
  /** The `Host` header sent. Default `<address>:<port>`, as a browser sends it. */
  host?: string;
}

export function callbackGet(
  port: number,
  path: string,
  options: CallbackRequest = {},
): Promise<Reply> {
  const address = options.address ?? '127.0.0.1';
  return new Promise((resolve, reject) => {
    const req = http.get(
      {
        host: address,
        port,
        path,
        agent: false,
        ...(options.host === undefined
          ? {}
          : { headers: { Host: options.host } }),
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
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

/** A logger that records how many callback requests the server ignored. */
export function ignoreCounter(): { logger: ILogger; ignored: () => number } {
  let last = 0;
  const logger: ILogger = {
    debug: () => undefined,
    info: () => undefined,
    error: () => undefined,
    warn: (_message: string, meta?: unknown) => {
      const count = (meta as { ignored?: unknown } | undefined)?.ignored;
      if (typeof count === 'number') last = count;
    },
  };
  return { logger, ignored: () => last };
}
