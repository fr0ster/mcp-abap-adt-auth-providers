/**
 * Shared pieces of the cancellation suites (spec §6b): controllable
 * promises, a real token server on loopback whose answers a test can hold
 * and release, and strategies that wait until answered or aborted. Nothing
 * here sleeps: every wait ends on an event the test controls.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';

export interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

export function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

/** Lets every queued microtask and one macrotask turn run. */
export const turn = (): Promise<void> =>
  new Promise((resolve) => setImmediate(resolve));

/** A few turns: enough for a chain of awaits to settle; no timer. */
export async function settle(turns = 5): Promise<void> {
  for (let i = 0; i < turns; i++) await turn();
}

const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');

/** An unsigned JWT expiring `seconds` from now, unique per `subject`. */
export function jwt(subject: string, seconds = 3600): string {
  return `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
    exp: Math.floor(Date.now() / 1000) + seconds,
    sub: subject,
  })}.sig`;
}

/** One request the token server received, and the way to answer it. */
export interface HeldRequest {
  readonly params: URLSearchParams;
  readonly path: string;
  /** Answers with `status` and a JSON `body`. */
  answer(status: number, body: object): void;
  /** Resolves when the client has gone (socket closed). */
  readonly closed: Promise<void>;
  /** True once the client closed the socket before an answer. */
  aborted(): boolean;
}

export interface TokenServer {
  readonly url: string;
  readonly port: number;
  /** Every request received, in order. */
  readonly requests: HeldRequest[];
  /** Resolves with the `n`th request (1-based) once it has arrived. */
  nth(n: number): Promise<HeldRequest>;
  close(): Promise<void>;
}

/**
 * A token endpoint on loopback. `respond` decides each request: answer it at
 * once (`request.answer(…)`), or hold it — the test answers it later, or
 * never. Requests are counted as they arrive, the body parsed as a form.
 */
export async function startTokenServer(
  respond: (request: HeldRequest) => void = () => undefined,
): Promise<TokenServer> {
  const requests: HeldRequest[] = [];
  const waiting = new Map<number, Deferred<HeldRequest>>();
  const sockets = new Set<import('node:net').Socket>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      let answered = false;
      let clientGone = false;
      const closed = deferred<void>();
      res.on('close', () => {
        if (!answered) clientGone = true;
        closed.resolve();
      });
      const held: HeldRequest = {
        params: new URLSearchParams(Buffer.concat(chunks).toString('utf8')),
        path: req.url ?? '',
        answer(status, body) {
          if (answered || res.writableEnded || clientGone) return;
          answered = true;
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(body));
        },
        closed: closed.promise,
        aborted: () => clientGone,
      };
      requests.push(held);
      waiting.get(requests.length)?.resolve(held);
      respond(held);
    });
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve()),
  );
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    requests,
    nth(n) {
      const arrived = requests[n - 1];
      if (arrived) return Promise.resolve(arrived);
      let entry = waiting.get(n);
      if (!entry) {
        entry = deferred<HeldRequest>();
        waiting.set(n, entry);
      }
      return entry.promise;
    },
    close() {
      for (const socket of sockets) socket.destroy();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** A strategy call the test can see and answer. */
export interface StrategyCall {
  readonly request: AuthorizationRequest & { signal?: AbortSignal };
  readonly signal: AbortSignal | undefined;
  /** Answers the authorization with `payload`. */
  answer(payload: string): void;
  /** The call's own promise, settled however it ends. */
  readonly settled: Promise<void>;
}

export interface WaitingStrategy extends IAuthorizationStrategy<string> {
  readonly calls: StrategyCall[];
  /** Resolves with the `n`th call (1-based) once it has been made. */
  nth(n: number): Promise<StrategyCall>;
}

/**
 * A strategy that waits until the test answers it, or until the request's
 * signal aborts — then it rejects. It settles only then: it holds nothing,
 * so it has nothing to release first.
 */
export function waitingStrategy(
  redirectUri = 'http://localhost:61001/callback',
): WaitingStrategy {
  const calls: StrategyCall[] = [];
  const waiting = new Map<number, Deferred<StrategyCall>>();
  return {
    calls,
    nth(n) {
      const made = calls[n - 1];
      if (made) return Promise.resolve(made);
      let entry = waiting.get(n);
      if (!entry) {
        entry = deferred<StrategyCall>();
        waiting.set(n, entry);
      }
      return entry.promise;
    },
    authorize(request): Promise<AuthorizationOutcome<string>> {
      const signal = (request as { signal?: AbortSignal }).signal;
      const outcome = deferred<AuthorizationOutcome<string>>();
      const done = deferred<void>();
      outcome.promise.then(
        () => done.resolve(),
        () => done.resolve(),
      );
      signal?.addEventListener(
        'abort',
        () => outcome.reject(new Error('the strategy saw the abort')),
        { once: true },
      );
      const call: StrategyCall = {
        request: request as StrategyCall['request'],
        signal,
        answer: (payload) => outcome.resolve({ payload, redirectUri }),
        settled: done.promise,
      };
      calls.push(call);
      waiting.get(calls.length)?.resolve(call);
      return outcome.promise;
    },
  };
}

/** Attaches a rejection observer at once; resolves with what was thrown. */
export function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    (value) => {
      throw new Error(`expected a rejection, got ${JSON.stringify(value)}`);
    },
    (error: unknown) => error,
  );
}

/** Items arriving in order; `nth(n)` resolves once the `n`th has arrived. */
export class Arrivals<T> {
  readonly items: T[] = [];
  private readonly waiting = new Map<number, Deferred<T>>();
  push(item: T): void {
    this.items.push(item);
    this.waiting.get(this.items.length)?.resolve(item);
  }
  nth(n: number): Promise<T> {
    const arrived = this.items[n - 1];
    if (arrived !== undefined) return Promise.resolve(arrived);
    let entry = this.waiting.get(n);
    if (!entry) {
      entry = deferred<T>();
      this.waiting.set(n, entry);
    }
    return entry.promise;
  }
}
