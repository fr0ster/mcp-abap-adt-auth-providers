/**
 * How a callback listener lets go of its connections (Task 30f, spec
 * §6d.3.5), with no timer of the package's choosing. Measured: a server's
 * `close()` destroys a parsed connection even mid-flush of a large response
 * to a client that does not read, and a pending write keeps the loop alive
 * whatever `unref()` says — so nothing here waits for a connection to end.
 */

import type * as http from 'node:http';
import type { Socket } from 'node:net';

export interface ConnectionTracker {
  /** Follows every connection and request of `server`. */
  watch(server: http.Server): void;
  /**
   * Closes every listening socket — the port is free once it returns (the
   * handle's descriptor is closed synchronously) — and lets every
   * connection go: at once when it is writing nothing, after its last
   * response otherwise; one whose request body is unfinished is destroyed.
   */
  release(): void;
}

export function trackConnections(): ConnectionTracker {
  const servers: http.Server[] = [];
  /** Every open connection, and how many responses each is still writing. */
  const sockets = new Map<Socket, number>();
  /** The request each connection is serving, to tell an unfinished body. */
  const requests = new Map<Socket, http.IncomingMessage>();
  let released = false;

  /**
   * A connection no longer needed: ended gracefully — the client still
   * reads what was written, which `destroy()` would cut off — and
   * unreferenced, so a client that never closes its side holds neither the
   * port (the listener is closed) nor the process.
   */
  const letGo = (socket: Socket): void => {
    socket.end();
    socket.unref();
  };

  /**
   * A connection still answering: referenced no longer, so it cannot keep
   * the process alive; and when its request body is unfinished — nothing
   * will ever answer it — destroyed. A finished request keeps its response,
   * which `letGo` ends after the last byte.
   */
  const holdNothing = (
    socket: Socket,
    request: http.IncomingMessage | undefined,
  ): void => {
    socket.unref();
    if (request && !request.complete) socket.destroy();
  };

  return {
    watch(server) {
      servers.push(server);
      server.on('connection', (socket: Socket) => {
        sockets.set(socket, 0);
        socket.on('close', () => {
          sockets.delete(socket);
          requests.delete(socket);
        });
      });
      server.on(
        'request',
        (req: http.IncomingMessage, res: http.ServerResponse) => {
          const socket = req.socket;
          sockets.set(socket, (sockets.get(socket) ?? 0) + 1);
          requests.set(socket, req);
          res.once('close', () => {
            const left = (sockets.get(socket) ?? 1) - 1;
            if (sockets.has(socket)) sockets.set(socket, left);
            if (released && left <= 0) letGo(socket);
          });
        },
      );
    },
    release() {
      released = true;
      for (const server of servers) if (server.listening) server.close();
      for (const [socket, responding] of sockets) {
        if (responding <= 0) letGo(socket);
        else holdNothing(socket, requests.get(socket));
      }
    },
  };
}

/**
 * Runs `then` once `res` has actually flushed, so a release cannot cut the
 * page off.
 *
 * The check is `writableFinished`, not `writableEnded`: the latter is true
 * as soon as `end()` has been called and says nothing about the data having
 * left. Measured on Node 25 with a paused client — an 800-byte body reports
 * both flags true at once, but a 20 MB body reports `writableEnded` true and
 * `writableFinished` false, with `finish` arriving 456 ms later.
 */
export function afterFlush(
  res: http.ServerResponse | undefined,
  then: () => void,
): void {
  if (!res || res.writableFinished) {
    then();
    return;
  }
  res.once('finish', then);
  res.once('close', then);
}
