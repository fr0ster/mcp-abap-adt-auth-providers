/**
 * The loopback listener transports: each binds only
 * loopback and advertises only what it binds — the origin it listens on
 * plus the endpoint it is given. `port` is required; `0` binds an
 * ephemeral port. A listener on a network address is the consumer's own
 * transport.
 */

import type {
  AnswerTransportOptions,
  IAnswerChannel,
  IAnswerTransport,
} from '@mcp-abap-adt/interfaces-auth';
import { ownOptions } from '../../auth/configuration';
import { validatePort } from './binding';
import { type ListenerPlan, openHttpListener } from './httpListener';

export interface LoopbackOptions {
  /** Required. `0` binds an ephemeral port — unusable where the IdP has a registered redirect. */
  readonly port: number;
}

function listenerTransport(
  options: LoopbackOptions,
  plan: Omit<ListenerPlan, 'port'>,
): IAnswerTransport {
  // Read once as own data: a hostile object throws nothing of its own.
  const { port } = ownOptions<{ port?: unknown }>(options);
  validatePort(port);
  return Object.freeze({
    label: 'browser' as const,
    async open<TReturn>(
      openOptions: AnswerTransportOptions,
      use: (channel: IAnswerChannel) => Promise<TReturn>,
    ): Promise<TReturn> {
      return await openHttpListener({ ...plan, port }, openOptions, use);
    },
  });
}

/** `::1` only; advertises `http://[::1]:<port><endpoint>`. */
export function loopback6(options: LoopbackOptions): IAnswerTransport {
  return listenerTransport(options, {
    binds: [{ address: '::1', ifAvailable: false }],
    advertises: '[::1]',
    tunnelsTo: '[::1]',
  });
}

/** `127.0.0.1` only; advertises `http://127.0.0.1:<port><endpoint>`. */
export function loopback4(options: LoopbackOptions): IAnswerTransport {
  return listenerTransport(options, {
    binds: [{ address: '127.0.0.1', ifAvailable: false }],
    advertises: '127.0.0.1',
    tunnelsTo: '127.0.0.1',
  });
}

/**
 * `127.0.0.1`, then `::1` on the same port — the two addresses `localhost`
 * resolves to; advertises `http://localhost:<port><endpoint>`. `::1` taken
 * fails `port-in-use`, never `127.0.0.1` alone; a machine
 * without `::1` listens on `127.0.0.1` alone: an address the machine
 * does not have is nobody's.
 */
export function loopback(options: LoopbackOptions): IAnswerTransport {
  return listenerTransport(options, {
    binds: [
      { address: '127.0.0.1', ifAvailable: false },
      { address: '::1', ifAvailable: true },
    ],
    advertises: 'localhost',
    tunnelsTo: 'localhost',
  });
}
