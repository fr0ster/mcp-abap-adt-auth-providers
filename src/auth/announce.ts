/**
 * Where an essential, user-facing prompt goes.
 *
 * Prompts are not log lines: a device code or an authorization URL the user
 * cannot see makes the flow impassable, so they must survive the absence of a
 * logger. They must equally never reach stdout, which carries protocol traffic
 * under an MCP or LSP stdio transport.
 */

import { isPromise, isProxy } from 'node:util/types';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { logQuietly } from './tokenRequest';

/** `Promise.prototype.then` as it was at load: never a value's own `then`. */
const promiseThen = Promise.prototype.then;

/**
 * The logger's `info`, or stderr without one. The prompt must not vanish: a
 * logger that throws gets it on stderr instead, and so does one whose `info`
 * answers a plain native promise that rejects (an async logger that failed)
 * — once the rejection arrives; the rejection itself is handled. Never
 * stdout.
 */
export function announcer(logger?: ILogger): (msg: string) => void {
  const toStderr = (msg: string) => {
    process.stderr.write(`${msg}\n`);
  };
  return (msg: string) => {
    if (!logger) {
      toStderr(msg);
      return;
    }
    let answered: unknown;
    let threw = false;
    logQuietly(() => {
      try {
        answered = logger.info(msg);
        return answered;
      } catch (error) {
        threw = true;
        throw error;
      }
    });
    if (threw) {
      toStderr(msg);
      return;
    }
    // A plain native promise only: a foreign thenable's code is never run.
    if (isPromise(answered) && !isProxy(answered)) {
      if (Object.getPrototypeOf(answered) !== Promise.prototype) return;
      promiseThen.call(answered, undefined, () => toStderr(msg));
    }
  };
}
