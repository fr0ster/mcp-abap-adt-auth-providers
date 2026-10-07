/**
 * Where an essential, user-facing prompt goes.
 *
 * Prompts are not log lines: a device code or an authorization URL the user
 * cannot see makes the flow impassable, so they must survive the absence of a
 * logger. They must equally never reach stdout, which carries protocol traffic
 * under an MCP or LSP stdio transport.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { onAnswerRejection } from './handled';
import { logQuietly } from './tokenRequest';

/**
 * The logger's `info`, or stderr without one. The prompt must not vanish: a
 * logger that throws gets it on stderr instead, and so does one whose `info`
 * answers a promise or any Promises/A+ thenable that rejects (an async
 * logger that failed; the logger is the consumer's own code, adopted like an
 * await would) — once the rejection arrives; the rejection itself is handled. Never
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
        return undefined;
      } catch (error) {
        threw = true;
        throw error;
      }
    });
    if (threw) {
      toStderr(msg);
      return;
    }
    if (
      (answered !== null && typeof answered === 'object') ||
      typeof answered === 'function'
    ) {
      onAnswerRejection(answered, () => toStderr(msg));
    }
  };
}
