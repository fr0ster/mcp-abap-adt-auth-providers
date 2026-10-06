/**
 * Where an essential, user-facing prompt goes.
 *
 * Prompts are not log lines: a device code or an authorization URL the user
 * cannot see makes the flow impassable, so they must survive the absence of a
 * logger. They must equally never reach stdout, which carries protocol traffic
 * under an MCP or LSP stdio transport.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { logQuietly } from './tokenRequest';

/**
 * The logger's `info`, or stderr without one. A logger that throws gets the
 * prompt on stderr instead — the prompt must not vanish — and one whose
 * `info` answers a rejecting promise (an async logger) changes nothing
 * (`logQuietly`).
 */
export function announcer(logger?: ILogger): (msg: string) => void {
  return (msg: string) => {
    if (logger) {
      let shown = true;
      logQuietly(() => {
        try {
          return logger.info(msg);
        } catch (error) {
          shown = false;
          throw error;
        }
      });
      if (shown) return;
    }
    process.stderr.write(`${msg}\n`);
  };
}
