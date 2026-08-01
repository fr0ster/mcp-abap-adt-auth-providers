/**
 * Where an essential, user-facing prompt goes.
 *
 * Prompts are not log lines: a device code or an authorization URL the user
 * cannot see makes the flow impassable, so they must survive the absence of a
 * logger. They must equally never reach stdout, which carries protocol traffic
 * under an MCP or LSP stdio transport.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces';

export function announcer(logger?: ILogger): (msg: string) => void {
  return (msg: string) => {
    if (logger) logger.info(msg);
    else process.stderr.write(`${msg}\n`);
  };
}
