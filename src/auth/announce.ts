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

/**
 * A URL as a prompt may show it: an `http:` or `https:` URL's WHATWG
 * serialisation when every character of it is printable ASCII, else
 * `undefined`. The serialiser percent-encodes what the source held of
 * spaces, non-ASCII and bidi controls in the path, query and fragment, and
 * drops tabs and line breaks; whatever is still not printable (a host it
 * kept) refuses the whole URL — a prompt never carries a control character
 * that could forge another line or reorder what the user reads. Total.
 */
export function promptableUrl(url: unknown): string | undefined {
  if (typeof url !== 'string') return undefined;
  let href: string;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return undefined;
    }
    href = parsed.href;
  } catch {
    return undefined;
  }
  return printableAscii(href, false) ? href : undefined;
}

/**
 * A short value a prompt may show as it is (a device flow's user code):
 * a string of printable ASCII, spaces inside it allowed, else `undefined`.
 * Total.
 */
export function promptableText(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed !== '' && printableAscii(trimmed, true) ? trimmed : undefined;
}

/** Every character in `!`..`~` (and a space, when `spaces`). Plain code. */
function printableAscii(value: string, spaces: boolean): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x20 && spaces) continue;
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}
