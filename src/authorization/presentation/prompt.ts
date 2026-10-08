/**
 * The prompt of the authorization URL (C8): the URL goes to stderr only —
 * never through `ILogger`, never to stdout — and only as `promptableUrl`
 * admits it; the logger gets the fixed line "the authorization URL was
 * shown". Where the channel waits and how a user elsewhere reaches it carry
 * no secret: they go through the announcer (the logger's `info`, else
 * stderr).
 */

import type { PresentationContext } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer, promptableText, promptableUrl } from '../../auth/announce';
import { readSafely } from '../../auth/knownCodes';
import { asAbortSignal } from '../../auth/signalledRequest';
import { logQuietly } from '../../auth/tokenRequest';

/** The fixed line the logger gets for a URL shown on stderr. */
export const SHOWN_NOTICE = 'the authorization URL was shown';

/** The context's fields a prompt reads, each guarded. */
export interface PromptContext {
  readonly logger: ILogger | undefined;
  readonly redirectUri: string | undefined;
  readonly waitingOn: string | undefined;
  readonly routeHint: string | undefined;
  readonly signal: AbortSignal | undefined;
}

/** What a presentation reads of its context, once, guarded. */
export function promptContext(context: PresentationContext): PromptContext {
  const logger = readSafely(context, 'logger');
  const redirectUri = readSafely(context, 'redirectUri');
  const waitingOn = readSafely(context, 'waitingOn');
  const routeHint = readSafely(context, 'routeHint');
  const signal = readSafely(context, 'signal');
  return {
    logger:
      logger !== null && typeof logger === 'object'
        ? (logger as ILogger)
        : undefined,
    redirectUri: typeof redirectUri === 'string' ? redirectUri : undefined,
    waitingOn: typeof waitingOn === 'string' ? waitingOn : undefined,
    routeHint: typeof routeHint === 'string' ? routeHint : undefined,
    signal: asAbortSignal(signal),
  };
}

/** One line to stderr: a write that throws is contained. */
function toStderr(line: string): void {
  try {
    process.stderr.write(`${line}\n`);
  } catch {
    // Nothing else to tell.
  }
}

/**
 * Prompts `authorizationUrl` after `lead`, on stderr only, then where the
 * channel waits and its route hint. Nothing once the login has ended.
 */
export function promptAuthorizationUrl(
  authorizationUrl: string,
  context: PromptContext,
  lead: string,
): void {
  if (context.signal?.aborted) return;
  const announce = announcer(context.logger);
  const shownUrl = promptableUrl(authorizationUrl);
  if (shownUrl === undefined) {
    announce('The authorization URL is not an http(s) URL that can be shown.');
  } else {
    toStderr(lead);
    toStderr(`   ${shownUrl}`);
    logQuietly(() => context.logger?.info(SHOWN_NOTICE));
  }
  if (context.waitingOn !== undefined) {
    const shownWaiting = promptableUrl(context.waitingOn);
    announce(
      shownWaiting === undefined
        ? 'Waiting for the callback ...'
        : `Waiting for callback on ${shownWaiting} ...`,
    );
  }
  // A hint is one printable line, or nothing.
  const shownHint = promptableText(context.routeHint);
  if (shownHint !== undefined) announce(shownHint);
}
