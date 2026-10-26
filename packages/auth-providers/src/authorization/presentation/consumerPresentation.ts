/**
 * `consumerPresentation({ show, onFailure? })`:
 * the consumer's own UI shows the URL. A `show` that throws or rejects is
 * a presentation failure the composer logs in fixed words; this part
 * prints **no URL** — the consumer chose its own UI because its stderr may
 * be collected — and runs the consumer's `onFailure` once, its own failure
 * logged in fixed words and nothing more. Nothing runs once the login has
 * ended.
 */

import { logFields, readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthorizationPresentation,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import { logQuietly } from '../../auth/tokenRequest';
import { promptContext } from './prompt';

/** What the consumer's UI gets beside the URL. */
export interface ShowContext {
  /** The redirect the channel advertises, when it has one. */
  readonly redirectUri: string | undefined;
  /** Aborts when the login ends — by its answer, an abort or a dispose. */
  readonly signal: AbortSignal;
}

/** The consumer's UI: shows `authorizationUrl` to the user. */
export type ShowAuthorizationUrl = (
  authorizationUrl: string,
  context: ShowContext,
) => unknown;

export interface ConsumerPresentationOptions {
  readonly show: ShowAuthorizationUrl;
  /** The consumer's own fallback when `show` fails; run once. */
  readonly onFailure?: ShowAuthorizationUrl | undefined;
}

/** A value adopted as `await` would, a synchronous throw as a rejection. */
const adopt = (run: () => unknown): Promise<unknown> =>
  new Promise<unknown>((resolve) => resolve(run()));

/** A signal that never aborts, for a context given none. */
const never = new AbortController().signal;

export function consumerPresentation(
  options: ConsumerPresentationOptions,
): IAuthorizationPresentation {
  // A typed copy: the options are read once, here.
  const { show, onFailure } = { ...options };
  return Object.freeze({
    async present(
      authorizationUrl: string,
      context: PresentationContext,
    ): Promise<void> {
      const read = promptContext(context);
      const shown: ShowContext = Object.freeze({
        redirectUri: read.redirectUri,
        signal: read.signal ?? never,
      });
      try {
        await adopt(() => show(authorizationUrl, shown));
      } catch (error) {
        if (onFailure !== undefined && !read.signal?.aborted) {
          try {
            await adopt(() => onFailure(authorizationUrl, shown));
          } catch (fallbackError) {
            const fields = logFields(
              readFailure(fallbackError, 'presenting-authorization-url'),
            );
            logQuietly(() =>
              read.logger?.error(
                `The consumer’s fallback for the authorization URL failed: ${fields.error}`,
                fields,
              ),
            );
          }
        }
        throw error;
      }
    },
  });
}
