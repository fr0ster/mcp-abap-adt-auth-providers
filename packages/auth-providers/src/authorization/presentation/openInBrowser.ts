/**
 * `openInBrowser({ browser })`: opens the URL through
 * `browser`, an `IBrowser` — a shipped one (`linuxDefaultBrowser()`,
 * `linuxBrowser(executable)`, `macDefaultBrowser()`, `macBrowser(app)`,
 * `windowsDefaultBrowser()`, `windowsBrowser(program)`) or the consumer's —
 * used as given: its `open` is called on it with exactly the URL and the
 * login's signal. A browser that throws or rejects
 * is a presentation failure: the URL is prompted once, to stderr only, and
 * the failure goes to the composer's fixed line; the login keeps waiting.
 * Nothing is prompted once the login has ended.
 *
 * No browser is named by a string. Showing the URL without a browser is
 * `showUrl`.
 */

import type {
  IAuthorizationPresentation,
  IBrowser,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import { promptAuthorizationUrl, promptContext } from './prompt';

export interface OpenInBrowserOptions {
  /** Required: the browser that opens the URL. */
  readonly browser: IBrowser;
}

export function openInBrowser(
  options: OpenInBrowserOptions,
): IAuthorizationPresentation {
  // A typed copy: the options are read once, here.
  const { browser } = { ...options };
  return Object.freeze({
    async present(
      authorizationUrl: string,
      context: PresentationContext,
    ): Promise<void> {
      const read = promptContext(context);
      try {
        // A synchronous throw is a rejection; `await` adopts any thenable.
        await new Promise<unknown>((resolve) =>
          resolve(browser.open(authorizationUrl, context.signal)),
        );
      } catch (error) {
        // The URL is the only way left to finish the login: prompted once,
        // then the failure goes to the composer's fixed line.
        promptAuthorizationUrl(
          authorizationUrl,
          read,
          '🔗 The browser could not be opened. The authorization URL:',
        );
        throw error;
      }
    },
  });
}
