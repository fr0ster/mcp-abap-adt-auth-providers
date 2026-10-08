/**
 * `openInBrowser({ browser })` (spec §6d.2, §6d.5): opens the URL with the
 * launcher as built (§6a0: no shell, `launchableUrl`, absolute paths on
 * Windows). Its own fallback — `auto` whose `open` failed, no `open` module
 * and a launcher exiting non-zero — prompts the URL itself and resolves; a
 * named browser or `system` whose `open` rejects prompts the URL and
 * rejects, so the composer logs the failure and never prompts it twice.
 * `none` / `headless` are refused: that is `showUrl`.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthorizationPresentation,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import { launchBrowser, type OpenableBrowser } from '../../auth/browserAuth';
import { misconfigured, ownOptions } from '../../auth/configuration';
import { promptAuthorizationUrl, promptContext } from './prompt';

export type { OpenableBrowser } from '../../auth/browserAuth';

export interface OpenInBrowserOptions {
  /** Required: which browser opens the URL. */
  readonly browser: OpenableBrowser;
}

const BROWSERS: ReadonlySet<unknown> = new Set<OpenableBrowser>([
  'auto',
  'system',
  'chrome',
  'msedge',
  'firefox',
]);

export function openInBrowser(
  options: OpenInBrowserOptions,
): IAuthorizationPresentation {
  // Read once as own data: a hostile object throws nothing of its own.
  const { browser } = ownOptions<{ browser?: unknown }>(options);
  if (browser === undefined) {
    throw misconfigured(
      authError.configuration({
        case: 'required-fields-missing',
        fields: ['presentation'],
      }),
    );
  }
  if (!BROWSERS.has(browser)) {
    throw misconfigured(
      authError.configuration({
        case: 'invalid-value',
        fields: ['presentation'],
      }),
    );
  }
  const chosen = browser as OpenableBrowser;
  return Object.freeze({
    async present(
      authorizationUrl: string,
      context: PresentationContext,
    ): Promise<void> {
      const read = promptContext(context);
      const prompt = (lead: string) =>
        promptAuthorizationUrl(authorizationUrl, read, lead);
      try {
        await launchBrowser(
          authorizationUrl,
          chosen,
          prompt,
          read.logger ?? null,
        );
      } catch (error) {
        // The URL is the only way left to finish the login: prompted once,
        // then the failure goes to the composer's fixed line.
        prompt('🔗 The browser could not be opened. The authorization URL:');
        throw error;
      }
    },
  });
}
