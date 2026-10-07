/**
 * How the user learns where to go and what to enter in a device flow. Injected
 * like a strategy: the provider hands over structured data, and the consumer's
 * UI renders it its own way.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer, promptableText, promptableUrl } from '../auth/announce';
import { loginFailure } from '../auth/interactiveLogin';

export interface DeviceCodePrompt {
  verificationUri: string;
  verificationUriComplete?: string | undefined;
  userCode: string;
  expiresInSeconds?: number | undefined;
}

export interface IDeviceCodePresenter {
  /** Show the prompt; resolves once it has been shown. */
  present(prompt: DeviceCodePrompt): Promise<void>;
}

/**
 * The logger's info, or stderr without one — never stdout. The prompt's
 * values come from the authorization server: the verification URI is shown
 * only as `promptableUrl` admits it, the user code only as `promptableText`
 * does (printable ASCII), so no control character forges or reorders a line.
 * Without an admitted URI or code nothing is shown and `present` rejects
 * (`interactive-login`, `device-code-not-shown`); an inadmissible complete
 * URI is left out.
 */
export function consoleDeviceCodePresenter(
  logger?: ILogger,
): IDeviceCodePresenter {
  const announce = announcer(logger);
  return {
    async present(prompt) {
      const shownUri = promptableUrl(prompt.verificationUri);
      const shownCode = promptableText(prompt.userCode);
      if (shownUri === undefined || shownCode === undefined) {
        throw loginFailure({ outcome: 'device-code-not-shown' });
      }
      const shownComplete = promptableUrl(prompt.verificationUriComplete);
      announce('OIDC device authorization');
      announce(`Go to: ${shownUri}`);
      if (shownComplete !== undefined) {
        announce(`Or use: ${shownComplete}`);
      }
      announce(`Enter code: ${shownCode}`);
    },
  };
}
