/**
 * How the user learns where to go and what to enter in a device flow. Injected
 * like a strategy: the provider hands over structured data, and the consumer's
 * UI renders it its own way.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer } from '../auth/announce';

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

/** The logger's info, or stderr without one — never stdout. */
export function consoleDeviceCodePresenter(
  logger?: ILogger,
): IDeviceCodePresenter {
  const announce = announcer(logger);
  return {
    async present(prompt) {
      announce('OIDC device authorization');
      announce(`Go to: ${prompt.verificationUri}`);
      if (prompt.verificationUriComplete) {
        announce(`Or use: ${prompt.verificationUriComplete}`);
      }
      announce(`Enter code: ${prompt.userCode}`);
    },
  };
}
