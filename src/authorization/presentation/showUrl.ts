/**
 * `showUrl()` (spec §6d.2, C8): the authorization URL to stderr only, the
 * logger the fixed line "the authorization URL was shown", then where the
 * channel waits and its route hint. Synchronous; it never fails.
 */

import type {
  IAuthorizationPresentation,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import { promptAuthorizationUrl, promptContext } from './prompt';

export function showUrl(): IAuthorizationPresentation {
  return Object.freeze({
    present(authorizationUrl: string, context: PresentationContext): unknown {
      promptAuthorizationUrl(
        authorizationUrl,
        promptContext(context),
        '🔗 Open this URL in your browser to authenticate:',
      );
      return undefined;
    },
  });
}
