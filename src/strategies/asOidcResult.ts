/**
 * Adapts a code-producing strategy to the OIDC provider's payload type.
 *
 * Everything a human or a consumer hands back is a string; only a real callback
 * carries `state` beside the code. Rather than an OIDC twin of every strategy,
 * the mismatch is bridged in one place.
 */

import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces';
import type { OidcCallbackResult } from '../auth/oidcBrowserAuth';

export function asOidcResult(
  inner: IAuthorizationStrategy<string>,
): IAuthorizationStrategy<OidcCallbackResult> {
  const adapted: IAuthorizationStrategy<OidcCallbackResult> = {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<OidcCallbackResult>> {
      const outcome = await inner.authorize(request);
      // No `state`: a value that never travelled through a redirect has none
      // to check.
      return {
        payload: { code: outcome.payload },
        redirectUri: outcome.redirectUri,
      };
    },
  };
  // Delegated, not reimplemented: the consumer holds only the adapter, so an
  // undelegated dispose would strand whatever the wrapped strategy owns. Absent
  // when the wrapped strategy has none, so optionality survives the wrapping.
  if (inner.dispose) {
    adapted.dispose = () => inner.dispose?.() ?? Promise.resolve();
  }
  return adapted;
}
