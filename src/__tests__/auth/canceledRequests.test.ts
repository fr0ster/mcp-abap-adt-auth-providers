/**
 * A canceled token request, or a canceled discovery, is replaced like every
 * other rejection (spec §6, D2; L3: the `AxiosError` identity, and with it
 * `axios.isCancel`, is lost): an `AuthProviderFailure` of the site's
 * operation, `request-failed` `no-response`, nothing of the original kept.
 * TRANSITION: the abort's own kind and the consumer's signal are Task 22a's
 * (spec §6b, C6); until then a cancellation reads as no response. Real axios,
 * unmocked: the request is aborted before it is sent, through
 * `axios.defaults.signal`.
 */

import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import axios from 'axios';
import { discoverOidc } from '../../auth/oidcDiscovery';
import { refreshOidcToken } from '../../auth/oidcToken';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import { clientSecretPost } from '../../clientAuthentication';

const NOWHERE = 'http://127.0.0.1:9';

describe('an aborted request', () => {
  let previous: typeof axios.defaults.signal;
  beforeEach(() => {
    previous = axios.defaults.signal;
    axios.defaults.signal = AbortSignal.abort();
  });
  afterEach(() => {
    if (previous === undefined) delete axios.defaults.signal;
    else axios.defaults.signal = previous;
  });

  it.each([
    [
      'OIDC discovery',
      () => discoverOidc(`${NOWHERE}/issuer-${Math.random()}`),
    ],
    [
      'OIDC refresh without a strategy',
      () => refreshOidcToken(`${NOWHERE}/token`, 'cid', 'secret', 'rt'),
    ],
    [
      'OIDC refresh with a strategy',
      () =>
        refreshOidcToken(
          `${NOWHERE}/token`,
          'cid',
          undefined,
          'rt',
          undefined,
          {
            strategy: clientSecretPost('secret'),
          },
        ),
    ],
  ])(
    '%s: an AuthProviderFailure, nothing of the original',
    async (_label, run) => {
      let thrown: unknown;
      const failed = expect(
        run().catch((error: unknown) => {
          thrown = error;
          throw error;
        }),
      ).rejects.toBeDefined();
      await failed;
      expect(isAuthProviderFailure(thrown)).toBe(true);
      expect(axios.isAxiosError(thrown)).toBe(false);
      const failure = readFailure(thrown, 'unfamiliar-error');
      expect(failure.kind).toBe('request-failed');
      expect(failure.facts).toMatchObject({ problem: 'no-response' });
      const error = thrown as Error & { config?: unknown; cause?: unknown };
      expect(error.config).toBeUndefined();
      expect(error.cause).toBeUndefined();
      expect(inspect(error, { depth: null })).not.toContain(NOWHERE);
    },
  );

  it('a site that wrapped its errors: the same, no cause', async () => {
    let thrown: unknown;
    const failed = expect(
      refreshJwtToken('rt', NOWHERE, 'cid', 'secret').catch(
        (error: unknown) => {
          thrown = error;
          throw error;
        },
      ),
    ).rejects.toBeDefined();
    await failed;
    expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
      operation: 'token-refresh',
      problem: 'no-response',
    });
    expect((thrown as { cause?: unknown }).cause).toBeUndefined();
    expect(inspect(thrown, { depth: null })).not.toContain(NOWHERE);
  });
});
