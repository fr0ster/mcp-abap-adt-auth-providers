/**
 * A canceled token request, or a canceled discovery, stays a cancellation
 * after its rejection is replaced by a safe error: `axios.isCancel` and
 * `axios.isAxiosError` both hold, so a consumer that aborts can tell an abort
 * from a failure. Nothing of the original is kept. Real axios, unmocked: the
 * request is aborted before it is sent, through `axios.defaults.signal`.
 */

import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
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
  ])('%s: still a cancellation, in fixed words', async (_label, run) => {
    let thrown: unknown;
    const failed = expect(
      run().catch((error: unknown) => {
        thrown = error;
        throw error;
      }),
    ).rejects.toBeDefined();
    await failed;
    expect(axios.isCancel(thrown)).toBe(true);
    expect(axios.isAxiosError(thrown)).toBe(true);
    const error = thrown as Error & { config?: unknown; cause?: unknown };
    expect(error.message).toBe('the token request was canceled');
    expect(error.config).toBeUndefined();
    expect(error.cause).toBeUndefined();
    expect(inspect(error, { depth: null })).not.toContain(NOWHERE);
  });

  it('a wrapping site keeps the cancellation as its safe cause', async () => {
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
    const cause = (thrown as { cause?: unknown }).cause;
    expect(axios.isCancel(cause)).toBe(true);
    expect(inspect(thrown, { depth: null })).not.toContain(NOWHERE);
  });
});
