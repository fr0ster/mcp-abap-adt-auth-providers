/**
 * A canceled token request, or a canceled discovery, is replaced like every
 * other rejection (the `AxiosError` identity, and with it
 * `axios.isCancel`, is lost): an `AuthProviderFailure` of the site's
 * operation, `request-failed` `no-response`, nothing of the original kept.
 * A cancellation that is not the site's own attempt's (here a global
 * `axios.defaults.signal`) still reads as no response; an attempt's own
 * signal ends a request `interactive-login` `aborted`
 * (`attemptSignals.test.ts`). Real axios,
 * unmocked: the request is aborted before it is sent, through
 * `axios.defaults.signal`.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { inspect } from 'node:util';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import axios from 'axios';
import { discoverOidc } from '../../auth/oidcDiscovery';
import { refreshOidcToken } from '../../auth/oidcToken';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import { clientSecretPost } from '../../clientAuthentication';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';

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

  for (const [caseIndex, caseRow] of cases([
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
  ]).entries()) {
    const [_label, run] = caseRow;
    it(
      caseTitle(
        '%s: an AuthProviderFailure, nothing of the original',
        caseRow,
        caseIndex,
      ),
      async () => {
        let thrown: unknown;
        const failed = assert.rejects(
          run().catch((error: unknown) => {
            thrown = error;
            throw error;
          }),
          (error) => error !== undefined,
        );
        await failed;
        assert.equal(isAuthProviderFailure(thrown), true);
        assert.equal(axios.isAxiosError(thrown), false);
        const failure = readFailure(thrown, 'unfamiliar-error');
        assert.equal(failure.kind, 'request-failed');
        matchObject(failure.facts, { problem: 'no-response' });
        const error = thrown as Error & { config?: unknown; cause?: unknown };
        assert.equal(error.config, undefined);
        assert.equal(error.cause, undefined);
        notContains(inspect(error, { depth: null }), NOWHERE);
      },
    );
  }

  it('a site that wrapped its errors: the same, no cause', async () => {
    let thrown: unknown;
    const failed = assert.rejects(
      refreshJwtToken('rt', NOWHERE, 'cid', 'secret').catch(
        (error: unknown) => {
          thrown = error;
          throw error;
        },
      ),
      (error) => error !== undefined,
    );
    await failed;
    assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
      operation: 'token-refresh',
      problem: 'no-response',
    });
    assert.equal((thrown as { cause?: unknown }).cause, undefined);
    notContains(inspect(thrown, { depth: null }), NOWHERE);
  });
});
