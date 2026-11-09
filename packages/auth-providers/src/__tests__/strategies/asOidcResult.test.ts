import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { asOidcResult } from '../../strategies/asOidcResult';

describe('asOidcResult', () => {
  it('wraps a code and leaves the redirect URI alone', async () => {
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({
        payload: 'the-code',
        redirectUri: 'http://localhost:61001/callback',
      }),
    };
    const outcome = await asOidcResult(inner).authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/authorize',
    });
    assert.deepEqual(outcome.payload, { code: 'the-code' });
    assert.equal(outcome.redirectUri, 'http://localhost:61001/callback');
  });

  it('delegates dispose', async () => {
    const dispose = mock.fn(async () => undefined);
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({ payload: 'c', redirectUri: 'u' }),
      dispose,
    };
    const adapted = asOidcResult(inner);
    await adapted.dispose?.();
    await adapted.dispose?.();
    assert.equal(dispose.mock.callCount(), 2);
  });

  it('has no dispose when the wrapped strategy has none', () => {
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({ payload: 'c', redirectUri: 'u' }),
    };
    assert.equal(asOidcResult(inner).dispose, undefined);
  });
});
