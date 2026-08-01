import { describe, expect, it, jest } from '@jest/globals';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces';
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
    expect(outcome.payload).toEqual({ code: 'the-code' });
    expect(outcome.redirectUri).toBe('http://localhost:61001/callback');
  });

  it('delegates dispose', async () => {
    const dispose = jest.fn(async () => undefined);
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({ payload: 'c', redirectUri: 'u' }),
      dispose,
    };
    const adapted = asOidcResult(inner);
    await adapted.dispose?.();
    await adapted.dispose?.();
    expect(dispose).toHaveBeenCalledTimes(2);
  });

  it('has no dispose when the wrapped strategy has none', () => {
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({ payload: 'c', redirectUri: 'u' }),
    };
    expect(asOidcResult(inner).dispose).toBeUndefined();
  });
});
