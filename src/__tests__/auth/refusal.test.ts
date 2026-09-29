import { describe, expect, it } from '@jest/globals';
import { OK, oops, refusalFrom, safely } from '../../auth/refusal';
import { AssertionValidationError } from '../../errors/AssertionValidationError';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from '../../errors/TokenProviderErrors';

const text = (x: unknown) => JSON.stringify(x);

describe('refusal', () => {
  it('OK and oops build the two outcomes', () => {
    expect(OK).toEqual({ ok: true });
    expect(oops('r', 'h')).toEqual({
      ok: false,
      refusal: { reason: 'r', hint: 'h' },
    });
    expect(oops('r')).toEqual({ ok: false, refusal: { reason: 'r' } });
  });

  it.each([
    [
      new BrowserAuthError('SECRET-MSG'),
      'the interactive login did not complete',
      "complete the login within the strategy's time",
    ],
    [
      new RefreshError('SECRET-MSG'),
      'the refresh token was refused',
      'log in again',
    ],
    [
      new ValidationError('SECRET-MSG', ['clientId']),
      'the provider configuration is incomplete or invalid: clientId',
      'check the provider configuration',
    ],
    [
      new ServiceKeyError('SECRET-MSG', ['uaaUrl']),
      'the service key or session data is incomplete: uaaUrl',
      'check the service key or session data',
    ],
    [
      new SessionDataError('SECRET-MSG', ['refreshToken']),
      'the service key or session data is incomplete: refreshToken',
      'check the service key or session data',
    ],
  ])('%p → fixed wording, never its message', (error, reason, hint) => {
    expect(refusalFrom(error, 'it')).toEqual({
      ok: false,
      refusal: { reason, hint },
    });
  });

  it('an assertion refusal names its check only when it is an AssertionCheck', () => {
    expect(
      refusalFrom(new AssertionValidationError('issuer', 'SECRET'), 'it'),
    ).toEqual({
      ok: false,
      refusal: { reason: 'the SAML assertion was refused (issuer)' },
    });
    const forged = Object.assign(new AssertionValidationError('issuer', 'x'), {
      check: 'SECRET_CHECK',
    });
    expect(text(refusalFrom(forged, 'it'))).not.toMatch(/SECRET/);
  });

  it('foreign callback text wrapped in BrowserAuthError stays out', () => {
    const wrapped = new BrowserAuthError(
      'access_denied: SECRET-IDP-DESCRIPTION (https://idp/SECRET-URI)',
    );
    expect(text(refusalFrom(wrapped, 'it'))).not.toMatch(/SECRET/);
  });

  it('a field name not in KNOWN_CONFIG_FIELDS is dropped', () => {
    expect(
      refusalFrom(new ValidationError('x', ['clientId', 'SECRET-FIELD']), 'it'),
    ).toEqual({
      ok: false,
      refusal: {
        reason: 'the provider configuration is incomplete or invalid: clientId',
        hint: 'check the provider configuration',
      },
    });
    expect(
      refusalFrom(new ValidationError('x', ['SECRET-FIELD']), 'it'),
    ).toMatchObject({
      refusal: {
        reason: 'the provider configuration is incomplete or invalid',
      },
    });
  });

  it('another own error: its class label, no message', () => {
    expect(
      refusalFrom(new TokenProviderError('SECRET', 'CODE'), 'x token request'),
    ).toEqual({
      ok: false,
      refusal: { reason: 'x token request failed (TokenProviderError)' },
    });
  });

  it('a foreign error: "unknown error", plus an allowlisted code only', () => {
    const axios = Object.assign(new Error('Basic U0VDUkVU'), {
      name: 'AxiosError',
      code: 'ECONNREFUSED',
      response: { data: 'SECRET' },
    });
    expect(refusalFrom(axios, 'the token endpoint')).toEqual({
      ok: false,
      refusal: {
        reason: 'the token endpoint failed (unknown error, ECONNREFUSED)',
      },
    });
    const forged = Object.assign(new Error('x'), {
      name: 'SECRETError',
      code: 'ESECRET',
    });
    expect(refusalFrom(forged, 'it')).toEqual({
      ok: false,
      refusal: { reason: 'it failed (unknown error)' },
    });
  });

  it('a thrown string or object lends nothing', () => {
    expect(refusalFrom('SECRET-STRING', 'it')).toEqual({
      ok: false,
      refusal: { reason: 'it failed (unknown error)' },
    });
    expect(
      text(
        refusalFrom(
          { message: 'SECRET', key: 'SECRET_KEY', code: 'ENOENT' },
          'it',
        ),
      ),
    ).toBe(
      text({
        ok: false,
        refusal: { reason: 'it failed (unknown error, ENOENT)' },
      }),
    );
  });

  it('safely: sync throw, async rejection and a returned outcome', async () => {
    await expect(
      safely('it', () => {
        throw new Error('SECRET');
      }),
    ).resolves.toEqual({
      ok: false,
      refusal: { reason: 'it failed (unknown error)' },
    });
    await expect(
      safely('it', async () => {
        throw new RefreshError('SECRET');
      }),
    ).resolves.toMatchObject({
      ok: false,
      refusal: { reason: 'the refresh token was refused' },
    });
    await expect(safely('it', () => OK)).resolves.toEqual({ ok: true });
  });
});
