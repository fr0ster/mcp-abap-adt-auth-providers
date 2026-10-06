import { describe, expect, it } from '@jest/globals';
import { OK, oops, refusalFrom, safely } from '../../auth/refusal';
import { DeviceCodePresentationError } from '../../deviceCode/DeviceCodePresenter';
import { AssertionValidationError } from '../../errors/AssertionValidationError';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from '../../errors/TokenProviderErrors';
import { wordsOf } from '../helpers/minted';

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
      // A9: the outcome's words (K11) and the new hint (§6a).
      new BrowserAuthError('SECRET-MSG'),
      'the browser login failed (unknown error)',
      'complete the login, or abort it',
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
    expect(wordsOf(refusalFrom(error, 'it'))).toEqual({
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

  it('another own error: unknown with the operation, no message (A13: the class label is lost, L11)', () => {
    expect(
      wordsOf(
        refusalFrom(
          new TokenProviderError('SECRET', 'CODE'),
          'password token request',
        ),
      ),
    ).toEqual({
      ok: false,
      refusal: { reason: 'password token request failed (unknown error)' },
    });
  });

  it('a foreign error: "unknown error", plus an allowlisted code only', () => {
    const axios = Object.assign(new Error('Basic U0VDUkVU'), {
      name: 'AxiosError',
      code: 'ECONNREFUSED',
      response: { data: 'SECRET' },
    });
    expect(wordsOf(refusalFrom(axios, 'the token request'))).toEqual({
      ok: false,
      refusal: {
        reason: 'the token request failed (unknown error, ECONNREFUSED)',
      },
    });
    const forged = Object.assign(new Error('x'), {
      name: 'SECRETError',
      code: 'ESECRET',
    });
    expect(wordsOf(refusalFrom(forged, 'the token request'))).toEqual({
      ok: false,
      refusal: { reason: 'the token request failed (unknown error)' },
    });
  });

  it('a thrown string or object lends nothing', () => {
    expect(wordsOf(refusalFrom('SECRET-STRING', 'the token source'))).toEqual({
      ok: false,
      refusal: { reason: 'the token source failed (unknown error)' },
    });
    expect(
      text(
        refusalFrom(
          { message: 'SECRET', key: 'SECRET_KEY', code: 'ENOENT' },
          'loading the certificate',
        ),
      ),
    ).toBe(
      text({
        ok: false,
        refusal: {
          kind: 'unknown',
          facts: { operation: 'loading-certificate', code: 'ENOENT' },
          reason: 'loading the certificate failed (unknown error, ENOENT)',
        },
      }),
    );
  });

  it('a presenter failure is the fixed device-code refusal', () => {
    expect(
      wordsOf(
        refusalFrom(new DeviceCodePresentationError(), 'x token request'),
      ),
    ).toEqual({
      ok: false,
      refusal: { reason: 'showing the device code failed' },
    });
  });

  it('safely: sync throw, async rejection and a returned outcome', async () => {
    expect(
      wordsOf(
        await safely('the token source', () => {
          throw new Error('SECRET');
        }),
      ),
    ).toEqual({
      ok: false,
      refusal: { reason: 'the token source failed (unknown error)' },
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

describe('shared word and outcome objects are frozen', () => {
  it('every one a refusal, a log line or a provider hands out', async () => {
    const certificate = await import('../../errors/CertificateMaterialError');
    const client = await import('../../errors/ClientAuthenticationError');
    const refusal = await import('../../auth/refusal');
    const shared: object[] = [
      certificate.CERTIFICATE_INCOMPLETE,
      certificate.CERTIFICATE_UNUSABLE,
      certificate.CERTIFICATE_EXPIRED,
      client.CLIENT_KEY_UNUSABLE,
      client.CLIENT_AUTHENTICATION_UNUSABLE,
      client.BASIC_CLIENT_ID_UNUSABLE,
      refusal.OK,
      refusal.TOKEN_BOUND_ELSEWHERE,
      refusal.TOKEN_RENEWED_BOUND_ELSEWHERE,
    ];
    for (const words of shared) expect(Object.isFrozen(words)).toBe(true);
  });
});
