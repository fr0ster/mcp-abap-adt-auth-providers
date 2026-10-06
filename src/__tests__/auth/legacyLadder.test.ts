/**
 * TRANSITION TEST — removed in Task 27 with the class ladder (Decision D6).
 *
 * `refusalFrom`'s ladder: each of this package's 13 error classes (A.1) →
 * its builder per Appendix A. Three rows cannot be built from what their
 * class carries, so they keep their 5.4.2 words, unminted, until their
 * producers move: A3 (`AssertionValidationError` carries a `check` but no
 * `rule`, which `saml-assertion` requires — Task 24), A11 (`ValidationError`
 * carries `missingFields` but no `case` — Task 26) and A12 (`ServiceKeyError`
 * / `SessionDataError`: no kind; no producer in this package — Task 27).
 */
import { describe, expect, it } from '@jest/globals';
import { isMinted } from '@mcp-abap-adt/auth-errors';
import type { AuthOutcome } from '@mcp-abap-adt/interfaces-auth';
import { AuthorizationRefusedError } from '../../auth/callbackScopeError';
import { refusalFrom } from '../../auth/refusal';
import { DeviceCodePresentationError } from '../../deviceCode/DeviceCodePresenter';
import { AssertionValidationError } from '../../errors/AssertionValidationError';
import { CertificateMaterialError } from '../../errors/CertificateMaterialError';
import {
  BasicClientIdError,
  ClientAuthenticationError,
  ClientAuthenticationResultError,
} from '../../errors/ClientAuthenticationError';
import { TokenEndpointError } from '../../errors/TokenEndpointError';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from '../../errors/TokenProviderErrors';
import { mintedRefusal } from '../helpers/minted';

const MARKER = 'SECRET-MARKER';
const WHAT = 'client_credentials token request';

const words = (outcome: AuthOutcome) => {
  expect(JSON.stringify(outcome)).not.toContain(MARKER);
  return mintedRefusal(outcome);
};

describe('legacy ladder: each class of this package → its kind', () => {
  it('DeviceCodePresentationError → interactive-login device-code-not-shown (A2)', () => {
    const error = words(refusalFrom(new DeviceCodePresentationError(), WHAT));
    expect(error.kind).toBe('interactive-login');
    expect(error.facts).toEqual({ outcome: 'device-code-not-shown' });
    expect(error.reason).toBe('showing the device code failed');
  });

  it.each([
    [new CertificateMaterialError(true), 'incomplete'],
    [new CertificateMaterialError(false), 'unusable'],
    [new CertificateMaterialError(false, true), 'expired'],
  ])('CertificateMaterialError → client-certificate %#', (thrown, problem) => {
    const error = words(refusalFrom(thrown, WHAT));
    expect(error.kind).toBe('client-certificate');
    expect(error.facts).toEqual({ problem });
  });

  it('ClientAuthenticationResultError → client-authentication result-unsendable (A5)', () => {
    const error = words(
      refusalFrom(new ClientAuthenticationResultError(), WHAT),
    );
    expect(error.kind).toBe('client-authentication');
    expect(error.facts).toEqual({ problem: 'result-unsendable' });
    expect(error.reason).toBe(
      'the client authentication returned a request that cannot be sent',
    );
    expect(error.hint).toBe('check the client authentication strategy');
  });

  it('ClientAuthenticationError → client-authentication signing-key-unusable (A6)', () => {
    const error = words(refusalFrom(new ClientAuthenticationError(), WHAT));
    expect(error.kind).toBe('client-authentication');
    expect(error.facts).toEqual({ problem: 'signing-key-unusable' });
    expect(error.reason).toBe('the client signing key could not be used');
  });

  it('BasicClientIdError → client-authentication basic-client-id-colon (A7)', () => {
    const error = words(refusalFrom(new BasicClientIdError(), WHAT));
    expect(error.kind).toBe('client-authentication');
    expect(error.facts).toEqual({ problem: 'basic-client-id-colon' });
    expect(error.reason).toBe(
      "the client id contains ':', which raw Basic cannot carry",
    );
  });

  it('BrowserAuthError from an IdP refusal → interactive-login identity-provider-refused (A8)', () => {
    const refused = words(
      refusalFrom(
        new BrowserAuthError(
          MARKER,
          new AuthorizationRefusedError('access_denied'),
        ),
        WHAT,
      ),
    );
    expect(refused.kind).toBe('interactive-login');
    expect(refused.facts).toEqual({
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
    expect(refused.reason).toBe(
      'the identity provider refused the login (access_denied)',
    );
    expect(refused.hint).toBe(
      'check the identity provider: the user, the client and the scopes it allows',
    );
    const unregistered = words(
      refusalFrom(
        new BrowserAuthError(MARKER, new AuthorizationRefusedError(MARKER)),
        WHAT,
      ),
    );
    expect(unregistered.facts).toEqual({
      outcome: 'identity-provider-refused',
    });
    expect(unregistered.reason).toBe(
      'the identity provider refused the login (an unregistered error code)',
    );
  });

  it('any other BrowserAuthError → interactive-login failed (A9)', () => {
    const error = words(refusalFrom(new BrowserAuthError(MARKER), WHAT));
    expect(error.kind).toBe('interactive-login');
    expect(error.facts).toEqual({ outcome: 'failed' });
    expect(error.reason).toBe('the browser login failed (unknown error)');
    expect(error.hint).toBe('complete the login, or abort it');
  });

  it('RefreshError → credential-refused refresh-token (A10)', () => {
    const error = words(refusalFrom(new RefreshError(MARKER), WHAT));
    expect(error.kind).toBe('credential-refused');
    expect(error.facts).toEqual({ credential: 'refresh-token' });
    expect(error.reason).toBe('the refresh token was refused');
    expect(error.hint).toBe('log in again');
  });

  it('TokenEndpointError → request-failed (A14)', () => {
    const error = words(
      refusalFrom(new TokenEndpointError(MARKER, { status: 400 }), WHAT),
    );
    expect(error.kind).toBe('request-failed');
    expect(error.facts).toEqual({
      operation: 'token-request',
      grant: 'client_credentials',
      problem: 'refused',
      status: 400,
    });
  });

  it('TokenProviderError → unknown with the operation (A13)', () => {
    const error = words(
      refusalFrom(new TokenProviderError(MARKER, 'CODE'), WHAT),
    );
    expect(error.kind).toBe('unknown');
    expect(error.facts).toEqual({
      operation: 'token-request',
      grant: 'client_credentials',
    });
  });

  it('AssertionValidationError keeps its 5.4.2 words, unminted, until Task 24 (A3)', () => {
    const outcome = refusalFrom(
      new AssertionValidationError('issuer', MARKER),
      WHAT,
    );
    expect(outcome).toEqual({
      ok: false,
      refusal: { reason: 'the SAML assertion was refused (issuer)' },
    });
    expect(!outcome.ok && isMinted(outcome.refusal)).toBe(false);
    const forged = Object.assign(new AssertionValidationError('issuer', 'x'), {
      check: MARKER,
    });
    expect(refusalFrom(forged, WHAT)).toEqual({
      ok: false,
      refusal: { reason: 'the SAML assertion was refused' },
    });
  });

  it('ValidationError keeps its 5.4.2 words, unminted, until Task 26 (A11)', () => {
    const outcome = refusalFrom(
      new ValidationError(MARKER, ['clientId', MARKER]),
      WHAT,
    );
    expect(outcome).toEqual({
      ok: false,
      refusal: {
        reason: 'the provider configuration is incomplete or invalid: clientId',
        hint: 'check the provider configuration',
      },
    });
    expect(!outcome.ok && isMinted(outcome.refusal)).toBe(false);
  });

  it.each([
    [new ServiceKeyError(MARKER, ['uaaUrl']), 'uaaUrl'],
    [new SessionDataError(MARKER, ['refreshToken']), 'refreshToken'],
  ])('%p keeps its 5.4.2 words, unminted (A12)', (thrown, field) => {
    const outcome = refusalFrom(thrown, WHAT);
    expect(outcome).toEqual({
      ok: false,
      refusal: {
        reason: `the service key or session data is incomplete: ${field}`,
        hint: 'check the service key or session data',
      },
    });
    expect(!outcome.ok && isMinted(outcome.refusal)).toBe(false);
  });

  it('anything else reaches classify', () => {
    const error = words(
      refusalFrom(Object.assign(new Error(MARKER), { status: 418 }), WHAT),
    );
    expect(error.kind).toBe('unknown');
    expect(error.facts).toEqual({
      operation: 'token-request',
      grant: 'client_credentials',
      status: 418,
    });
  });
});
