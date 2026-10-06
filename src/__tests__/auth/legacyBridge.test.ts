/**
 * TRANSITION TEST — removed in Task 27 with `legacyBridge` (Decision D6).
 *
 * guard's own `classify` does not know this package's error classes; the
 * bridge between guard and the `on…` call answers the ladder's refusal for a
 * body that throws one, so a class keeps its kind until its producers move
 * (Tasks 21–26). Anything else still reaches guard's `classify`.
 */
import { describe, expect, it } from '@jest/globals';
import { isMinted } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthProviderBase } from '../../auth/AuthProviderBase';
import { AuthorizationRefusedError } from '../../auth/callbackScopeError';
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
import { recordingTargets } from '../helpers/targets';

const MARKER = 'SECRET-MARKER';

/** A provider whose every moment throws `thrown`. */
class Throws extends AuthProviderBase {
  readonly kind = 'test';
  constructor(private readonly thrown: () => unknown) {
    super({
      prepare: 'token-request',
      establish: 'token-request',
      authorize: 'token-request',
      rejected: 'token-request',
    });
  }
  protected override grant(): OAuth2GrantType {
    return 'client_credentials';
  }
  private fail(): AuthOutcome {
    throw this.thrown();
  }
  protected onPrepare() {
    return this.fail();
  }
  protected onEstablish() {
    return this.fail();
  }
  protected onAuthorize() {
    return this.fail();
  }
  protected onRejected() {
    return this.fail();
  }
}

async function allFour(p: IAuthProvider) {
  const t = recordingTargets();
  return [
    await p.prepare(),
    await p.establish(t.logonTarget),
    await p.authorize(t.requestTarget),
    await p.rejected({ at: 'request', status: 401, error: {} }),
  ];
}

const OPERATION = { operation: 'token-request', grant: 'client_credentials' };

describe('legacyBridge: a ladder class thrown by a body keeps its kind', () => {
  it.each([
    [
      'DeviceCodePresentationError',
      () => new DeviceCodePresentationError(),
      'interactive-login',
      { outcome: 'device-code-not-shown' },
    ],
    [
      'CertificateMaterialError',
      () => new CertificateMaterialError(false, true),
      'client-certificate',
      { problem: 'expired' },
    ],
    [
      'ClientAuthenticationResultError',
      () => new ClientAuthenticationResultError(),
      'client-authentication',
      { problem: 'result-unsendable' },
    ],
    [
      'ClientAuthenticationError',
      () => new ClientAuthenticationError(),
      'client-authentication',
      { problem: 'signing-key-unusable' },
    ],
    [
      'BasicClientIdError',
      () => new BasicClientIdError(),
      'client-authentication',
      { problem: 'basic-client-id-colon' },
    ],
    [
      'BrowserAuthError (IdP refusal)',
      () =>
        new BrowserAuthError(
          MARKER,
          new AuthorizationRefusedError('access_denied'),
        ),
      'interactive-login',
      { outcome: 'identity-provider-refused', oauthError: 'access_denied' },
    ],
    [
      'BrowserAuthError',
      () => new BrowserAuthError(MARKER),
      'interactive-login',
      { outcome: 'failed' },
    ],
    [
      'RefreshError',
      () => new RefreshError(MARKER),
      'credential-refused',
      { credential: 'refresh-token' },
    ],
    [
      'TokenEndpointError',
      () => new TokenEndpointError(MARKER, { status: 401 }),
      'request-failed',
      { ...OPERATION, problem: 'refused', status: 401 },
    ],
    [
      'TokenProviderError',
      () => new TokenProviderError(MARKER, 'CODE'),
      'unknown',
      OPERATION,
    ],
    // A3: constructed by no site since Task 24 (every SAML site throws its
    // minted rule); an instance a consumer throws is any other own class,
    // A13's `unknown` with the operation and grant.
    [
      'AssertionValidationError (A3, an own class since Task 24)',
      () => new AssertionValidationError('issuer', MARKER),
      'unknown',
      OPERATION,
    ],
    // A11, A12: the ladder's 5.4.2 words are unminted, and guard answers
    // an unminted refusal with its own fallback — `unknown` with the
    // operation and grant — until Tasks 26 / 27 (spec §8.1).
    [
      'ValidationError (A11, until Task 26)',
      () => new ValidationError(MARKER, ['clientId']),
      'unknown',
      OPERATION,
    ],
    [
      'ServiceKeyError (A12, until Task 27)',
      () => new ServiceKeyError(MARKER, ['uaaUrl']),
      'unknown',
      OPERATION,
    ],
    [
      'SessionDataError (A12, until Task 27)',
      () => new SessionDataError(MARKER, ['refreshToken']),
      'unknown',
      OPERATION,
    ],
  ])('%s, through all four moments', async (_name, thrown, kind, facts) => {
    for (const outcome of await allFour(new Throws(thrown))) {
      expect(outcome.ok).toBe(false);
      if (outcome.ok) continue;
      expect(isMinted(outcome.refusal)).toBe(true);
      expect(outcome.refusal).toMatchObject({ kind, facts });
      expect(JSON.stringify(outcome)).not.toContain(MARKER);
    }
  });

  it("anything else still reaches guard's classify", async () => {
    const foreign = () =>
      Object.assign(new Error(MARKER), { response: { status: 503 } });
    for (const outcome of await allFour(new Throws(foreign))) {
      expect(outcome).toMatchObject({
        ok: false,
        refusal: { kind: 'unknown', facts: { ...OPERATION, status: 503 } },
      });
    }
  });
});
