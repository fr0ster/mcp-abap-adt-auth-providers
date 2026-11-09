/**
 * Each credential provider's
 * own refusals — kind, facts and the verbatim 5.4.2 words — and the
 * operation each credential's moments name.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type {
  AuthOutcome,
  ICertificateMaterial,
  IClientAuthentication,
  IRequestTarget,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import {
  BaseTokenProvider,
  BasicAuthProvider,
  CertificateAuthProvider,
  SamlAuthProvider,
  TokenAuthProvider,
} from '../../index';
import { refreshThenLogin } from '../../renewal';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { mintedRefusal } from '../helpers/minted';
import { CERTIFICATES } from '../helpers/packagePaths';
import { recordingTargets } from '../helpers/targets';

const MARKER = 'SECRET-MARKER';
const r401 = { at: 'request' as const, status: 401, error: {} };
const logonRefused = {
  at: 'logon' as const,
  error: { key: 'RFC_LOGON_FAILURE' },
};
const throwingRequest: IRequestTarget = {
  header: () => {
    throw new Error(MARKER);
  },
  cookies: () => {
    throw new Error(MARKER);
  },
};

const dir = CERTIFICATES;
const read = (name: string) => readFileSync(join(dir, name));
const A: ICertificateMaterial = {
  cert: read('client.crt'),
  key: read('client.key'),
};
const B: ICertificateMaterial = {
  cert: read('other.crt'),
  key: read('other.key'),
};

/** The minted refusal of `outcome`, with no marker anywhere. */
function refusal(outcome: AuthOutcome) {
  notContains(JSON.stringify(outcome), MARKER);
  return mintedRefusal(outcome);
}

describe('A.2 — the credentials’ own refusals', () => {
  it('Basic, a refused credential → credential-refused user-password, verbatim', async () => {
    const error = refusal(await new BasicAuthProvider('u', 'p').rejected(r401));
    assert.equal(error.kind, 'credential-refused');
    assert.deepEqual(error.facts, {
      credential: 'user-password',
      at: 'request',
    });
    assert.equal(error.reason, 'the user or password was refused');
    assert.equal(error.hint, 'check the user and password');
    const logon = refusal(
      await new BasicAuthProvider('u', 'p').rejected(logonRefused),
    );
    assert.deepEqual(logon.facts, { credential: 'user-password', at: 'logon' });
  });

  it('Certificate, establish before prepare → not-prepared certificate, verbatim', async () => {
    const p = new CertificateAuthProvider({ load: async () => A }, {} as never);
    const error = refusal(await p.establish(recordingTargets().logonTarget));
    assert.equal(error.kind, 'not-prepared');
    assert.deepEqual(error.facts, { provider: 'certificate' });
    assert.equal(error.reason, 'the certificate is not loaded');
    assert.equal(error.hint, 'connect() prepares it first');
  });

  it('Certificate, a refused credential → credential-refused client-certificate, verbatim', async () => {
    const p = new CertificateAuthProvider({ load: async () => A }, {} as never);
    const error = refusal(await p.rejected(logonRefused));
    assert.equal(error.kind, 'credential-refused');
    assert.deepEqual(error.facts, {
      credential: 'client-certificate',
      at: 'logon',
    });
    assert.equal(error.reason, 'the client certificate was refused');
    assert.equal(
      error.hint,
      'check that it is mapped to a user (CERTRULE / USREXTID)',
    );
  });

  it('SAML cookies, a refused credential → credential-refused saml-session, verbatim', async () => {
    const error = refusal(await new SamlAuthProvider('S=x').rejected(r401));
    assert.equal(error.kind, 'credential-refused');
    assert.deepEqual(error.facts, {
      credential: 'saml-session',
      at: 'request',
    });
    assert.equal(error.reason, 'the SAML session was refused or has expired');
    assert.equal(error.hint, 'obtain a new SAML session');
  });

  it('a fixed token, a refused credential → credential-refused token, verbatim', async () => {
    const error = refusal(await TokenAuthProvider.fixed('t').rejected(r401));
    assert.equal(error.kind, 'credential-refused');
    assert.deepEqual(error.facts, { credential: 'token', at: 'request' });
    assert.equal(error.reason, 'the token was refused');
    assert.equal(error.hint, 'obtain a new token');
  });

  it('a token source renewing to the refused token → renewal-unchanged token-source, verbatim', async () => {
    const p = TokenAuthProvider.from({
      getToken: async () => 'SAME',
      refreshToken: async () => 'SAME',
    });
    await p.authorize(recordingTargets().requestTarget);
    const error = refusal(await p.rejected(r401));
    assert.equal(error.kind, 'renewal-unchanged');
    assert.deepEqual(error.facts, { source: 'token-source' });
    assert.equal(
      error.reason,
      'the renewal returned the credential that was refused',
    );
    assert.equal(error.hint, 'the token source must issue a new token');
  });

  it('a token provider renewing to the refused token → renewal-unchanged token-provider, verbatim', async () => {
    class Same extends BaseTokenProvider {
      protected async performLogin(): Promise<ITokenResult> {
        return {
          authorizationToken: 'SAME',
          authType: 'client_credentials',
          expiresAt: Date.now() + 3600_000,
        };
      }
      protected performRefresh(): Promise<ITokenResult> {
        return this.performLogin();
      }
      protected getAuthType(): OAuth2GrantType {
        return 'client_credentials';
      }
    }
    const p = new Same({ renewal: refreshThenLogin() });
    await p.authorize(recordingTargets().requestTarget);
    const error = refusal(await p.rejected(r401));
    assert.equal(error.kind, 'renewal-unchanged');
    assert.deepEqual(error.facts, { source: 'token-provider' });
    assert.equal(
      error.reason,
      'the renewal returned the credential that was refused',
    );
    assert.equal(
      error.hint,
      'the token source must issue a new token; log in again',
    );
  });

  describe('the operation each credential moment names, verbatim words', () => {
    for (const [caseIndex, caseRow] of cases([
      [
        'Basic authorize',
        () => new BasicAuthProvider('u', 'p').authorize(throwingRequest),
        'writing-authorization-header',
        'writing the Authorization header failed (unknown error)',
      ],
      [
        'Basic establish',
        () =>
          new BasicAuthProvider('u', 'p').establish({
            tlsMaterial: () => ({ ok: true }),
            logonParameters: () => {
              throw new Error(MARKER);
            },
          }),
        'offering-logon-parameters',
        'offering the logon parameters failed (unknown error)',
      ],
      [
        'SAML authorize',
        () => new SamlAuthProvider('S=x').authorize(throwingRequest),
        'writing-session-cookies',
        'writing the session cookies failed (unknown error)',
      ],
      [
        'Certificate prepare',
        () =>
          new CertificateAuthProvider(
            {
              load: async () => {
                throw Object.assign(new Error(MARKER), { code: 'ENOENT' });
              },
            },
            {} as never,
          ).prepare(),
        'loading-certificate',
        'loading the certificate failed (unknown error, ENOENT)',
      ],
      [
        'Certificate establish',
        async () => {
          const p = new CertificateAuthProvider(
            { load: async () => A },
            {} as never,
          );
          await p.prepare();
          return p.establish({
            tlsMaterial: () => {
              throw new Error(MARKER);
            },
            logonParameters: () => ({ ok: true }),
          });
        },
        'presenting-certificate',
        'presenting the certificate failed (unknown error)',
      ],
      [
        'Token authorize',
        () =>
          TokenAuthProvider.from({
            getToken: async () => {
              throw new Error(MARKER);
            },
            refreshToken: async () => 'x',
          }).authorize(recordingTargets().requestTarget),
        'token-source',
        'the token source failed (unknown error)',
      ],
      [
        'Token rejected',
        () =>
          TokenAuthProvider.from({
            getToken: async () => 'x',
            refreshToken: async () => {
              throw new Error(MARKER);
            },
          }).rejected(r401),
        'token-source',
        'the token source failed (unknown error)',
      ],
    ]).entries()) {
      const [_name, run, operation, reason] = caseRow;
      it(caseTitle('%s → %s', caseRow, caseIndex), async () => {
        const error = refusal(await run());
        assert.equal(error.kind, 'unknown');
        matchObject(error.facts, { operation });
        assert.equal(error.reason, reason);
      });
    }
  });
});

describe('A.1 — the token binding refusals', () => {
  const b64url = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const boundTo = (material: ICertificateMaterial) =>
    `${b64url({ alg: 'none' })}.${b64url({
      exp: Math.floor(Date.now() / 1000) + 3600,
      cnf: { 'x5t#S256': certificateThumbprint(material) },
    })}.sig`;

  class Issuing extends BaseTokenProvider {
    constructor(
      private readonly token: string,
      clientAuthentication?: IClientAuthentication,
    ) {
      super({
        renewal: refreshThenLogin(),
        ...(clientAuthentication ? { clientAuthentication } : {}),
      });
    }
    protected async performLogin(): Promise<ITokenResult> {
      return {
        authorizationToken: this.token,
        authType: 'client_credentials',
        expiresAt: Date.now() + 3600_000,
      };
    }
    protected performRefresh(): Promise<ITokenResult> {
      return this.performLogin();
    }
    protected getAuthType(): OAuth2GrantType {
      return 'client_credentials';
    }
  }

  it('a bound token, nothing pinned → token-binding bound-to-unpinned, verbatim', async () => {
    const p = new Issuing(boundTo(A));
    const error = refusal(await p.authorize(recordingTargets().requestTarget));
    assert.equal(error.kind, 'token-binding');
    assert.deepEqual(error.facts, { problem: 'bound-to-unpinned' });
    assert.equal(
      error.reason,
      'the token is bound to a client certificate this provider does not present',
    );
    assert.equal(
      error.hint,
      'give the provider a clientAuthentication that presents the certificate the token was issued for',
    );
  });

  it('A pinned, the renewed token bound to B → token-binding renewed-bound-elsewhere, verbatim', async () => {
    const strategy: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: async () => A,
    };
    const p = new Issuing(boundTo(B), strategy);
    const t = recordingTargets();
    const error = refusal(await p.authorize(t.requestTarget));
    assert.equal(error.kind, 'token-binding');
    assert.deepEqual(error.facts, { problem: 'renewed-bound-elsewhere' });
    assert.equal(
      error.reason,
      'the new token is bound to a client certificate this provider does not present',
    );
    assert.equal(
      error.hint,
      'the authorization server bound the new token to another certificate: check the certificate registered for this client',
    );
    assert.deepEqual(t.request.headers, {});
  });

  it('the remembered refusal is answered itself — the same minted object every time', async () => {
    const strategy: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: async () => A,
    };
    const p = new Issuing(boundTo(B), strategy);
    const first = refusal(await p.authorize(recordingTargets().requestTarget));
    const second = refusal(await p.authorize(recordingTargets().requestTarget));
    assert.equal(second, first);
    assert.deepEqual(second.facts, { problem: 'renewed-bound-elsewhere' });
  });
});
