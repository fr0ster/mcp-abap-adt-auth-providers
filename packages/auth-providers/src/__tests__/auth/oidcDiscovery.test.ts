/**
 * OIDC discovery keeps a snapshot, not the document: the three endpoints the
 * providers read, each a non-empty string read through `readSafely`, and the
 * two mTLS aliases rebuilt as a plain object. Nothing else reaches the
 * snapshot, the cache or a provider. A document without `token_endpoint`,
 * or one that cannot be read, is `request-failed` `incomplete-response` of
 * `oidc-discovery` and is not cached; a transport rejection is `tls` or
 * `request-failed`.
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { beforeEach, describe, it, mock } from 'node:test';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IClientAuthentication,
  ITokenRequestDraft,
} from '@mcp-abap-adt/interfaces-auth';
import { discoverOidc, mtlsAlias } from '../../auth/oidcDiscovery';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { refreshThenLogin } from '../../renewal';
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';

let issuers = 0;
/** A fresh issuer: discovery is cached per URL. */
const freshIssuer = () => `https://idp-${++issuers}.example`;

const FULL = {
  issuer: 'https://idp.example',
  authorization_endpoint: 'https://idp.example/auth',
  token_endpoint: 'https://idp.example/token',
  device_authorization_endpoint: 'https://idp.example/device',
  jwks_uri: 'https://idp.example/jwks',
  end_session_endpoint: 'https://idp.example/logout',
  mtls_endpoint_aliases: {
    token_endpoint: 'https://mtls.idp.example/token',
    device_authorization_endpoint: 'https://mtls.idp.example/device',
    revocation_endpoint: 'https://mtls.idp.example/revoke',
  },
  extra_field: 'not in the snapshot',
};

const answering = (data: unknown) =>
  mockedAxios.get.mock.mockImplementation(async () => ({ status: 200, data }));

beforeEach(() => {
  resetAxiosMock();
});

async function failureOf(p: Promise<unknown>): Promise<unknown> {
  return p.then(
    () => {
      throw new Error('expected a rejection');
    },
    (error: unknown) => error,
  );
}

const INCOMPLETE = {
  operation: 'oidc-discovery',
  problem: 'incomplete-response',
};

describe('a successful discovery', () => {
  it('the snapshot holds the three endpoints and the two aliases, nothing else', async () => {
    answering(FULL);
    const snapshot = await discoverOidc(freshIssuer());
    assert.deepEqual(snapshot, {
      authorization_endpoint: 'https://idp.example/auth',
      token_endpoint: 'https://idp.example/token',
      device_authorization_endpoint: 'https://idp.example/device',
      mtls_endpoint_aliases: {
        token_endpoint: 'https://mtls.idp.example/token',
        device_authorization_endpoint: 'https://mtls.idp.example/device',
      },
    });
    assert.notEqual(snapshot.mtls_endpoint_aliases, FULL.mtls_endpoint_aliases);
  });

  it('the cache holds the snapshot: no field outside the list, one request', async () => {
    answering(FULL);
    const issuer = freshIssuer();
    const first = await discoverOidc(issuer);
    const second = await discoverOidc(issuer);
    assert.equal(second, first);
    assert.equal(mockedAxios.get.mock.callCount(), 1);
    for (const field of [
      'issuer',
      'jwks_uri',
      'end_session_endpoint',
      'extra_field',
    ]) {
      assert.equal(field in second, false);
    }
    assert.equal(
      'revocation_endpoint' in (second.mtls_endpoint_aliases ?? {}),
      false,
    );
  });

  it('a provider uses the discovered endpoint and its mTLS alias', async () => {
    const issuer = freshIssuer();
    answering({
      token_endpoint: `${issuer}/token`,
      mtls_endpoint_aliases: { token_endpoint: `${issuer}/mtls/token` },
    });
    const drafts: ITokenRequestDraft[] = [];
    const strategy: IClientAuthentication = {
      authenticate: async (draft) => {
        drafts.push(draft);
        return { parameters: { client_id: draft.clientId } };
      },
    };
    mockedAxios.mock.mockImplementation(async () => ({
      status: 200,
      data: { access_token: 'at', expires_in: 60 },
    }));
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      username: 'u',
      password: 'p',
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    matchObject(drafts[0], {
      endpoint: `${issuer}/token`,
      mtlsEndpoint: `${issuer}/mtls/token`,
    });
  });

  it('a marker string in a kept field is that field’s value (public metadata)', async () => {
    answering({ token_endpoint: 'MARKER-token-endpoint' });
    assert.equal(
      (await discoverOidc(freshIssuer())).token_endpoint,
      'MARKER-token-endpoint',
    );
  });

  it('a toJSON on the document is never invoked', async () => {
    const toJSON = mock.fn(() => ({ token_endpoint: 'https://forged' }));
    answering({ token_endpoint: 'https://idp.example/token', toJSON });
    const snapshot = await discoverOidc(freshIssuer());
    assert.equal(toJSON.mock.callCount(), 0);
    assert.deepEqual(snapshot, { token_endpoint: 'https://idp.example/token' });
  });
});

describe('mTLS aliases', () => {
  for (const [caseIndex, caseRow] of cases([
    ['a non-string alias', { token_endpoint: 42 }],
    ['an empty alias', { token_endpoint: '' }],
    ['aliases that are not an object', 'https://mtls.idp.example/token'],
    ['aliases that are null', null],
    [
      'aliases whose getter throws',
      {
        get token_endpoint(): string {
          throw new Error('MARKER');
        },
      },
    ],
  ]).entries()) {
    const [_name, aliases] = caseRow;
    it(
      caseTitle('%s: ignored, discovery succeeds', caseRow, caseIndex),
      async () => {
        answering({
          token_endpoint: 'https://idp.example/token',
          mtls_endpoint_aliases: aliases,
        });
        const snapshot = await discoverOidc(freshIssuer());
        assert.deepEqual(snapshot, {
          token_endpoint: 'https://idp.example/token',
        });
        assert.equal(mtlsAlias(snapshot, 'token_endpoint'), undefined);
      },
    );
  }

  it('a token and a device alias are each read', async () => {
    answering(FULL);
    const snapshot = await discoverOidc(freshIssuer());
    assert.equal(
      mtlsAlias(snapshot, 'token_endpoint'),
      'https://mtls.idp.example/token',
    );
    assert.equal(
      mtlsAlias(snapshot, 'device_authorization_endpoint'),
      'https://mtls.idp.example/device',
    );
  });
});

describe('field-only semantics on hostile documents', () => {
  const throwingGetter = (name: string) =>
    Object.defineProperty(
      { token_endpoint: 'https://idp.example/token' },
      name,
      {
        enumerable: true,
        get() {
          throw new Error('MARKER');
        },
      },
    );

  for (const [caseIndex, caseRow] of cases([
    ['authorization_endpoint'],
    ['device_authorization_endpoint'],
    ['mtls_endpoint_aliases'],
  ]).entries()) {
    const [field] = caseRow;
    it(caseTitle('a throwing %s is ignored', caseRow, caseIndex), async () => {
      answering(throwingGetter(field));
      assert.deepEqual(await discoverOidc(freshIssuer()), {
        token_endpoint: 'https://idp.example/token',
      });
    });
  }

  for (const [caseIndex, caseRow] of cases([
    ['an invalid authorization_endpoint', { authorization_endpoint: 7 }],
    [
      'an empty device_authorization_endpoint',
      { device_authorization_endpoint: '' },
    ],
  ]).entries()) {
    const [_name, extra] = caseRow;
    it(caseTitle('%s is ignored', caseRow, caseIndex), async () => {
      answering({
        token_endpoint: 'https://idp.example/token',
        ...(extra as object),
      });
      assert.deepEqual(await discoverOidc(freshIssuer()), {
        token_endpoint: 'https://idp.example/token',
      });
    });
  }

  for (const [caseIndex, caseRow] of cases([
    ['no token_endpoint', () => ({ authorization_endpoint: 'https://a' })],
    ['an empty token_endpoint', () => ({ token_endpoint: '' })],
    ['a non-string token_endpoint', () => ({ token_endpoint: 1 })],
    [
      'a token_endpoint getter that throws',
      () => ({
        get token_endpoint(): string {
          throw new Error('MARKER');
        },
      }),
    ],
    [
      'a document Proxy whose every trap throws',
      () =>
        new Proxy(
          {},
          new Proxy(
            {},
            {
              get: () => () => {
                throw new Error('MARKER');
              },
            },
          ),
        ),
    ],
    ['a document that is not an object', () => 'MARKER'],
    ['no document', () => undefined],
  ]).entries()) {
    const [_name, document] = caseRow;
    it(
      caseTitle(
        '%s: request-failed incomplete-response, nothing cached',
        caseRow,
        caseIndex,
      ),
      async () => {
        answering(document());
        const issuer = freshIssuer();
        const thrown = await failureOf(discoverOidc(issuer));
        assert.equal(isAuthProviderFailure(thrown), true);
        const failure = readFailure(thrown, 'unfamiliar-error');
        assert.equal(failure.kind, 'request-failed');
        assert.deepEqual(failure.facts, INCOMPLETE);
        notContains(JSON.stringify(thrown), 'MARKER');
        // Not cached: the next call asks again.
        answering(FULL);
        await discoverOidc(issuer);
        assert.equal(mockedAxios.get.mock.callCount(), 2);
      },
    );
  }

  it('a response object whose data getter throws: incomplete-response', async () => {
    mockedAxios.get.mock.mockImplementation(async () => ({
      status: 200,
      get data(): unknown {
        throw new Error('MARKER');
      },
    }));
    const thrown = await failureOf(discoverOidc(freshIssuer()));
    assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, INCOMPLETE);
  });
});

describe('a failed discovery request', () => {
  for (const [caseIndex, caseRow] of cases([
    [
      'a 404',
      {
        isAxiosError: true,
        message: 'MARKER',
        response: { status: 404, data: 'MARKER' },
      },
      {
        kind: 'request-failed',
        facts: { operation: 'oidc-discovery', problem: 'refused', status: 404 },
      },
    ],
    [
      'a refused connection',
      Object.assign(new Error('MARKER'), { code: 'ECONNREFUSED' }),
      {
        kind: 'request-failed',
        facts: {
          operation: 'oidc-discovery',
          problem: 'no-response',
          code: 'ECONNREFUSED',
        },
      },
    ],
    [
      'an untrusted certificate',
      Object.assign(new Error('MARKER'), { code: 'SELF_SIGNED_CERT_IN_CHAIN' }),
      {
        kind: 'tls',
        facts: {
          operation: 'oidc-discovery',
          code: 'SELF_SIGNED_CERT_IN_CHAIN',
        },
      },
    ],
  ]).entries()) {
    const [_name, rejection, expected] = caseRow;
    it(
      caseTitle(
        '%s: classified, nothing of it kept, not cached',
        caseRow,
        caseIndex,
      ),
      async () => {
        mockedAxios.get.mock.mockImplementation(async () => {
          throw rejection;
        });
        const issuer = freshIssuer();
        const thrown = await failureOf(discoverOidc(issuer));
        const failure = readFailure(thrown, 'unfamiliar-error');
        assert.deepEqual(
          { kind: failure.kind, facts: failure.facts },
          expected,
        );
        notContains(JSON.stringify(thrown), 'MARKER');
        assert.equal((thrown as { cause?: unknown }).cause, undefined);
        answering(FULL);
        await discoverOidc(issuer);
        assert.equal(mockedAxios.get.mock.callCount(), 2);
      },
    );
  }
});
