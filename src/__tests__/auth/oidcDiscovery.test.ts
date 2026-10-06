/**
 * OIDC discovery keeps a snapshot, not the document (spec §6, "OIDC
 * discovery has its own snapshot"; row D6): the three endpoints the
 * providers read, each a non-empty string read through `readSafely`, and the
 * two mTLS aliases rebuilt as a plain object. Nothing else reaches the
 * snapshot, the cache or a provider. A document without `token_endpoint`,
 * or one that cannot be read, is `request-failed` `incomplete-response` of
 * `oidc-discovery` and is not cached; a transport rejection is `tls` or
 * `request-failed`.
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IClientAuthentication,
  ITokenRequestDraft,
} from '@mcp-abap-adt/interfaces-auth';
import axios from 'axios';
import { discoverOidc, mtlsAlias } from '../../auth/oidcDiscovery';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';

jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { get: Mock; post: Mock };

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
  mockedAxios.get.mockImplementation(async () => ({ status: 200, data }));

beforeEach(() => {
  jest.resetAllMocks();
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
    expect(snapshot).toEqual({
      authorization_endpoint: 'https://idp.example/auth',
      token_endpoint: 'https://idp.example/token',
      device_authorization_endpoint: 'https://idp.example/device',
      mtls_endpoint_aliases: {
        token_endpoint: 'https://mtls.idp.example/token',
        device_authorization_endpoint: 'https://mtls.idp.example/device',
      },
    });
    expect(snapshot.mtls_endpoint_aliases).not.toBe(FULL.mtls_endpoint_aliases);
  });

  it('the cache holds the snapshot: no field outside the list, one request', async () => {
    answering(FULL);
    const issuer = freshIssuer();
    const first = await discoverOidc(issuer);
    const second = await discoverOidc(issuer);
    expect(second).toBe(first);
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    for (const field of [
      'issuer',
      'jwks_uri',
      'end_session_endpoint',
      'extra_field',
    ]) {
      expect(field in second).toBe(false);
    }
    expect('revocation_endpoint' in (second.mtls_endpoint_aliases ?? {})).toBe(
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
    mockedAxios.mockImplementation(async () => ({
      status: 200,
      data: { access_token: 'at', expires_in: 60 },
    }));
    const provider = new OidcPasswordProvider({
      issuerUrl: issuer,
      clientId: 'cid',
      username: 'u',
      password: 'p',
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    expect(drafts[0]).toMatchObject({
      endpoint: `${issuer}/token`,
      mtlsEndpoint: `${issuer}/mtls/token`,
    });
  });

  it('a marker string in a kept field is that field’s value (public metadata)', async () => {
    answering({ token_endpoint: 'MARKER-token-endpoint' });
    expect((await discoverOidc(freshIssuer())).token_endpoint).toBe(
      'MARKER-token-endpoint',
    );
  });

  it('a toJSON on the document is never invoked', async () => {
    const toJSON = jest.fn(() => ({ token_endpoint: 'https://forged' }));
    answering({ token_endpoint: 'https://idp.example/token', toJSON });
    const snapshot = await discoverOidc(freshIssuer());
    expect(toJSON).not.toHaveBeenCalled();
    expect(snapshot).toEqual({ token_endpoint: 'https://idp.example/token' });
  });
});

describe('mTLS aliases', () => {
  it.each<[string, unknown]>([
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
  ])('%s: ignored, discovery succeeds', async (_name, aliases) => {
    answering({
      token_endpoint: 'https://idp.example/token',
      mtls_endpoint_aliases: aliases,
    });
    const snapshot = await discoverOidc(freshIssuer());
    expect(snapshot).toEqual({ token_endpoint: 'https://idp.example/token' });
    expect(mtlsAlias(snapshot, 'token_endpoint')).toBeUndefined();
  });

  it('a token and a device alias are each read', async () => {
    answering(FULL);
    const snapshot = await discoverOidc(freshIssuer());
    expect(mtlsAlias(snapshot, 'token_endpoint')).toBe(
      'https://mtls.idp.example/token',
    );
    expect(mtlsAlias(snapshot, 'device_authorization_endpoint')).toBe(
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

  it.each([
    ['authorization_endpoint'],
    ['device_authorization_endpoint'],
    ['mtls_endpoint_aliases'],
  ])('a throwing %s is ignored', async (field) => {
    answering(throwingGetter(field));
    expect(await discoverOidc(freshIssuer())).toEqual({
      token_endpoint: 'https://idp.example/token',
    });
  });

  it.each<[string, unknown]>([
    ['an invalid authorization_endpoint', { authorization_endpoint: 7 }],
    [
      'an empty device_authorization_endpoint',
      { device_authorization_endpoint: '' },
    ],
  ])('%s is ignored', async (_name, extra) => {
    answering({
      token_endpoint: 'https://idp.example/token',
      ...(extra as object),
    });
    expect(await discoverOidc(freshIssuer())).toEqual({
      token_endpoint: 'https://idp.example/token',
    });
  });

  it.each<[string, () => unknown]>([
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
  ])(
    '%s: request-failed incomplete-response, nothing cached',
    async (_name, document) => {
      answering(document());
      const issuer = freshIssuer();
      const thrown = await failureOf(discoverOidc(issuer));
      expect(isAuthProviderFailure(thrown)).toBe(true);
      const failure = readFailure(thrown, 'unfamiliar-error');
      expect(failure.kind).toBe('request-failed');
      expect(failure.facts).toEqual(INCOMPLETE);
      expect(JSON.stringify(thrown)).not.toContain('MARKER');
      // Not cached: the next call asks again.
      answering(FULL);
      await discoverOidc(issuer);
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    },
  );

  it('a response object whose data getter throws: incomplete-response', async () => {
    mockedAxios.get.mockImplementation(async () => ({
      status: 200,
      get data(): unknown {
        throw new Error('MARKER');
      },
    }));
    const thrown = await failureOf(discoverOidc(freshIssuer()));
    expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual(INCOMPLETE);
  });
});

describe('a failed discovery request', () => {
  it.each<[string, unknown, Record<string, unknown>]>([
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
  ])(
    '%s: classified, nothing of it kept, not cached',
    async (_name, rejection, expected) => {
      mockedAxios.get.mockImplementation(async () => {
        throw rejection;
      });
      const issuer = freshIssuer();
      const thrown = await failureOf(discoverOidc(issuer));
      const failure = readFailure(thrown, 'unfamiliar-error');
      expect({ kind: failure.kind, facts: failure.facts }).toEqual(expected);
      expect(JSON.stringify(thrown)).not.toContain('MARKER');
      expect((thrown as { cause?: unknown }).cause).toBeUndefined();
      answering(FULL);
      await discoverOidc(issuer);
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    },
  );
});
