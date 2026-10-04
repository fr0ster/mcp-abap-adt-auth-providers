/**
 * A bound token at the resource (spec §4): before a token is presented —
 * `establish()` and `authorize()` — the provider reads what the token says
 * about its binding and answers by the table, one test per row.
 *
 * The token is seeded (`accessToken`), so no request leaves: the check runs on
 * whatever the provider would present, obtained or seeded. axios is mocked so
 * that a test which did reach the network would fail, not wait.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type {
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import axios from 'axios';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import {
  TOKEN_BOUND_ELSEWHERE,
  TOKEN_RENEWED_BOUND_ELSEWHERE,
} from '../../auth/refusal';
import { readBinding } from '../../auth/tokenBinding';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { recordingTargets } from '../helpers/targets';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock; get: Mock };

const dir = join(__dirname, '..', 'fixtures', 'certificates');
const read = (name: string) => readFileSync(join(dir, name));
const A: ICertificateMaterial = {
  cert: read('client.crt'),
  key: read('client.key'),
};
const B: ICertificateMaterial = {
  cert: read('other.crt'),
  key: read('other.key'),
};
const THUMB_A = certificateThumbprint(A);
const THUMB_B = certificateThumbprint(B);

const b64url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const exp = (seconds = 3600) => Math.floor(Date.now() / 1000) + seconds;
/** An unsigned JWT; `extra` is merged into its payload. */
const jwt = (extra: Record<string, unknown> = {}, seconds = 3600) =>
  `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({ exp: exp(seconds), sub: 'u', ...extra })}.sig`;

const UNBOUND = jwt();
const boundTo = (thumbprint: string, seconds = 3600) =>
  jwt({ cnf: { 'x5t#S256': thumbprint } }, seconds);
/** Opaque: says nothing of its binding. Its expiry is stated beside it. */
const OPAQUE = 'opaque-access-token';

/** A held token bound to a certificate, and no certificate to present. */
const REFUSAL = {
  ok: false,
  refusal: {
    reason:
      'the token is bound to a client certificate this provider does not present',
    hint: 'give the provider a clientAuthentication that presents the certificate the token was issued for',
  },
};

/** A certificate pinned, renewed once, and the new token is bound elsewhere too. */
const RENEWED_REFUSAL = {
  ok: false,
  refusal: {
    reason:
      'the new token is bound to a client certificate this provider does not present',
    hint: 'the authorization server bound the new token to another certificate: check the certificate registered for this client',
  },
};

function strategyWith(material?: ICertificateMaterial) {
  let calls = 0;
  const strategy: IClientAuthentication = {
    authenticate: async (draft) => ({
      parameters: { client_id: draft.clientId },
    }),
  };
  if (material) {
    strategy.tlsMaterial = async () => {
      calls += 1;
      return material;
    };
  }
  return { strategy, tlsCalls: () => calls };
}

/** A provider seeded with `token`; with `material`, a strategy presenting it. */
function seeded(token: string, material?: ICertificateMaterial) {
  const { strategy, tlsCalls } = strategyWith(material);
  const provider = new OidcPasswordProvider({
    clientId: 'client',
    username: 'user',
    password: 'pw',
    tokenEndpoint: 'https://idp.example/token',
    accessToken: token,
    expiresAt: Date.now() + 3600_000,
    ...(material ? { clientAuthentication: strategy } : {}),
  });
  return { provider, tlsCalls };
}

/** A provider holding no token at all. */
function unseeded(material?: ICertificateMaterial) {
  const { strategy } = strategyWith(material);
  const provider = new OidcPasswordProvider({
    clientId: 'client',
    username: 'user',
    password: 'pw',
    tokenEndpoint: 'https://idp.example/token',
    ...(material ? { clientAuthentication: strategy } : {}),
  });
  return { provider };
}

/** What the token endpoint received, request by request. */
let requests: Array<{ grant: string | null; cert: unknown }> = [];

/** The token endpoint answers each request with the next token, the last one repeated. */
function issuing(...tokens: string[]) {
  let n = 0;
  mockedAxios.mockImplementation(async (config: any) => {
    requests.push({
      grant: new URLSearchParams(config.data).get('grant_type'),
      cert: config.httpsAgent?.options?.cert,
    });
    const token = tokens[Math.min(n, tokens.length - 1)];
    n += 1;
    return { data: { access_token: token, expires_in: 3600 } };
  });
}

/**
 * A provider pinned to A, holding a valid token bound to B — restored from a
 * store after the certificate rotated, say.
 */
function rotating(options: { refreshToken?: string; token?: string } = {}) {
  const { strategy, tlsCalls } = strategyWith(A);
  const provider = new OidcPasswordProvider({
    clientId: 'client',
    username: 'user',
    password: 'pw',
    tokenEndpoint: 'https://idp.example/token',
    accessToken: options.token ?? boundTo(THUMB_B),
    ...(options.refreshToken ? { refreshToken: options.refreshToken } : {}),
    clientAuthentication: strategy,
  });
  return { provider, tlsCalls };
}

beforeEach(() => {
  jest.clearAllMocks();
  requests = [];
});

describe('readBinding', () => {
  it('a JWT with cnf["x5t#S256"] is bound to that thumbprint', () => {
    expect(readBinding(boundTo(THUMB_A))).toEqual({
      state: 'bound',
      thumbprint: THUMB_A,
    });
  });

  it('a JWT without cnf is unbound', () => {
    expect(readBinding(UNBOUND)).toEqual({ state: 'unbound' });
  });

  it.each([
    ['an opaque token', OPAQUE],
    ['two segments', `${b64url({ a: 1 })}.${b64url({ b: 2 })}`],
    ['a payload that is not JSON', `${b64url({})}.bm90LWpzb24.sig`],
    ['a payload that is an array', `${b64url({})}.${b64url([1])}.sig`],
    ['a payload that is null', `${b64url({})}.${b64url(null)}.sig`],
    ['a segment outside base64url', `${b64url({})}.${b64url({})}=.sig`],
    ['cookies', 'SAP_SESSIONID_ABC_100=x.y.z; sap-usercontext=x'],
  ])('%s is unknown', (_label, token) => {
    expect(readBinding(token)).toEqual({ state: 'unknown' });
  });

  it.each([
    ['cnf null', null],
    ['cnf a string', THUMB_A],
    ['cnf an array', [THUMB_A]],
    ['cnf without x5t#S256', { jkt: 'dpop-key' }],
    ['x5t#S256 empty', { 'x5t#S256': '' }],
    ['x5t#S256 not a string', { 'x5t#S256': 42 }],
  ])('%s: bound, to nothing this provider can present', (_label, cnf) => {
    expect(readBinding(jwt({ cnf }))).toEqual({
      state: 'bound',
      thumbprint: undefined,
    });
  });
});

describe('the binding table (spec §4)', () => {
  // ---- unbound
  it('unbound, no material: establish presents nothing, Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(UNBOUND);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon.tls).toHaveLength(0);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${UNBOUND}`);
  });

  it('unbound, material: establish presents it and is Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(UNBOUND, A);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon.tls).toHaveLength(1);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${UNBOUND}`);
  });

  it('unbound, material, a wire refusing TLS material: establish still Ok (the Bearer carries it)', async () => {
    const { provider } = seeded(UNBOUND, A);
    const t = recordingTargets({ acceptsTls: false });
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
  });

  // ---- bound, equal thumbprint
  it('bound, equal thumbprint: establish presents the pinned material, Ok; authorize Bearer, Ok', async () => {
    const token = boundTo(THUMB_A);
    const { provider } = seeded(token, A);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon.tls).toHaveLength(1);
    expect(certificateThumbprint(t.logon.tls[0])).toBe(THUMB_A);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${token}`);
  });

  it("bound, equal thumbprint, a wire refusing TLS material: the wire's Oops (rule 4)", async () => {
    const { provider } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets({ acceptsTls: false });
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: false,
      refusal: { reason: 'this wire does not take TLS material' },
    });
  });

  // ---- bound, none or another thumbprint
  it('bound, no material: Oops in both, nothing presented, no header written', async () => {
    const { provider } = seeded(boundTo(THUMB_A));
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual(REFUSAL);
    expect(t.logon.tls).toHaveLength(0);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(REFUSAL);
    expect(t.request.headers).toEqual({});
  });

  it('authorize alone refuses a seeded bound token without a strategy', async () => {
    const { provider } = seeded(boundTo(THUMB_A));
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(REFUSAL);
    expect(t.request.headers).toEqual({});
  });

  it.each([
    ['cnf null', null],
    ['cnf without x5t#S256', { jkt: 'dpop-key' }],
    ['x5t#S256 empty', { 'x5t#S256': '' }],
  ])(
    'malformed cnf (%s), no material: Oops in both — fail closed',
    async (_label, cnf) => {
      const { provider } = seeded(jwt({ cnf }));
      const t = recordingTargets();
      await expect(provider.establish(t.logonTarget)).resolves.toEqual(REFUSAL);
      await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
        REFUSAL,
      );
      expect(t.logon.tls).toHaveLength(0);
      expect(t.request.headers).toEqual({});
    },
  );

  // ---- unknown
  it('unknown, material: establish presents it, Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(OPAQUE, A);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon.tls).toHaveLength(1);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${OPAQUE}`);
  });

  it("unknown, material, a wire refusing TLS material: the wire's Oops — treated as bound", async () => {
    const { provider } = seeded(OPAQUE, A);
    const t = recordingTargets({ acceptsTls: false });
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: false,
      refusal: { reason: 'this wire does not take TLS material' },
    });
  });

  it('unknown, no material: establish presents nothing, Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(OPAQUE);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon.tls).toHaveLength(0);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${OPAQUE}`);
  });
});

describe('around the table', () => {
  it('the refusals name no thumbprint', async () => {
    const t = recordingTargets();
    const held = seeded(boundTo(THUMB_B)).provider;
    issuing(boundTo(THUMB_B));
    const renewed = rotating({ refreshToken: 'R1' }).provider;
    const outcomes = [
      [await held.establish(t.logonTarget), TOKEN_BOUND_ELSEWHERE],
      [await held.authorize(t.requestTarget), TOKEN_BOUND_ELSEWHERE],
      [await renewed.authorize(t.requestTarget), TOKEN_RENEWED_BOUND_ELSEWHERE],
    ] as const;
    for (const [outcome, words] of outcomes) {
      const text = JSON.stringify(outcome);
      expect(text).not.toContain(THUMB_A);
      expect(text).not.toContain(THUMB_B);
      expect(outcome).toEqual({ ok: false, refusal: { ...words } });
    }
  });

  it('establish pins the material of a provider whose token comes from cache', async () => {
    const { provider, tlsCalls } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(tlsCalls()).toBe(1);
    expect(certificateThumbprint(t.logon.tls[0])).toBe(THUMB_A);
    // Pinned once, for life.
    await provider.establish(t.logonTarget);
    await provider.authorize(t.requestTarget);
    expect(tlsCalls()).toBe(1);
  });

  it('authorize pins the material of a provider whose token comes from cache', async () => {
    const { provider, tlsCalls } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(tlsCalls()).toBe(1);
  });

  it('a target that throws in establish is its own failure, carrying nothing of it', async () => {
    const { provider } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets({ throws: true });
    const outcome = await provider.establish(t.logonTarget);
    expect(outcome).toEqual({
      ok: false,
      refusal: { reason: 'presenting the certificate failed (unknown error)' },
    });
    expect(JSON.stringify(outcome)).not.toContain('SECRET-IN-TARGET');
  });

  it('unbound, material, a target that throws: Oops — a throwing target is broken (rule 1), not a refusal to go on from', async () => {
    const { provider } = seeded(UNBOUND, A);
    const t = recordingTargets({ throws: true });
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: false,
      refusal: { reason: 'presenting the certificate failed (unknown error)' },
    });
  });

  it('a target that throws in authorize is its own failure, not a token request', async () => {
    const { provider } = seeded(UNBOUND);
    const t = recordingTargets({ throws: true });
    const outcome = await provider.authorize(t.requestTarget);
    expect(outcome).toEqual({
      ok: false,
      refusal: { reason: 'presenting the token failed (unknown error)' },
    });
    expect(JSON.stringify(outcome)).not.toContain('SECRET-IN-TARGET');
  });

  it('a refused authorize leaves the presented token as it was', async () => {
    const { provider } = seeded(UNBOUND, A);
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    // The held token, replaced as a store would; `presented` read to prove it unchanged.
    const internals = provider as unknown as {
      presented?: string;
      authorizationToken?: string;
    };
    expect(internals.presented).toBe(UNBOUND);
    // Bound elsewhere: renewed once, and the renewal is bound elsewhere too.
    issuing(boundTo(THUMB_B));
    internals.authorizationToken = boundTo(THUMB_B);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
      RENEWED_REFUSAL,
    );
    expect(internals.presented).toBe(UNBOUND);
  });
});

describe('establish decides on the token held, never fetching one', () => {
  it('no token, no material: Ok, nothing presented, no request', async () => {
    const { provider } = unseeded();
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon.tls).toHaveLength(0);
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it('no token, material: presented — unknown, so the wire must carry it', async () => {
    const { provider } = unseeded(A);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(certificateThumbprint(t.logon.tls[0])).toBe(THUMB_A);
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it("no token, material, a wire refusing TLS material: the wire's Oops (fail closed)", async () => {
    const { provider } = unseeded(A);
    const t = recordingTargets({ acceptsTls: false });
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: false,
      refusal: { reason: 'this wire does not take TLS material' },
    });
  });

  it('a valid token bound elsewhere, while a renewal is in flight: unknown — the pinned material presented, not refused', async () => {
    let answer: (value: unknown) => void = () => {};
    const pending = new Promise((resolve) => {
      answer = resolve;
    });
    mockedAxios.mockImplementation(() => pending);
    mockedAxios.post.mockImplementation(() => pending);
    const { strategy } = strategyWith(A);
    const provider = new OidcPasswordProvider({
      clientId: 'client',
      username: 'user',
      password: 'pw',
      tokenEndpoint: 'https://idp.example/token',
      accessToken: boundTo(THUMB_B),
      refreshToken: 'R1',
      clientAuthentication: strategy,
    });
    const renewal = provider.refreshTokens().catch(() => undefined);
    // The refresh request is out and unanswered.
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(
      mockedAxios.mock.calls.length + mockedAxios.post.mock.calls.length,
    ).toBe(1);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(certificateThumbprint(t.logon.tls[0])).toBe(THUMB_A);
    answer({ data: { access_token: boundTo(THUMB_A), expires_in: 3600 } });
    await renewal;
  });

  it('an expired token bound to another certificate is not refused at logon: the renewal will be bound to the pinned one', async () => {
    const { provider } = seeded(boundTo(THUMB_B, -3600), A);
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(certificateThumbprint(t.logon.tls[0])).toBe(THUMB_A);
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });
});

describe('a held token bound to another certificate, one pinned: renewed like an expired one', () => {
  it('authorize() refreshes once through the pinned material and sends the new token', async () => {
    const renewed = boundTo(THUMB_A);
    issuing(renewed);
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${renewed}`);
    expect(requests).toEqual([{ grant: 'refresh_token', cert: A.cert }]);
  });

  it('without a refresh token: one login through the pinned material', async () => {
    const renewed = boundTo(THUMB_A);
    issuing(renewed);
    const { provider } = rotating();
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${renewed}`);
    expect(requests).toEqual([{ grant: 'password', cert: A.cert }]);
  });

  it('getTokens() renews it too, and returns the new token', async () => {
    const renewed = boundTo(THUMB_A);
    issuing(renewed);
    const { provider } = rotating({ refreshToken: 'R1' });
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: renewed,
    });
    expect(requests).toHaveLength(1);
  });

  it('the renewal is bound elsewhere again: Oops, no header — a successful refresh is not followed by a login', async () => {
    issuing(boundTo(THUMB_B));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
      RENEWED_REFUSAL,
    );
    expect(t.request.headers).toEqual({});
    expect(requests.map((r) => r.grant)).toEqual(['refresh_token']);
  });

  it('the refresh refused, the login bound elsewhere: Oops after one refresh and one login, no step twice', async () => {
    let n = 0;
    mockedAxios.mockImplementation(async (config: any) => {
      requests.push({
        grant: new URLSearchParams(config.data).get('grant_type'),
        cert: config.httpsAgent?.options?.cert,
      });
      n += 1;
      if (n === 1) {
        throw Object.assign(new Error('refused'), {
          isAxiosError: true,
          response: { status: 400, data: { error: 'invalid_grant' } },
        });
      }
      return { data: { access_token: boundTo(THUMB_B), expires_in: 3600 } };
    });
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
      RENEWED_REFUSAL,
    );
    expect(t.request.headers).toEqual({});
    expect(requests.map((r) => r.grant)).toEqual(['refresh_token', 'password']);
  });

  it('a renewal that stays bound elsewhere is remembered: the next authorize() refuses without renewing again', async () => {
    const first = boundTo(THUMB_B, 3600);
    issuing(first, boundTo(THUMB_B, 3700));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    for (let i = 0; i < 3; i += 1) {
      await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
        RENEWED_REFUSAL,
      );
    }
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: first,
    });
    expect(requests.map((r) => r.grant)).toEqual(['refresh_token']);
    expect(t.request.headers).toEqual({});
  });

  it('without a refresh token: one login, never a login per request', async () => {
    issuing(boundTo(THUMB_B, 3600), boundTo(THUMB_B, 3700));
    const { provider } = rotating();
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.authorize(t.requestTarget);
    expect(requests.map((r) => r.grant)).toEqual(['password']);
  });

  it('after rejected(), a new renewal is attempted once — and remembered again', async () => {
    issuing(boundTo(THUMB_B, 3600), boundTo(THUMB_B, 3700));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    expect(requests).toHaveLength(1);
    await expect(
      provider.rejected({ at: 'request', status: 401, error: undefined }),
    ).resolves.toEqual({ ok: true });
    expect(requests).toHaveLength(2);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
      RENEWED_REFUSAL,
    );
    await provider.authorize(t.requestTarget);
    expect(requests).toHaveLength(2);
  });

  /** Every request to the token endpoint is refused: refresh and login both fail. */
  function refusingAll() {
    mockedAxios.mockImplementation(async (config: any) => {
      requests.push({
        grant: new URLSearchParams(config.data).get('grant_type'),
        cert: config.httpsAgent?.options?.cert,
      });
      throw Object.assign(new Error('refused'), {
        isAxiosError: true,
        response: { status: 400, data: { error: 'invalid_grant' } },
      });
    });
  }

  it.each([
    [
      'with a refresh token',
      { refreshToken: 'R1' },
      ['refresh_token', 'password'],
    ],
    ['without a refresh token', {}, ['password']],
  ])(
    'a renewal that throws, %s, is remembered too: later authorize() calls refuse without a token request or a login',
    async (_label, options, firstRenewal) => {
      refusingAll();
      const { provider } = rotating(options);
      const t = recordingTargets();
      const first = await provider.authorize(t.requestTarget);
      expect(first.ok).toBe(false);
      expect(requests.map((r) => r.grant)).toEqual(firstRenewal);
      for (let i = 0; i < 2; i += 1) {
        await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
          REFUSAL,
        );
      }
      expect(requests.map((r) => r.grant)).toEqual(firstRenewal);
      expect(t.request.headers).toEqual({});
    },
  );

  it('after a renewal that threw, rejected() tries exactly once more, and the mark holds again', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.authorize(t.requestTarget);
    expect(requests).toHaveLength(2);
    const outcome = await provider.rejected({
      at: 'request',
      status: 401,
      error: undefined,
    });
    expect(outcome.ok).toBe(false);
    // The refresh token was spent by the first refusal: one login, once.
    expect(requests.map((r) => r.grant)).toEqual([
      'refresh_token',
      'password',
      'password',
    ]);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(REFUSAL);
    expect(requests).toHaveLength(3);
  });

  it('after a renewal that threw, prepare() tries exactly once more', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.authorize(t.requestTarget);
    expect(requests).toHaveLength(2);
    expect((await provider.prepare()).ok).toBe(false);
    expect(requests.map((r) => r.grant)).toEqual([
      'refresh_token',
      'password',
      'password',
    ]);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(REFUSAL);
    expect(requests).toHaveLength(3);
  });

  it('after a renewal that threw, a new token held clears the mark', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    expect(requests).toHaveLength(2);
    const fresh = boundTo(THUMB_A);
    (
      provider as unknown as { authorizationToken?: string }
    ).authorizationToken = fresh;
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.headers.Authorization).toBe(`Bearer ${fresh}`);
    expect(requests).toHaveLength(2);
  });

  it.each([
    ['with a refresh token', { refreshToken: 'R1' }, ['refresh_token']],
    ['without a refresh token', {}, ['password']],
  ])(
    'two authorize() calls racing the first renewal, %s: exactly one token request',
    async (_label, options, expected) => {
      const renewed = boundTo(THUMB_A);
      mockedAxios.mockImplementation(async (config: any) => {
        requests.push({
          grant: new URLSearchParams(config.data).get('grant_type'),
          cert: config.httpsAgent?.options?.cert,
        });
        await new Promise((resolve) => setTimeout(resolve, 20));
        return { data: { access_token: renewed, expires_in: 3600 } };
      });
      const { provider } = rotating(options);
      const a = recordingTargets();
      const b = recordingTargets();
      const outcomes = await Promise.all([
        provider.authorize(a.requestTarget),
        provider.authorize(b.requestTarget),
      ]);
      expect(outcomes).toEqual([{ ok: true }, { ok: true }]);
      expect(requests.map((r) => r.grant)).toEqual(expected);
      expect(a.request.headers.Authorization).toBe(`Bearer ${renewed}`);
      expect(b.request.headers.Authorization).toBe(`Bearer ${renewed}`);
    },
  );

  it('two authorize() calls racing a first renewal that throws: one refresh and one login, both refused, later calls make none', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const a = recordingTargets();
    const b = recordingTargets();
    const outcomes = await Promise.all([
      provider.authorize(a.requestTarget),
      provider.authorize(b.requestTarget),
    ]);
    expect(outcomes.map((o) => o.ok)).toEqual([false, false]);
    expect(requests.map((r) => r.grant)).toEqual(['refresh_token', 'password']);
    await expect(provider.authorize(a.requestTarget)).resolves.toEqual(REFUSAL);
    expect(requests).toHaveLength(2);
  });

  it('prepare() clears the mark: one more renewal per connect', async () => {
    issuing(boundTo(THUMB_B, 3600), boundTo(THUMB_B, 3700));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.prepare();
    await provider.authorize(t.requestTarget);
    expect(requests).toHaveLength(2);
  });

  it.each([
    ['cnf null', null],
    ['cnf without x5t#S256', { jkt: 'dpop-key' }],
    ['x5t#S256 empty', { 'x5t#S256': '' }],
  ])(
    'malformed cnf (%s): renewed the same way, and the new token is the one checked',
    async (_label, cnf) => {
      const renewed = boundTo(THUMB_A);
      issuing(renewed);
      const { provider } = rotating({ token: jwt({ cnf }) });
      const t = recordingTargets();
      await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
        ok: true,
      });
      expect(t.request.headers.Authorization).toBe(`Bearer ${renewed}`);
      expect(requests).toHaveLength(1);
    },
  );

  it('establish() reads it as unknown, never fetching: the pinned certificate is presented, Ok', async () => {
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(certificateThumbprint(t.logon.tls[0])).toBe(THUMB_A);
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it('no certificate pinned: unchanged — getTokens() returns the token, establish() and authorize() refuse it', async () => {
    const token = boundTo(THUMB_B);
    const { provider } = seeded(token);
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: token,
    });
    const t = recordingTargets();
    await expect(provider.establish(t.logonTarget)).resolves.toEqual(REFUSAL);
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(REFUSAL);
    expect(t.request.headers).toEqual({});
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });
});
