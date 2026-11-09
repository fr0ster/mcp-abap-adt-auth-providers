/**
 * A bound token at the resource: before a token is presented —
 * `establish()` and `authorize()` — the provider reads what the token says
 * about its binding and answers by the table, one test per row.
 *
 * The token is seeded (`accessToken`), so no request leaves: the check runs on
 * whatever the provider would present, obtained or seeded. axios is mocked so
 * that a test which did reach the network would fail, not wait.
 */

import { CERTIFICATES } from '../helpers/packagePaths';
import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, it, mock } from 'node:test';
import type {
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import { readBinding } from '../../auth/tokenBinding';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { refreshThenLogin } from '../../renewal';
import { clearAxiosMockCalls, mockedAxios } from '../helpers/axiosModuleMock';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { wordsOf } from '../helpers/minted';
import { recordingTargets } from '../helpers/targets';

// Automocked, but with axios's own error class: the sites throw it.

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
    renewal: refreshThenLogin(),
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
    renewal: refreshThenLogin(),
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
  mockedAxios.mock.mockImplementation(async (config: any) => {
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
    renewal: refreshThenLogin(),
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
  clearAxiosMockCalls();
  requests = [];
});

describe('readBinding', () => {
  it('a JWT with cnf["x5t#S256"] is bound to that thumbprint', () => {
    assert.deepEqual(readBinding(boundTo(THUMB_A)), {
      state: 'bound',
      thumbprint: THUMB_A,
    });
  });

  it('a JWT without cnf is unbound', () => {
    assert.deepEqual(readBinding(UNBOUND), { state: 'unbound' });
  });

  for (const [caseIndex, caseRow] of cases([
    ['an opaque token', OPAQUE],
    ['two segments', `${b64url({ a: 1 })}.${b64url({ b: 2 })}`],
    ['a payload that is not JSON', `${b64url({})}.bm90LWpzb24.sig`],
    ['a payload that is an array', `${b64url({})}.${b64url([1])}.sig`],
    ['a payload that is null', `${b64url({})}.${b64url(null)}.sig`],
    ['a segment outside base64url', `${b64url({})}.${b64url({})}=.sig`],
    ['cookies', 'SAP_SESSIONID_ABC_100=x.y.z; sap-usercontext=x'],
  ]).entries()) {
    const [_label, token] = caseRow;
    it(caseTitle('%s is unknown', caseRow, caseIndex), () => {
      assert.deepEqual(readBinding(token), { state: 'unknown' });
    });
  }

  for (const [caseIndex, caseRow] of cases([
    ['cnf null', null],
    ['cnf a string', THUMB_A],
    ['cnf an array', [THUMB_A]],
    ['cnf without x5t#S256', { jkt: 'dpop-key' }],
    ['x5t#S256 empty', { 'x5t#S256': '' }],
    ['x5t#S256 not a string', { 'x5t#S256': 42 }],
  ]).entries()) {
    const [_label, cnf] = caseRow;
    it(
      caseTitle(
        '%s: bound, to nothing this provider can present',
        caseRow,
        caseIndex,
      ),
      () => {
        assert.deepEqual(readBinding(jwt({ cnf })), {
          state: 'bound',
          thumbprint: undefined,
        });
      },
    );
  }
});

describe('the binding table', () => {
  // ---- unbound
  it('unbound, no material: establish presents nothing, Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(UNBOUND);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(t.logon.tls.length, 0);
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${UNBOUND}`);
  });

  it('unbound, material: establish presents it and is Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(UNBOUND, A);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(t.logon.tls.length, 1);
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${UNBOUND}`);
  });

  it('unbound, material, a wire refusing TLS material: establish still Ok (the Bearer carries it)', async () => {
    const { provider } = seeded(UNBOUND, A);
    const t = recordingTargets({ acceptsTls: false });
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
  });

  // ---- bound, equal thumbprint
  it('bound, equal thumbprint: establish presents the pinned material, Ok; authorize Bearer, Ok', async () => {
    const token = boundTo(THUMB_A);
    const { provider } = seeded(token, A);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(t.logon.tls.length, 1);
    assert.equal(certificateThumbprint(t.logon.tls[0]!), THUMB_A);
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${token}`);
  });

  it("bound, equal thumbprint, a wire refusing TLS material: the wire's Oops (rule 4)", async () => {
    const { provider } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets({ acceptsTls: false });
    assert.deepEqual(wordsOf(await provider.establish(t.logonTarget)), {
      ok: false,
      refusal: { reason: 'this wire carries no TLS material (RFC)' },
    });
  });

  // ---- bound, none or another thumbprint
  it('bound, no material: Oops in both, nothing presented, no header written', async () => {
    const { provider } = seeded(boundTo(THUMB_A));
    const t = recordingTargets();
    assert.deepEqual(wordsOf(await provider.establish(t.logonTarget)), REFUSAL);
    assert.equal(t.logon.tls.length, 0);
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      REFUSAL,
    );
    assert.deepEqual(t.request.headers, {});
  });

  it('authorize alone refuses a seeded bound token without a strategy', async () => {
    const { provider } = seeded(boundTo(THUMB_A));
    const t = recordingTargets();
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      REFUSAL,
    );
    assert.deepEqual(t.request.headers, {});
  });

  for (const [caseIndex, caseRow] of cases([
    ['cnf null', null],
    ['cnf without x5t#S256', { jkt: 'dpop-key' }],
    ['x5t#S256 empty', { 'x5t#S256': '' }],
  ]).entries()) {
    const [_label, cnf] = caseRow;
    it(
      caseTitle(
        'malformed cnf (%s), no material: Oops in both — fail closed',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { provider } = seeded(jwt({ cnf }));
        const t = recordingTargets();
        assert.deepEqual(
          wordsOf(await provider.establish(t.logonTarget)),
          REFUSAL,
        );
        assert.deepEqual(
          wordsOf(await provider.authorize(t.requestTarget)),
          REFUSAL,
        );
        assert.equal(t.logon.tls.length, 0);
        assert.deepEqual(t.request.headers, {});
      },
    );
  }

  // ---- unknown
  it('unknown, material: establish presents it, Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(OPAQUE, A);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(t.logon.tls.length, 1);
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${OPAQUE}`);
  });

  it("unknown, material, a wire refusing TLS material: the wire's Oops — treated as bound", async () => {
    const { provider } = seeded(OPAQUE, A);
    const t = recordingTargets({ acceptsTls: false });
    assert.deepEqual(wordsOf(await provider.establish(t.logonTarget)), {
      ok: false,
      refusal: { reason: 'this wire carries no TLS material (RFC)' },
    });
  });

  it('unknown, no material: establish presents nothing, Ok; authorize Bearer, Ok', async () => {
    const { provider } = seeded(OPAQUE);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(t.logon.tls.length, 0);
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${OPAQUE}`);
  });
});

describe('around the table', () => {
  it('the refusals name no thumbprint', async () => {
    const t = recordingTargets();
    const held = seeded(boundTo(THUMB_B)).provider;
    issuing(boundTo(THUMB_B));
    const renewed = rotating({ refreshToken: 'R1' }).provider;
    const outcomes = [
      [await held.establish(t.logonTarget), REFUSAL],
      [await held.authorize(t.requestTarget), REFUSAL],
      [await renewed.authorize(t.requestTarget), RENEWED_REFUSAL],
    ] as const;
    for (const [outcome, words] of outcomes) {
      const text = JSON.stringify(outcome);
      notContains(text, THUMB_A);
      notContains(text, THUMB_B);
      assert.deepEqual(wordsOf(outcome), words);
    }
  });

  it('establish pins the material of a provider whose token comes from cache', async () => {
    const { provider, tlsCalls } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(tlsCalls(), 1);
    assert.equal(certificateThumbprint(t.logon.tls[0]!), THUMB_A);
    // Pinned once, for life.
    await provider.establish(t.logonTarget);
    await provider.authorize(t.requestTarget);
    assert.equal(tlsCalls(), 1);
  });

  it('authorize pins the material of a provider whose token comes from cache', async () => {
    const { provider, tlsCalls } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets();
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(tlsCalls(), 1);
  });

  it('a target that throws in establish is its own failure, carrying nothing of it', async () => {
    const { provider } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets({ throws: true });
    const outcome = await provider.establish(t.logonTarget);
    assert.deepEqual(wordsOf(outcome), {
      ok: false,
      refusal: { reason: 'presenting the certificate failed (unknown error)' },
    });
    notContains(JSON.stringify(outcome), 'SECRET-IN-TARGET');
  });

  it('unbound, material, a target that throws: Oops — a throwing target is broken (rule 1), not a refusal to go on from', async () => {
    const { provider } = seeded(UNBOUND, A);
    const t = recordingTargets({ throws: true });
    assert.deepEqual(wordsOf(await provider.establish(t.logonTarget)), {
      ok: false,
      refusal: { reason: 'presenting the certificate failed (unknown error)' },
    });
  });

  it('a target that throws in authorize is its own failure, not a token request', async () => {
    const { provider } = seeded(UNBOUND);
    const t = recordingTargets({ throws: true });
    const outcome = await provider.authorize(t.requestTarget);
    assert.deepEqual(wordsOf(outcome), {
      ok: false,
      refusal: { reason: 'presenting the token failed (unknown error)' },
    });
    notContains(JSON.stringify(outcome), 'SECRET-IN-TARGET');
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
    assert.equal(internals.presented, UNBOUND);
    // Bound elsewhere: renewed once, and the renewal is bound elsewhere too.
    issuing(boundTo(THUMB_B));
    internals.authorizationToken = boundTo(THUMB_B);
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      RENEWED_REFUSAL,
    );
    assert.equal(internals.presented, UNBOUND);
  });
});

describe('establish decides on the token held, never fetching one', () => {
  it('no token, no material: Ok, nothing presented, no request', async () => {
    const { provider } = unseeded();
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(t.logon.tls.length, 0);
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });

  it('no token, material: presented — unknown, so the wire must carry it', async () => {
    const { provider } = unseeded(A);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(certificateThumbprint(t.logon.tls[0]!), THUMB_A);
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });

  it("no token, material, a wire refusing TLS material: the wire's Oops (fail closed)", async () => {
    const { provider } = unseeded(A);
    const t = recordingTargets({ acceptsTls: false });
    assert.deepEqual(wordsOf(await provider.establish(t.logonTarget)), {
      ok: false,
      refusal: { reason: 'this wire carries no TLS material (RFC)' },
    });
  });

  it('a valid token bound elsewhere, while a renewal is in flight: unknown — the pinned material presented, not refused', async () => {
    let answer: (value: unknown) => void = () => {};
    const pending = new Promise((resolve) => {
      answer = resolve;
    });
    mockedAxios.mock.mockImplementation(() => pending);
    mockedAxios.post.mock.mockImplementation(() => pending);
    const { strategy } = strategyWith(A);
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
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
    assert.equal(
      mockedAxios.mock.calls.map((call) => call.arguments).length +
        mockedAxios.post.mock.calls.map((call) => call.arguments).length,
      1,
    );
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(certificateThumbprint(t.logon.tls[0]!), THUMB_A);
    answer({ data: { access_token: boundTo(THUMB_A), expires_in: 3600 } });
    await renewal;
  });

  it('an expired token bound to another certificate is not refused at logon: the renewal will be bound to the pinned one', async () => {
    const { provider } = seeded(boundTo(THUMB_B, -3600), A);
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(certificateThumbprint(t.logon.tls[0]!), THUMB_A);
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });
});

describe('a held token bound to another certificate, one pinned: renewed like an expired one', () => {
  it('authorize() refreshes once through the pinned material and sends the new token', async () => {
    const renewed = boundTo(THUMB_A);
    issuing(renewed);
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${renewed}`);
    assert.deepEqual(requests, [{ grant: 'refresh_token', cert: A.cert }]);
  });

  it('without a refresh token: one login through the pinned material', async () => {
    const renewed = boundTo(THUMB_A);
    issuing(renewed);
    const { provider } = rotating();
    const t = recordingTargets();
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${renewed}`);
    assert.deepEqual(requests, [{ grant: 'password', cert: A.cert }]);
  });

  it('getTokens() renews it too, and returns the new token', async () => {
    const renewed = boundTo(THUMB_A);
    issuing(renewed);
    const { provider } = rotating({ refreshToken: 'R1' });
    matchObject(await provider.getTokens(), {
      authorizationToken: renewed,
    });
    assert.equal(requests.length, 1);
  });

  it('the renewal is bound elsewhere again: Oops, no header — a successful refresh is not followed by a login', async () => {
    issuing(boundTo(THUMB_B));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      RENEWED_REFUSAL,
    );
    assert.deepEqual(t.request.headers, {});
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token'],
    );
  });

  it('the refresh refused, the login bound elsewhere: Oops after one refresh and one login, no step twice', async () => {
    let n = 0;
    mockedAxios.mock.mockImplementation(async (config: any) => {
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
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      RENEWED_REFUSAL,
    );
    assert.deepEqual(t.request.headers, {});
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token', 'password'],
    );
  });

  it('a renewal that stays bound elsewhere is remembered: the next authorize() refuses without renewing again', async () => {
    const first = boundTo(THUMB_B, 3600);
    issuing(first, boundTo(THUMB_B, 3700));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    for (let i = 0; i < 3; i += 1) {
      assert.deepEqual(
        wordsOf(await provider.authorize(t.requestTarget)),
        RENEWED_REFUSAL,
      );
    }
    // getTokens() answers the remembered refusal too; the
    // token stays held, committed.
    const thrown = await provider.getTokens().then(
      () => undefined,
      (error: unknown) => error,
    );
    assert.deepEqual(
      wordsOf({ ok: false, refusal: (thrown as { error: never }).error }),
      RENEWED_REFUSAL,
    );
    assert.equal(
      (provider as unknown as { authorizationToken?: string })
        .authorizationToken,
      first,
    );
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token'],
    );
    assert.deepEqual(t.request.headers, {});
  });

  it('without a refresh token: one login, never a login per request', async () => {
    issuing(boundTo(THUMB_B, 3600), boundTo(THUMB_B, 3700));
    const { provider } = rotating();
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.authorize(t.requestTarget);
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['password'],
    );
  });

  it('after rejected(), a new renewal is attempted once — and remembered again', async () => {
    issuing(boundTo(THUMB_B, 3600), boundTo(THUMB_B, 3700));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    assert.equal(requests.length, 1);
    // The new token is still bound elsewhere: what is presented did not
    // change, so rejected() answers that refusal.
    assert.deepEqual(
      wordsOf(
        await provider.rejected({
          at: 'request',
          status: 401,
          error: undefined,
        }),
      ),
      RENEWED_REFUSAL,
    );
    assert.equal(requests.length, 2);
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      RENEWED_REFUSAL,
    );
    await provider.authorize(t.requestTarget);
    assert.equal(requests.length, 2);
  });

  /** Every request to the token endpoint is refused: refresh and login both fail. */
  function refusingAll() {
    mockedAxios.mock.mockImplementation(async (config: any) => {
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

  for (const [caseIndex, caseRow] of cases([
    [
      'with a refresh token',
      { refreshToken: 'R1' },
      ['refresh_token', 'password'],
    ],
    ['without a refresh token', {}, ['password']],
  ]).entries()) {
    const [_label, options, firstRenewal] = caseRow;
    it(
      caseTitle(
        'a renewal that throws, %s, is remembered too: later authorize() calls give its refusal again, without a token request or a login',
        caseRow,
        caseIndex,
      ),
      async () => {
        refusingAll();
        const { provider } = rotating(options);
        const t = recordingTargets();
        const first = await provider.authorize(t.requestTarget);
        assert.equal(first.ok, false);
        // The renewal's own refusal, not the generic bound-elsewhere words.
        assert.notDeepEqual(wordsOf(first), REFUSAL);
        assert.deepEqual(
          requests.map((r) => r.grant),
          firstRenewal,
        );
        for (let i = 0; i < 2; i += 1) {
          assert.deepEqual(await provider.authorize(t.requestTarget), first);
        }
        assert.deepEqual(
          requests.map((r) => r.grant),
          firstRenewal,
        );
        assert.deepEqual(t.request.headers, {});
      },
    );
  }

  it('after a renewal that threw, rejected() tries exactly once more, and the mark holds again', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.authorize(t.requestTarget);
    assert.equal(requests.length, 2);
    const outcome = await provider.rejected({
      at: 'request',
      status: 401,
      error: undefined,
    });
    assert.equal(outcome.ok, false);
    // The refresh token was spent by the first refusal: one login, once.
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token', 'password', 'password'],
    );
    // The latest renewal's refusal is the one remembered.
    assert.deepEqual(await provider.authorize(t.requestTarget), outcome);
    assert.equal(requests.length, 3);
  });

  it('after a renewal that threw, prepare() tries exactly once more', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.authorize(t.requestTarget);
    assert.equal(requests.length, 2);
    const prepared = await provider.prepare();
    assert.equal(prepared.ok, false);
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token', 'password', 'password'],
    );
    assert.deepEqual(await provider.authorize(t.requestTarget), prepared);
    assert.equal(requests.length, 3);
  });

  it('after a renewal that threw, a new token held clears the mark', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    assert.equal(requests.length, 2);
    const fresh = boundTo(THUMB_A);
    (
      provider as unknown as { authorizationToken?: string }
    ).authorizationToken = fresh;
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(t.request.headers.Authorization, `Bearer ${fresh}`);
    assert.equal(requests.length, 2);
  });

  for (const [caseIndex, caseRow] of cases([
    ['with a refresh token', { refreshToken: 'R1' }, ['refresh_token']],
    ['without a refresh token', {}, ['password']],
  ]).entries()) {
    const [_label, options, expected] = caseRow;
    it(
      caseTitle(
        'two authorize() calls racing the first renewal, %s: exactly one token request',
        caseRow,
        caseIndex,
      ),
      async () => {
        const renewed = boundTo(THUMB_A);
        mockedAxios.mock.mockImplementation(async (config: any) => {
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
        assert.deepEqual(outcomes, [{ ok: true }, { ok: true }]);
        assert.deepEqual(
          requests.map((r) => r.grant),
          expected,
        );
        assert.equal(a.request.headers.Authorization, `Bearer ${renewed}`);
        assert.equal(b.request.headers.Authorization, `Bearer ${renewed}`);
      },
    );
  }

  it('two authorize() calls racing a first renewal that throws: one refresh and one login, both refused, later calls make none', async () => {
    refusingAll();
    const { provider } = rotating({ refreshToken: 'R1' });
    const a = recordingTargets();
    const b = recordingTargets();
    const outcomes = await Promise.all([
      provider.authorize(a.requestTarget),
      provider.authorize(b.requestTarget),
    ]);
    assert.deepEqual(
      outcomes.map((o) => o.ok),
      [false, false],
    );
    assert.deepEqual(outcomes[1], outcomes[0]);
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token', 'password'],
    );
    assert.deepEqual(await provider.authorize(a.requestTarget), outcomes[0]);
    assert.equal(requests.length, 2);
  });

  it('a renewal refused because the client certificate expired: every later authorize() says so, with nothing sent', async () => {
    const EXPIRED = {
      ok: false,
      refusal: {
        reason: 'the client certificate has expired',
        hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
      },
    };
    // Bound to B and valid past the moved clock: renewed for its binding,
    // not for its age.
    const { provider } = rotating({
      refreshToken: 'R1',
      token: boundTo(THUMB_B, 200 * 365 * 86400),
    });
    const t = recordingTargets();
    // Pinned while A is valid; nothing obtained.
    await provider.establish(t.logonTarget);
    // client.crt is valid until 2126: the clock is moved past it.
    const now = mock.method(Date, 'now', () => Date.UTC(2127, 0, 1));
    try {
      for (let i = 0; i < 3; i += 1) {
        assert.deepEqual(
          wordsOf(await provider.authorize(t.requestTarget)),
          EXPIRED,
        );
      }
    } finally {
      now.mock.restore();
    }
    assert.equal(requests.length, 0);
    assert.deepEqual(t.request.headers, {});
  });

  it('a token renewed bound elsewhere, renewed again after prepare() and failing: later calls give that failure, not the earlier words', async () => {
    issuing(boundTo(THUMB_B, 3600));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      RENEWED_REFUSAL,
    );
    refusingAll();
    const prepared = await provider.prepare();
    assert.equal(prepared.ok, false);
    assert.notDeepEqual(wordsOf(prepared), RENEWED_REFUSAL);
    const count = requests.length;
    assert.deepEqual(await provider.authorize(t.requestTarget), prepared);
    assert.deepEqual(await provider.authorize(t.requestTarget), prepared);
    assert.equal(requests.length, count);
  });

  it('an EXPIRED token (bound to the pinned one) whose renewal fails is not remembered: each authorize() renews again, as before', async () => {
    refusingAll();
    const { provider } = rotating({
      refreshToken: 'R1',
      token: boundTo(THUMB_A, -3600),
    });
    const t = recordingTargets();
    assert.equal((await provider.authorize(t.requestTarget)).ok, false);
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token', 'password'],
    );
    assert.equal((await provider.authorize(t.requestTarget)).ok, false);
    assert.equal((await provider.authorize(t.requestTarget)).ok, false);
    // The refresh token was spent by the first refusal: a login each time.
    assert.deepEqual(
      requests.map((r) => r.grant),
      ['refresh_token', 'password', 'password', 'password'],
    );
  });

  it('prepare() clears the mark: one more renewal per connect', async () => {
    issuing(boundTo(THUMB_B, 3600), boundTo(THUMB_B, 3700));
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    await provider.prepare();
    await provider.authorize(t.requestTarget);
    assert.equal(requests.length, 2);
  });

  for (const [caseIndex, caseRow] of cases([
    ['cnf null', null],
    ['cnf without x5t#S256', { jkt: 'dpop-key' }],
    ['x5t#S256 empty', { 'x5t#S256': '' }],
  ]).entries()) {
    const [_label, cnf] = caseRow;
    it(
      caseTitle(
        'malformed cnf (%s): renewed the same way, and the new token is the one checked',
        caseRow,
        caseIndex,
      ),
      async () => {
        const renewed = boundTo(THUMB_A);
        issuing(renewed);
        const { provider } = rotating({ token: jwt({ cnf }) });
        const t = recordingTargets();
        assert.deepEqual(await provider.authorize(t.requestTarget), {
          ok: true,
        });
        assert.equal(t.request.headers.Authorization, `Bearer ${renewed}`);
        assert.equal(requests.length, 1);
      },
    );
  }

  it('establish() reads it as unknown, never fetching: the pinned certificate is presented, Ok', async () => {
    const { provider } = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    assert.deepEqual(await provider.establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(certificateThumbprint(t.logon.tls[0]!), THUMB_A);
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });

  it('no certificate pinned: unchanged — getTokens() returns the token, establish() and authorize() refuse it', async () => {
    const token = boundTo(THUMB_B);
    const { provider } = seeded(token);
    matchObject(await provider.getTokens(), {
      authorizationToken: token,
    });
    const t = recordingTargets();
    assert.deepEqual(wordsOf(await provider.establish(t.logonTarget)), REFUSAL);
    assert.deepEqual(
      wordsOf(await provider.authorize(t.requestTarget)),
      REFUSAL,
    );
    assert.deepEqual(t.request.headers, {});
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });
});
