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
import { describe, expect, it, jest } from '@jest/globals';
import type {
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import { TOKEN_BOUND_ELSEWHERE } from '../../auth/refusal';
import { readBinding } from '../../auth/tokenBinding';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { recordingTargets } from '../helpers/targets';

jest.mock('axios');

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
const exp = () => Math.floor(Date.now() / 1000) + 3600;
/** An unsigned JWT; `extra` is merged into its payload. */
const jwt = (extra: Record<string, unknown> = {}) =>
  `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({ exp: exp(), sub: 'u', ...extra })}.sig`;

const UNBOUND = jwt();
const boundTo = (thumbprint: string) =>
  jwt({ cnf: { 'x5t#S256': thumbprint } });
/** Opaque: says nothing of its binding. Its expiry is stated beside it. */
const OPAQUE = 'opaque-access-token';

const REFUSAL = {
  ok: false,
  refusal: {
    reason:
      'the token is bound to a client certificate this provider does not present',
    hint: 'configure the certificate the token was issued for, or obtain a new token',
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

  it('bound, another thumbprint: Oops in both, nothing presented, no header written', async () => {
    const { provider } = seeded(boundTo(THUMB_B), A);
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

  it('authorize alone refuses a seeded token bound to another certificate', async () => {
    const { provider } = seeded(boundTo(THUMB_B), A);
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual(REFUSAL);
    expect(t.request.headers).toEqual({});
  });

  it.each([
    ['cnf null', null],
    ['cnf without x5t#S256', { jkt: 'dpop-key' }],
    ['x5t#S256 empty', { 'x5t#S256': '' }],
  ])(
    'malformed cnf (%s): Oops in both, with or without material — fail closed',
    async (_label, cnf) => {
      for (const material of [undefined, A]) {
        const { provider } = seeded(jwt({ cnf }), material);
        const t = recordingTargets();
        await expect(provider.establish(t.logonTarget)).resolves.toEqual(
          REFUSAL,
        );
        await expect(provider.authorize(t.requestTarget)).resolves.toEqual(
          REFUSAL,
        );
        expect(t.logon.tls).toHaveLength(0);
        expect(t.request.headers).toEqual({});
      }
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
  it('the refusal names no thumbprint', async () => {
    const { provider } = seeded(boundTo(THUMB_B), A);
    const t = recordingTargets();
    const outcomes = [
      await provider.establish(t.logonTarget),
      await provider.authorize(t.requestTarget),
    ];
    for (const outcome of outcomes) {
      const text = JSON.stringify(outcome);
      expect(text).not.toContain(THUMB_A);
      expect(text).not.toContain(THUMB_B);
      expect(outcome).toEqual({
        ok: false,
        refusal: { ...TOKEN_BOUND_ELSEWHERE },
      });
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

  it('a target that throws in establish is caught, carrying nothing of it', async () => {
    const { provider } = seeded(boundTo(THUMB_A), A);
    const t = recordingTargets({ throws: true });
    const outcome = await provider.establish(t.logonTarget);
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome)).not.toContain('SECRET-IN-TARGET');
  });
});
