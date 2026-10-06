/**
 * Spec §7: how a provider relays a logon target's answer (rule 4). The same
 * minted refusal **returned** by the target means "the wire cannot take
 * this"; **thrown**, "the target is broken". Garbage returned is the
 * `logon-target` fallback; garbage thrown is `unknown` with the operation.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, jest } from '@jest/globals';
import { authError, isMinted } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  ICertificateMaterial,
  IClientAuthentication,
  ILogonTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import { toLegacyOutcome } from '../../auth/contractTransition';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';

jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});

const MARKER = 'SECRET-MARKER';
const dir = join(__dirname, '..', 'fixtures', 'certificates');
const read = (name: string) => readFileSync(join(dir, name));
const A: ICertificateMaterial = {
  cert: read('client.crt'),
  key: read('client.key'),
};

/** One minted refusal, the very object a target returns or throws. */
const WIRE_REFUSAL = toLegacyOutcome({
  ok: false,
  refusal: authError['logon-target']({ wire: 'rfc', refused: 'tls-material' }),
});
const GARBAGE = { ok: 'maybe', reason: MARKER };

type Answer = 'returned' | 'thrown' | 'garbage returned' | 'garbage thrown';

/** A logon target whose both members answer as `answer` says. */
function target(answer: Answer): ILogonTarget {
  const respond = (): AuthOutcome => {
    if (answer === 'returned') return WIRE_REFUSAL;
    // Thrown: the refusal itself, the error a target throws.
    if (answer === 'thrown') throw wireRefusal();
    if (answer === 'garbage returned') return GARBAGE as never;
    throw new Error(MARKER);
  };
  return { tlsMaterial: respond, logonParameters: respond };
}

/** The refusal of an outcome, checked minted and leak-free. */
function refusalOf(outcome: AuthOutcome) {
  expect(outcome.ok).toBe(false);
  if (outcome.ok) throw new Error('unreachable');
  expect(isMinted(outcome.refusal)).toBe(true);
  expect(JSON.stringify(outcome)).not.toContain(MARKER);
  return outcome.refusal as unknown as { kind: string; facts: object };
}

const wireRefusal = () =>
  WIRE_REFUSAL.ok ? undefined : (WIRE_REFUSAL.refusal as unknown);
const FALLBACK = {
  kind: 'logon-target',
  facts: { wire: 'unknown', refused: 'tls-material' },
};

async function certificateProvider() {
  const p = new CertificateAuthProvider({ load: async () => A }, {} as never);
  await p.prepare();
  return p;
}

const b64url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (extra: Record<string, unknown> = {}) =>
  `${b64url({ alg: 'none' })}.${b64url({ exp: Math.floor(Date.now() / 1000) + 3600, ...extra })}.sig`;
const TOKENS = {
  unbound: jwt(),
  bound: jwt({ cnf: { 'x5t#S256': certificateThumbprint(A) } }),
  unknown: 'opaque-access-token',
} as const;

/** A token provider holding `token`, with the certificate A pinned. */
function tokenProvider(token: string) {
  const strategy: IClientAuthentication = {
    authenticate: async (draft) => ({
      parameters: { client_id: draft.clientId },
    }),
    tlsMaterial: async () => A,
  };
  return new OidcPasswordProvider({
    clientId: 'client',
    username: 'user',
    password: 'pw',
    tokenEndpoint: 'https://idp.example/token',
    accessToken: token,
    expiresAt: Date.now() + 3600_000,
    clientAuthentication: strategy,
  });
}

describe('CertificateAuthProvider: no other way in — the target answer is its own', () => {
  it('returned refusal → that refusal', async () => {
    const out = await (await certificateProvider()).establish(
      target('returned'),
    );
    expect(refusalOf(out)).toBe(wireRefusal());
  });
  it('thrown refusal → that refusal', async () => {
    const out = await (await certificateProvider()).establish(target('thrown'));
    expect(refusalOf(out)).toBe(wireRefusal());
  });
  it('garbage returned → the logon-target fallback', async () => {
    const out = await (await certificateProvider()).establish(
      target('garbage returned'),
    );
    expect(refusalOf(out)).toMatchObject(FALLBACK);
  });
  it('garbage thrown → unknown presenting-certificate', async () => {
    const out = await (await certificateProvider()).establish(
      target('garbage thrown'),
    );
    expect(refusalOf(out)).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'presenting-certificate' },
    });
  });
});

describe('BasicAuthProvider: another way in — only a broken target refuses', () => {
  const p = () => new BasicAuthProvider('u', 'p');
  it('returned refusal → Ok', async () => {
    await expect(p().establish(target('returned'))).resolves.toEqual({
      ok: true,
    });
  });
  it('thrown refusal → that refusal', async () => {
    expect(refusalOf(await p().establish(target('thrown')))).toBe(
      wireRefusal(),
    );
  });
  it('garbage returned → Ok', async () => {
    await expect(p().establish(target('garbage returned'))).resolves.toEqual({
      ok: true,
    });
  });
  it('garbage thrown → unknown offering-logon-parameters', async () => {
    expect(
      refusalOf(await p().establish(target('garbage thrown'))),
    ).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'offering-logon-parameters' },
    });
  });
});

describe('BaseTokenProvider: the decision table on the token held', () => {
  it('unbound: returned refusal → Ok; thrown refusal → that refusal', async () => {
    await expect(
      tokenProvider(TOKENS.unbound).establish(target('returned')),
    ).resolves.toEqual({ ok: true });
    expect(
      refusalOf(
        await tokenProvider(TOKENS.unbound).establish(target('thrown')),
      ),
    ).toBe(wireRefusal());
  });

  it('unbound: garbage returned → Ok; garbage thrown → unknown presenting-certificate', async () => {
    await expect(
      tokenProvider(TOKENS.unbound).establish(target('garbage returned')),
    ).resolves.toEqual({ ok: true });
    expect(
      refusalOf(
        await tokenProvider(TOKENS.unbound).establish(target('garbage thrown')),
      ),
    ).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'presenting-certificate' },
    });
  });

  it.each(['bound', 'unknown'] as const)(
    '%s: returned and thrown refusal → that refusal; garbage → fallback / unknown',
    async (state) => {
      const token = TOKENS[state];
      expect(
        refusalOf(await tokenProvider(token).establish(target('returned'))),
      ).toBe(wireRefusal());
      expect(
        refusalOf(await tokenProvider(token).establish(target('thrown'))),
      ).toBe(wireRefusal());
      expect(
        refusalOf(
          await tokenProvider(token).establish(target('garbage returned')),
        ),
      ).toMatchObject(FALLBACK);
      expect(
        refusalOf(
          await tokenProvider(token).establish(target('garbage thrown')),
        ),
      ).toMatchObject({
        kind: 'unknown',
        facts: { operation: 'presenting-certificate' },
      });
    },
  );

  it("authorize's write: a throwing request target → unknown presenting-token", async () => {
    const out = await tokenProvider(TOKENS.unbound).authorize({
      header: () => {
        throw new Error(MARKER);
      },
      cookies: () => {
        throw new Error(MARKER);
      },
    });
    expect(refusalOf(out)).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'presenting-token' },
    });
  });
});
