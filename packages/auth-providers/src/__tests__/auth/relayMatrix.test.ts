/**
 * How a provider relays a logon target's answer (rule 4). The same
 * minted refusal **returned** by the target means "the wire cannot take
 * this"; **thrown**, "the target is broken". Garbage returned is the
 * `logon-target` fallback; garbage thrown is `unknown` with the operation.
 */
import { CERTIFICATES } from '../helpers/packagePaths';
import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { authError, isMinted } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  ICertificateMaterial,
  IClientAuthentication,
  ILogonTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { refreshThenLogin } from '../../renewal';
import { mockedAxios } from '../helpers/axiosModuleMock';
import { caseTitle, matchObject, notContains } from '../helpers/expectations';

const MARKER = 'SECRET-MARKER';
const dir = CERTIFICATES;
const read = (name: string) => readFileSync(join(dir, name));
const A: ICertificateMaterial = {
  cert: read('client.crt'),
  key: read('client.key'),
};

/** One minted refusal, the very object a target returns or throws. */
const WIRE_REFUSAL: AuthOutcome = {
  ok: false,
  refusal: authError['logon-target']({ wire: 'rfc', refused: 'tls-material' }),
};
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
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error('unreachable');
  assert.equal(isMinted(outcome.refusal), true);
  notContains(JSON.stringify(outcome), MARKER);
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
    renewal: refreshThenLogin(),
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
    assert.equal(refusalOf(out), wireRefusal());
  });
  it('thrown refusal → that refusal', async () => {
    const out = await (await certificateProvider()).establish(target('thrown'));
    assert.equal(refusalOf(out), wireRefusal());
  });
  it('garbage returned → the logon-target fallback', async () => {
    const out = await (await certificateProvider()).establish(
      target('garbage returned'),
    );
    matchObject(refusalOf(out), FALLBACK);
  });
  it('garbage thrown → unknown presenting-certificate', async () => {
    const out = await (await certificateProvider()).establish(
      target('garbage thrown'),
    );
    matchObject(refusalOf(out), {
      kind: 'unknown',
      facts: { operation: 'presenting-certificate' },
    });
  });
});

describe('BasicAuthProvider: another way in — only a broken target refuses', () => {
  const p = () => new BasicAuthProvider('u', 'p');
  it('returned refusal → Ok', async () => {
    assert.deepEqual(await p().establish(target('returned')), {
      ok: true,
    });
  });
  it('thrown refusal → that refusal', async () => {
    assert.equal(
      refusalOf(await p().establish(target('thrown'))),
      wireRefusal(),
    );
  });
  it('garbage returned → Ok', async () => {
    assert.deepEqual(await p().establish(target('garbage returned')), {
      ok: true,
    });
  });
  it('garbage thrown → unknown offering-logon-parameters', async () => {
    matchObject(refusalOf(await p().establish(target('garbage thrown'))), {
      kind: 'unknown',
      facts: { operation: 'offering-logon-parameters' },
    });
  });
});

describe('BaseTokenProvider: the decision table on the token held', () => {
  it('unbound: returned refusal → Ok; thrown refusal → that refusal', async () => {
    assert.deepEqual(
      await tokenProvider(TOKENS.unbound).establish(target('returned')),
      { ok: true },
    );
    assert.equal(
      refusalOf(
        await tokenProvider(TOKENS.unbound).establish(target('thrown')),
      ),
      wireRefusal(),
    );
  });

  it('unbound: garbage returned → Ok; garbage thrown → unknown presenting-certificate', async () => {
    assert.deepEqual(
      await tokenProvider(TOKENS.unbound).establish(target('garbage returned')),
      { ok: true },
    );
    matchObject(
      refusalOf(
        await tokenProvider(TOKENS.unbound).establish(target('garbage thrown')),
      ),
      {
        kind: 'unknown',
        facts: { operation: 'presenting-certificate' },
      },
    );
  });

  for (const [caseIndex, caseRow] of (
    ['bound', 'unknown'] as const
  ).entries()) {
    const state = caseRow;
    it(
      caseTitle(
        '%s: returned and thrown refusal → that refusal; garbage → fallback / unknown',
        caseRow,
        caseIndex,
      ),
      async () => {
        const token = TOKENS[state];
        assert.equal(
          refusalOf(await tokenProvider(token).establish(target('returned'))),
          wireRefusal(),
        );
        assert.equal(
          refusalOf(await tokenProvider(token).establish(target('thrown'))),
          wireRefusal(),
        );
        matchObject(
          refusalOf(
            await tokenProvider(token).establish(target('garbage returned')),
          ),
          FALLBACK,
        );
        matchObject(
          refusalOf(
            await tokenProvider(token).establish(target('garbage thrown')),
          ),
          {
            kind: 'unknown',
            facts: { operation: 'presenting-certificate' },
          },
        );
      },
    );
  }

  it("authorize's write: a throwing request target → unknown presenting-token", async () => {
    const out = await tokenProvider(TOKENS.unbound).authorize({
      header: () => {
        throw new Error(MARKER);
      },
      cookies: () => {
        throw new Error(MARKER);
      },
    });
    matchObject(refusalOf(out), {
      kind: 'unknown',
      facts: { operation: 'presenting-token' },
    });
  });
});
