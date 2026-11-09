// The SPNego protocol suite: SpnegoAuthProvider with gssapiTokenSource against
// a real MIT KDC and a real Negotiate-only service (Apache, mod_auth_gssapi) —
// auth-providers' Kerberos stand, tests/stand/kerberos, spec §6.
//
// Where it runs: inside the stand's spnego-client container only
// (`npm run test:stand` in packages/auth-providers, or the root's), which sets
// STAND_KERBEROS=1, KRB5_CONFIG (the stand's krb5.conf) and KRB5CCNAME (an
// empty cache in a temporary directory that this suite fills with kinit), and
// has built both packages and the kerberos binding there. Anywhere else the
// suite is skipped and says so.
//
// The provider is loaded from its sibling's source (test-only, no npm link);
// the child harness (prepare-child.mjs) loads both built packages. A case that
// needs another Kerberos environment runs in a child node process given that
// environment; this suite never writes its own process.env. This package has
// no no-real-program guard: kinit, klist and the children run by absolute
// path.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { before, describe, it } from 'node:test';
import { inspect } from 'node:util';
import type {
  AuthOutcome,
  IAuthProvider,
  INegotiateTokenSource,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { gssapiTokenSource } from '../../gssapiTokenSource';
import {
  cases,
  caseTitle,
  contains,
  matchObject,
  notContains,
} from '../helpers/expectations';

const ON = process.env.STAND_KERBEROS === '1';
const describeStand = ON ? describe : describe.skip;
const where = ON
  ? 'the Kerberos stand (spnego-client container)'
  : 'the Kerberos stand — skipped: STAND_KERBEROS=1 is set only inside the stand container spnego-client (npm run test:stand in packages/auth-providers)';

const GSSAPI_DIR = path.resolve(__dirname, '../../..');
const PROVIDERS_DIR = path.resolve(GSSAPI_DIR, '../auth-providers');
const KERBEROS_DIR = path.join(PROVIDERS_DIR, 'tests/stand/kerberos');
const HARNESS = path.join(KERBEROS_DIR, 'client/prepare-child.mjs');
const DEAD_KDC_CONF = path.join(KERBEROS_DIR, 'krb5-dead-kdc.conf');
const PASSWORD = path.join(KERBEROS_DIR, 'alice.password');
const KINIT = '/usr/bin/kinit';
const KLIST = '/usr/bin/klist';

const SERVICE = 'HTTP@negotiate.stand.test';
const STALE = 'HTTP@stale.stand.test';
const UNKNOWN = 'HTTP@unknown.stand.test';
const MECHANISMS = ['spnego', 'kerberos'] as const;
type Mechanism = (typeof MECHANISMS)[number];

type Logger = Record<
  'debug' | 'info' | 'warn' | 'error',
  (...args: unknown[]) => void
>;
type SpnegoAuthProviderCtor = new (config: {
  servicePrincipal: string;
  tokenSource: INegotiateTokenSource;
  logger?: Logger;
}) => IAuthProvider;

// ------------------------------------------------- what the oracle reads

/**
 * Every token the suite saw, and every surface of the provider and the source
 * a token must not reach: log lines, outcomes and refusals, the children's
 * output. The service's answers are not among them — a KRB-ERROR names the
 * service principal, which the ticket carries in the clear too.
 */
const issued: string[] = [];
const surfaces: string[] = [];

function recordingLogger(): Logger {
  const record =
    (level: string) =>
    (...args: unknown[]) =>
      surfaces.push(`${level} ${inspect(args, { depth: 10 })}`);
  return {
    debug: record('debug'),
    info: record('info'),
    warn: record('warn'),
    error: record('error'),
  };
}

function seen(outcome: AuthOutcome): AuthOutcome {
  surfaces.push(inspect(outcome, { depth: 10 }), JSON.stringify(outcome));
  if (!outcome.ok) surfaces.push(String(outcome.refusal.reason));
  return outcome;
}

/**
 * Whether any part of a token can be read back from a text: a window of 16
 * characters at every 8th offset, of the token as sent, in the base64url
 * alphabet, and of its bytes in hex.
 */
function fragmentsOf(token: string): string[] {
  const bytes = Buffer.from(token, 'base64');
  const forms = [
    token,
    bytes.toString('base64url'),
    bytes.toString('hex'),
    bytes.toString('latin1'),
  ];
  const out: string[] = [];
  for (const form of forms)
    for (let i = 0; i + 16 <= form.length; i += 8)
      out.push(form.slice(i, i + 16));
  return out;
}
const holdsToken = (text: string, token: string): boolean =>
  fragmentsOf(token).some((f) => text.includes(f));

// ----------------------------------------------------------- the helpers

/**
 * The source as the provider sees it, every token it answers recorded — the
 * ones prepare() obtains and drops included — for the oracle.
 */
function recordingSource(source: INegotiateTokenSource): INegotiateTokenSource {
  return {
    async token(servicePrincipal, options) {
      const answer = await source.token(servicePrincipal, options);
      if (answer.ok) issued.push(answer.token);
      return answer;
    },
  };
}

function provider(
  mechanism: Mechanism,
  servicePrincipal = SERVICE,
): IAuthProvider {
  // The sibling's source, loaded only here: off the stand nothing of it is
  // compiled.
  const { SpnegoAuthProvider } = require(path.join(PROVIDERS_DIR, 'src')) as {
    SpnegoAuthProvider: SpnegoAuthProviderCtor;
  };
  return new SpnegoAuthProvider({
    servicePrincipal,
    tokenSource: recordingSource(gssapiTokenSource({ mechanism })),
    logger: recordingLogger(),
  });
}

/** One authorize(): the Authorization header the provider wrote. */
async function authorized(p: IAuthProvider): Promise<string> {
  const headers: Record<string, string> = {};
  const target: IRequestTarget = {
    header(name, value) {
      headers[name] = value;
    },
    cookies() {
      throw new Error('SPNego writes no cookie');
    },
  };
  assert.deepEqual(seen(await p.authorize(target)), { ok: true });
  assert.deepEqual(Object.keys(headers), ['Authorization']);
  const value = headers.Authorization ?? '';
  assert.equal(value.startsWith('Negotiate '), true);
  contains(issued, value.slice('Negotiate '.length));
  return value;
}

interface Answer {
  status: number;
  headers: http.IncomingHttpHeaders;
}

/** A GET on the stand's network; the Host header is the host connected to. */
function get(
  host: string,
  urlPath: string,
  authorization?: string,
): Promise<Answer> {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host,
        port: 80,
        path: urlPath,
        method: 'GET',
        agent: false,
        headers: authorization ? { Authorization: authorization } : {},
      },
      (response) => {
        response.resume();
        response.on('end', () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
          }),
        );
      },
    );
    request.on('error', reject);
    request.end();
  });
}

function kinit(env: NodeJS.ProcessEnv): void {
  const run = spawnSync(KINIT, ['alice@STAND.TEST'], {
    env,
    input: fs.readFileSync(PASSWORD),
    encoding: 'utf8',
  });
  assert.equal(run.status, 0);
}

function klist(env: NodeJS.ProcessEnv): string {
  const run = spawnSync(KLIST, [], { env, encoding: 'utf8' });
  assert.equal(run.status, 0);
  return run.stdout;
}

interface ChildAnswer {
  ok: boolean;
  kind?: string;
  variant?: string;
  facts?: Record<string, unknown>;
  logs: unknown[];
}

/** prepare() in a child node process with the environment given. */
function prepareInChild(
  mechanism: Mechanism,
  servicePrincipal: string,
  env: NodeJS.ProcessEnv,
): ChildAnswer {
  const run = spawnSync(
    process.execPath,
    [HARNESS, PROVIDERS_DIR, GSSAPI_DIR, mechanism, servicePrincipal],
    { env, encoding: 'utf8' },
  );
  surfaces.push(run.stdout, run.stderr);
  assert.equal(run.status, 0);
  const lines = run.stdout.trim().split('\n');
  return JSON.parse(lines.at(-1) ?? '') as ChildAnswer;
}

function tempDir(label: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `spnego-${label}-`));
}

/** A token's mechanism, from its GSS frame's OID (RFC 2743 §3.1). */
function frameOid(token: string): string {
  const bytes = Buffer.from(token, 'base64');
  assert.equal(bytes[0], 0x60);
  const lengthBytes = (bytes[1] ?? 0) & 0x80 ? (bytes[1] ?? 0) & 0x7f : 0;
  const at = 2 + lengthBytes;
  assert.equal(bytes[at], 0x06);
  return bytes.subarray(at + 2, at + 2 + (bytes[at + 1] ?? 0)).toString('hex');
}
const OID_FOR: Record<Mechanism, string> = {
  spnego: '2b0601050502', // 1.3.6.1.5.5.2
  kerberos: '2a864886f712010202', // 1.2.840.113554.1.2.2
};

// ------------------------------------------------------------- the cases

describeStand(where, () => {
  before(() => {
    // The suite's own cache, given by run-suite.sh; filled here with alice's
    // TGT for every in-process case.
    const cache = process.env.KRB5CCNAME ?? '';
    assert.equal(cache.startsWith(`FILE:${os.tmpdir()}`), true);
    kinit(process.env);
    contains(klist(process.env), 'krbtgt/STAND.TEST@STAND.TEST');
  });

  for (const [caseIndex, caseRow] of MECHANISMS.entries()) {
    const mechanism = caseRow;
    describe(caseTitle('mechanism %s', caseRow, caseIndex), () => {
      it('a ticket for alice: 200, the service names alice', async () => {
        const p = provider(mechanism);
        assert.deepEqual(seen(await p.prepare()), { ok: true });
        const authorization = await authorized(p);
        assert.equal(
          frameOid(authorization.slice('Negotiate '.length)),
          OID_FOR[mechanism],
        );
        const answer = await get('negotiate.stand.test', '/sap', authorization);
        assert.equal(answer.status, 200);
        assert.equal(answer.headers['x-remote-user'], 'alice');
      });

      it('two requests: two different tokens, both 200; the first resent is refused', async () => {
        const p = provider(mechanism);
        const first = await authorized(p);
        const second = await authorized(p);
        assert.notEqual(second, first);
        assert.equal(
          (await get('negotiate.stand.test', '/sap', first)).status,
          200,
        );
        assert.equal(
          (await get('negotiate.stand.test', '/sap', second)).status,
          200,
        );
        // The first token by hand, once more: the service's replay cache
        // refuses it — the reason the provider never reuses one.
        assert.equal(
          (await get('negotiate.stand.test', '/sap', first)).status,
          401,
        );
      });

      for (const [caseIndex, caseRow] of cases([
        ['a missing cache file', false],
        ['an empty cache file', true],
      ]).entries()) {
        const [_label, empty] = caseRow;
        it(
          caseTitle(
            'no ticket (%s): prepare() is spnego no-credential, no request sent',
            caseRow,
            caseIndex,
          ),
          () => {
            const dir = tempDir('no-ticket');
            try {
              const cache = path.join(dir, 'cache');
              if (empty) fs.writeFileSync(cache, '');
              const answer = prepareInChild(mechanism, SERVICE, {
                ...process.env,
                KRB5CCNAME: `FILE:${cache}`,
              });
              matchObject(answer, {
                ok: false,
                kind: 'spnego',
                variant: 'no-credential',
                facts: {
                  problem: 'no-credential',
                  operation: 'obtaining-negotiate-token',
                },
              });
            } finally {
              fs.rmSync(dir, { recursive: true, force: true });
            }
          },
        );
      }

      it('a principal the KDC does not know: spnego service-unknown', async () => {
        const outcome = seen(await provider(mechanism, UNKNOWN).prepare());
        assert.equal(outcome.ok, false);
        if (outcome.ok) return;
        matchObject(outcome.refusal, {
          kind: 'spnego',
          variant: 'service-unknown',
          facts: {
            problem: 'service-unknown',
            operation: 'obtaining-negotiate-token',
          },
        });
      });

      it('a KDC that does not answer, a TGT and no service ticket: spnego kdc-unreachable', () => {
        const dir = tempDir('dead-kdc');
        try {
          const env = {
            ...process.env,
            KRB5CCNAME: `FILE:${path.join(dir, 'cache')}`,
          };
          kinit(env);
          const tickets = klist(env);
          contains(tickets, 'krbtgt/STAND.TEST@STAND.TEST');
          notContains(tickets, 'HTTP/negotiate.stand.test');
          const answer = prepareInChild(mechanism, SERVICE, {
            ...env,
            KRB5_CONFIG: DEAD_KDC_CONF,
          });
          matchObject(answer, {
            ok: false,
            kind: 'spnego',
            variant: 'kdc-unreachable',
            facts: {
              problem: 'kdc-unreachable',
              operation: 'obtaining-negotiate-token',
            },
          });
        } finally {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      });

      it('a ticket the service cannot read (stale keytab): 401, credential-refused kerberos-ticket', async () => {
        const p = provider(mechanism, STALE);
        assert.deepEqual(seen(await p.prepare()), { ok: true });
        const answer = await get(
          'stale.stand.test',
          '/sap',
          await authorized(p),
        );
        assert.equal(answer.status, 401);
        const outcome = seen(
          await p.rejected({ at: 'request', status: 401, error: undefined }),
        );
        matchObject(outcome, {
          ok: false,
          refusal: {
            kind: 'credential-refused',
            facts: { credential: 'kerberos-ticket', at: 'request' },
          },
        });
      });

      it('the configured continuation (401, WWW-Authenticate: Negotiate <token>): credential-refused', async () => {
        const p = provider(mechanism);
        const answer = await get(
          'negotiate.stand.test',
          '/continuation',
          await authorized(p),
        );
        assert.equal(answer.status, 401);
        const challenge = answer.headers['www-authenticate'];
        assert.equal(typeof challenge, 'string');
        assert.equal(String(challenge).startsWith('Negotiate '), true);
        assert.ok(
          String(challenge).slice('Negotiate '.length).length > 0,
          `${String(challenge).slice('Negotiate '.length).length} > ${0}`,
        );
        const outcome = seen(
          await p.rejected({ at: 'request', status: 401, error: undefined }),
        );
        matchObject(outcome, {
          ok: false,
          refusal: {
            kind: 'credential-refused',
            facts: { credential: 'kerberos-ticket', at: 'request' },
          },
        });
      });
    });
  }

  it('the oracle reads a token back (it is not blind)', () => {
    const token = issued[0] ?? '';
    assert.ok(token.length > 0, `${token.length} > ${0}`);
    const bytes = Buffer.from(token, 'base64');
    assert.equal(holdsToken(`x ${token.slice(40, 60)} y`, token), true);
    assert.equal(
      holdsToken(bytes.toString('base64url').slice(80), token),
      true,
    );
    assert.equal(
      holdsToken(bytes.toString('hex').slice(100, 140), token),
      true,
    );
  });

  it('no token in any log line, error or refusal of any case', () => {
    // Per mechanism: prepare() and authorize() for alice, two authorize()s,
    // prepare() and authorize() for the stale service, one for the
    // continuation.
    assert.equal(issued.length, 14);
    assert.ok(surfaces.length > 0, `${surfaces.length} > ${0}`);
    for (const token of issued)
      for (const surface of surfaces)
        assert.equal(holdsToken(surface, token), false);
  });
});
