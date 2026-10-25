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
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { inspect } from 'node:util';
import { beforeAll, describe, expect, it } from '@jest/globals';
import type {
  AuthOutcome,
  IAuthProvider,
  INegotiateTokenSource,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { gssapiTokenSource } from '../../gssapiTokenSource';

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
    tokenSource: gssapiTokenSource({ mechanism }),
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
  expect(seen(await p.authorize(target))).toEqual({ ok: true });
  expect(Object.keys(headers)).toEqual(['Authorization']);
  const value = headers.Authorization ?? '';
  expect(value.startsWith('Negotiate ')).toBe(true);
  const token = value.slice('Negotiate '.length);
  issued.push(token);
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
  expect(run.status).toBe(0);
}

function klist(env: NodeJS.ProcessEnv): string {
  const run = spawnSync(KLIST, [], { env, encoding: 'utf8' });
  expect(run.status).toBe(0);
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
  expect(run.status).toBe(0);
  const lines = run.stdout.trim().split('\n');
  return JSON.parse(lines.at(-1) ?? '') as ChildAnswer;
}

function tempDir(label: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `spnego-${label}-`));
}

/** A token's mechanism, from its GSS frame's OID (RFC 2743 §3.1). */
function frameOid(token: string): string {
  const bytes = Buffer.from(token, 'base64');
  expect(bytes[0]).toBe(0x60);
  const lengthBytes = (bytes[1] ?? 0) & 0x80 ? (bytes[1] ?? 0) & 0x7f : 0;
  const at = 2 + lengthBytes;
  expect(bytes[at]).toBe(0x06);
  return bytes.subarray(at + 2, at + 2 + (bytes[at + 1] ?? 0)).toString('hex');
}
const OID_FOR: Record<Mechanism, string> = {
  spnego: '2b0601050502', // 1.3.6.1.5.5.2
  kerberos: '2a864886f712010202', // 1.2.840.113554.1.2.2
};

// ------------------------------------------------------------- the cases

describeStand(where, () => {
  beforeAll(() => {
    // The suite's own cache, given by run-suite.sh; filled here with alice's
    // TGT for every in-process case.
    const cache = process.env.KRB5CCNAME ?? '';
    expect(cache.startsWith(`FILE:${os.tmpdir()}`)).toBe(true);
    kinit(process.env);
    expect(klist(process.env)).toContain('krbtgt/STAND.TEST@STAND.TEST');
  });

  describe.each(MECHANISMS)('mechanism %s', (mechanism) => {
    it('a ticket for alice: 200, the service names alice', async () => {
      const p = provider(mechanism);
      expect(seen(await p.prepare())).toEqual({ ok: true });
      const authorization = await authorized(p);
      expect(frameOid(authorization.slice('Negotiate '.length))).toBe(
        OID_FOR[mechanism],
      );
      const answer = await get('negotiate.stand.test', '/sap', authorization);
      expect(answer.status).toBe(200);
      expect(answer.headers['x-remote-user']).toBe('alice');
    });

    it('two requests: two different tokens, both 200; the first resent is refused', async () => {
      const p = provider(mechanism);
      const first = await authorized(p);
      const second = await authorized(p);
      expect(second).not.toBe(first);
      expect((await get('negotiate.stand.test', '/sap', first)).status).toBe(
        200,
      );
      expect((await get('negotiate.stand.test', '/sap', second)).status).toBe(
        200,
      );
      // The first token by hand, once more: the service's replay cache
      // refuses it — the reason the provider never reuses one.
      expect((await get('negotiate.stand.test', '/sap', first)).status).toBe(
        401,
      );
    });

    it.each([
      ['a missing cache file', false],
      ['an empty cache file', true],
    ])(
      'no ticket (%s): prepare() is spnego no-credential, no request sent',
      (_label, empty) => {
        const dir = tempDir('no-ticket');
        try {
          const cache = path.join(dir, 'cache');
          if (empty) fs.writeFileSync(cache, '');
          const answer = prepareInChild(mechanism, SERVICE, {
            ...process.env,
            KRB5CCNAME: `FILE:${cache}`,
          });
          expect(answer).toMatchObject({
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

    it('a principal the KDC does not know: spnego service-unknown', async () => {
      const outcome = seen(await provider(mechanism, UNKNOWN).prepare());
      expect(outcome.ok).toBe(false);
      if (outcome.ok) return;
      expect(outcome.refusal).toMatchObject({
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
        expect(tickets).toContain('krbtgt/STAND.TEST@STAND.TEST');
        expect(tickets).not.toContain('HTTP/negotiate.stand.test');
        const answer = prepareInChild(mechanism, SERVICE, {
          ...env,
          KRB5_CONFIG: DEAD_KDC_CONF,
        });
        expect(answer).toMatchObject({
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
      expect(seen(await p.prepare())).toEqual({ ok: true });
      const answer = await get('stale.stand.test', '/sap', await authorized(p));
      expect(answer.status).toBe(401);
      const outcome = seen(
        await p.rejected({ at: 'request', status: 401, error: undefined }),
      );
      expect(outcome).toMatchObject({
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
      expect(answer.status).toBe(401);
      const challenge = answer.headers['www-authenticate'];
      expect(typeof challenge).toBe('string');
      expect(String(challenge).startsWith('Negotiate ')).toBe(true);
      expect(
        String(challenge).slice('Negotiate '.length).length,
      ).toBeGreaterThan(0);
      const outcome = seen(
        await p.rejected({ at: 'request', status: 401, error: undefined }),
      );
      expect(outcome).toMatchObject({
        ok: false,
        refusal: {
          kind: 'credential-refused',
          facts: { credential: 'kerberos-ticket', at: 'request' },
        },
      });
    });
  });

  it('the oracle reads a token back (it is not blind)', () => {
    const token = issued[0] ?? '';
    expect(token.length).toBeGreaterThan(0);
    const bytes = Buffer.from(token, 'base64');
    expect(holdsToken(`x ${token.slice(40, 60)} y`, token)).toBe(true);
    expect(holdsToken(bytes.toString('base64url').slice(80), token)).toBe(true);
    expect(holdsToken(bytes.toString('hex').slice(100, 140), token)).toBe(true);
  });

  it('no token in any log line, error or refusal of any case', () => {
    expect(issued.length).toBe(10);
    expect(surfaces.length).toBeGreaterThan(0);
    for (const token of issued)
      for (const surface of surfaces)
        expect(holdsToken(surface, token)).toBe(false);
  });
});
