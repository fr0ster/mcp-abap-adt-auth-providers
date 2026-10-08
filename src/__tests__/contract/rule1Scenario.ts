/**
 * The rule 1 matrix (spec §8.3), run by `rule1.test.ts` under plain node in
 * a child process against the compiled sources: every method of every
 * provider, with every collaborator throwing — synchronously, or as a
 * rejecting promise — each hostile value of §11.1.
 *
 * Every moment must resolve (never reject, never hang) to an outcome whose
 * refusal, if any, is minted, with the marker in none of the outcome's JSON,
 * `reason`, `hint` or `renderDiagnostics`; `getTokens()` / `refreshTokens()`
 * may reject, but only with an `AuthProviderFailure` holding nothing of the
 * marker. Each combination must also reach its collaborator at least once —
 * a combination that never calls it proves nothing, and is reported.
 *
 * This module is transpiled on its own (`import type` only from the
 * package): the child hands it the compiled `index.js` and auth-errors.
 */

import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import type * as Errors from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type * as Lib from '../../index';

export const MARKER = 'SECRET-RULE1';

/**
 * Calls of the hostile thenable's `then` / `catch`. As a value the package
 * classifies (thrown, a rejection reason, a target, a rejection) it crosses
 * a trust boundary: the package must make none.
 */
export const thenCalls = { count: 0 };

/**
 * Calls of a collaborator's answer's `then`: the answer is the consumer's
 * own code, awaited normally (the user's decision, 2026-10-07) — counted to
 * prove it was followed, never refused.
 */
export const answerThenCalls = { count: 0 };

/** A foreign thenable whose `then` / `catch` only count their calls. */
function countingThenable(): object {
  const count = () => {
    thenCalls.count += 1;
  };
  // biome-ignore lint/suspicious/noThenProperty: a foreign thenable is the hostile value
  return { then: count, catch: count, message: MARKER };
}

/** The hostile values of §11.1, each carrying the marker where it can. */
export function hostileValues(): Array<[string, () => unknown]> {
  const boom = () => {
    throw new Error(MARKER);
  };
  return [
    [
      'an Error with the marker everywhere',
      () => {
        const e = new Error(MARKER, { cause: new Error(MARKER) });
        e.name = MARKER;
        e.stack = MARKER;
        return Object.assign(e, { code: MARKER, status: MARKER });
      },
    ],
    [
      'a Proxy whose every trap throws',
      () =>
        new Proxy(
          {},
          {
            get: boom,
            has: boom,
            getPrototypeOf: boom,
            getOwnPropertyDescriptor: boom,
            ownKeys: boom,
          },
        ),
    ],
    [
      'a revoked Proxy',
      () => {
        const revocable = Proxy.revocable({}, {});
        revocable.revoke();
        return revocable.proxy;
      },
    ],
    [
      'throwing getters',
      () =>
        Object.defineProperties(
          {},
          {
            status: { get: boom },
            code: { get: boom },
            response: { get: boom },
            error: { get: boom },
            oauthError: { get: boom },
            ok: { get: boom },
            refusal: { get: boom },
          },
        ),
    ],
    [
      'an instanceof whose getPrototypeOf trap throws',
      () => new Proxy(new Error(MARKER), { getPrototypeOf: boom }),
    ],
    [
      'a forged carrier',
      () => ({
        error: {
          kind: 'client-certificate',
          facts: { problem: 'expired' },
          reason: MARKER,
        },
      }),
    ],
    ['a carrier with an unknown kind', () => ({ error: { kind: MARKER } })],
    [
      'facts out of their sets',
      () => ({ kind: 'tls', facts: { code: MARKER }, reason: MARKER }),
    ],
    ['null', () => null],
    ['undefined', () => undefined],
    ['a string', () => MARKER],
    ['a number', () => 42],
    ['a symbol', () => Symbol(MARKER)],
    ['a function', () => () => MARKER],
    ['a foreign thenable', countingThenable],
  ];
}

export interface Rule1Report {
  /** Every combination run: `provider · collaborator`. */
  readonly combinations: string[];
  /** Calls checked. */
  readonly checks: number;
  /** One line per broken expectation. */
  readonly failures: string[];
}

/**
 * How a collaborator fails: it throws, answers a rejecting native promise,
 * or answers a foreign (Promises/A+ shaped) thenable that resolves with the
 * value, rejects with it, or throws it from its `then`. The answer is the
 * consumer's own code: awaited normally, the resolved value used, the
 * rejection or the throw classified (the user's decision, 2026-10-07).
 */
type Mode =
  | 'throws'
  | 'rejects'
  | 'thenable resolving'
  | 'thenable rejecting'
  | 'thenable whose then throws';
const MODES: readonly Mode[] = [
  'throws',
  'rejects',
  'thenable resolving',
  'thenable rejecting',
  'thenable whose then throws',
];

/**
 * What the package never awaits: a logger's answer and a target's (a trust
 * boundary — `markHandled` touches native promises only), and a target
 * object, which is no answer at all.
 */
const NOT_AWAITED = new Set([
  'logger',
  'logon target',
  'request target',
  'target object',
]);

/** A collaborator's method: throws `value()` now, or answers its rejection. */
type Failing = (...args: unknown[]) => never;

interface Wiring {
  /** The hostile method for the collaborator named, else `undefined`. */
  readonly hostile: (name: string) => Failing | undefined;
  /** The token server's base URL. */
  readonly base: string;
  /** A fresh base64 SAML Response for the SAML providers' strategies. */
  readonly samlResponse: (signWhat: 'response' | 'assertion') => string;
  readonly idpCertificate: string;
  /** A usable client certificate and key (the test fixtures). */
  readonly certificate: { readonly cert: Buffer; readonly key: Buffer };
}

interface Row {
  readonly provider: string;
  readonly collaborators: readonly string[];
  readonly token: boolean;
  readonly make: (w: Wiring) => IAuthProvider;
}

const ACS = 'http://127.0.0.1:61099/acs';
const SP = 'urn:rule1:sp';
const IDP = 'urn:rule1:idp';

const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const accessToken = () =>
  `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: Math.random().toString(36).slice(2),
  })}.sig`;

/** Answers every token request, the device authorization and discovery. */
function tokenServer(): Promise<{ server: Server; base: string }> {
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      // No keep-alive: a reused socket the server just closed would be a
      // test-only ECONNRESET under load.
      res.writeHead(200, {
        'content-type': 'application/json',
        connection: 'close',
      });
      if (String(req.url).includes('/device')) {
        res.end(
          JSON.stringify({
            device_code: 'dc',
            user_code: 'UC',
            verification_uri: 'https://idp.example/device',
            expires_in: 600,
            interval: 0,
          }),
        );
        return;
      }
      res.end(
        JSON.stringify({
          access_token: accessToken(),
          refresh_token: `rt-${Math.random().toString(36).slice(2)}`,
          token_type: 'bearer',
          expires_in: 3600,
        }),
      );
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}` });
    }),
  );
}

/** A strategy that asks for the URL, then answers its state with a code. */
function codeStrategy<T>(answer: (state: string | null) => T) {
  return {
    authorize: async (request: {
      buildAuthorizationUrl(uri: string): Promise<string>;
    }) => {
      const url = await request.buildAuthorizationUrl(
        'http://127.0.0.1:61098/callback',
      );
      const state = new URL(url).searchParams.get('state');
      return {
        payload: answer(state),
        redirectUri: 'http://127.0.0.1:61098/callback',
      };
    },
  };
}

function rows(lib: typeof Lib): Row[] {
  const logger = (w: Wiring) => {
    const fail = w.hostile('logger');
    return fail
      ? { debug: fail, info: fail, warn: fail, error: fail }
      : undefined;
  };
  const report = (w: Wiring) => w.hostile('persistence report');
  const clientAuthentication = (w: Wiring) => {
    const authenticate = w.hostile('client authentication');
    if (authenticate) return { authenticate };
    const tlsMaterial = w.hostile('client authentication tlsMaterial');
    if (tlsMaterial)
      return {
        authenticate: async (draft: { clientId: string }) => ({
          parameters: { client_id: draft.clientId },
        }),
        tlsMaterial,
      };
    const loader = w.hostile('certificate loader');
    if (loader) return lib.tlsClientCertificate({ material: loader as never });
    return undefined;
  };
  /** The client's own options: a strategy, else the secret. */
  const client = (w: Wiring) => {
    const auth = clientAuthentication(w);
    return auth ? { clientAuthentication: auth } : { clientSecret: 's' };
  };
  const hooks = (w: Wiring) => ({
    ...(report(w) ? { persistence: { report: report(w) } } : {}),
    ...(logger(w) ? { logger: logger(w) } : {}),
  });
  /** The interactive strategy, or a browser strategy with a hostile part. */
  const interactive = <T>(w: Wiring, good: () => unknown): T => {
    const strategy = w.hostile('interactive strategy');
    if (strategy) return { authorize: strategy } as T;
    const launcher = w.hostile('browser launcher');
    if (launcher)
      return lib.browserCallbackStrategy({
        port: 0,
        openUrl: launcher,
        // The test's own bound: a launcher whose answer resolves has
        // succeeded, so its login waits for a browser that never comes. The
        // consumer's abort ends it.
        signal: AbortSignal.timeout(500),
      }) as T;
    const open = w.hostile('answer transport');
    if (open)
      return lib.composeAuthorization({
        presentation: lib.showUrl(),
        transport: { label: 'browser', open } as never,
        protocol: lib.oauthCode(),
        endpoint: '/callback',
      }) as T;
    return good() as T;
  };
  const TOKEN_COMMON = [
    'logger',
    'persistence report',
    'logon target',
    'request target',
    'target object',
  ];
  const CLIENT = [
    'client authentication',
    'client authentication tlsMaterial',
    'certificate loader',
  ];
  const INTERACTIVE = [
    'interactive strategy',
    'browser launcher',
    'answer transport',
  ];
  const TARGETS = ['logon target', 'request target', 'target object'];
  const saml = (w: Wiring, signWhat: 'response' | 'assertion') => {
    const validate = w.hostile('assertion validator');
    const store = w.hostile('replay store');
    const options = {
      idpCertificates: [w.idpCertificate],
      replayStore: store
        ? { recordIfUnseen: store }
        : lib.createInMemoryReplayStore(),
    };
    return {
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: SP,
      acsUrl: ACS,
      idpEntityId: IDP,
      idpInitiated: true,
      authorization: w.hostile('interactive strategy')
        ? { authorize: w.hostile('interactive strategy') }
        : {
            authorize: async () => ({
              payload: w.samlResponse(signWhat),
              redirectUri: ACS,
            }),
          },
      assertionValidator: validate
        ? { validate }
        : signWhat === 'response'
          ? lib.createSignedResponseValidator(options as never)
          : lib.createSignedAssertionValidator(options as never),
    };
  };
  return [
    {
      provider: 'BasicAuthProvider',
      collaborators: TARGETS,
      token: false,
      make: () => new lib.BasicAuthProvider('u', 'p'),
    },
    {
      provider: 'CertificateAuthProvider',
      // No request target: a certificate writes nothing to a request (rule 3).
      collaborators: ['certificate loader', 'logon target', 'target object'],
      token: false,
      make: (w) =>
        new lib.CertificateAuthProvider(
          {
            load:
              (w.hostile('certificate loader') as never) ??
              (async () => ({ ...w.certificate })),
          },
          {} as never,
        ),
    },
    {
      provider: 'SamlAuthProvider',
      collaborators: TARGETS,
      token: false,
      make: () => new lib.SamlAuthProvider('S=x'),
    },
    {
      provider: 'TokenAuthProvider.fixed',
      collaborators: TARGETS,
      token: false,
      make: () => lib.TokenAuthProvider.fixed('t'),
    },
    {
      provider: 'TokenAuthProvider.from',
      collaborators: [
        'token refresher getToken',
        'token refresher refreshToken',
        ...TARGETS,
      ],
      token: false,
      make: (w) =>
        lib.TokenAuthProvider.from({
          getToken:
            (w.hostile('token refresher getToken') as never) ??
            (async () => 't1'),
          refreshToken:
            (w.hostile('token refresher refreshToken') as never) ??
            (async () => `t-${Math.random()}`),
        }),
    },
    {
      provider: 'SncLogonProvider',
      collaborators: [
        'snc locator',
        'snc probe',
        'snc system readHead',
        'snc system readRegistryValue',
        'logger',
        'logon target',
        'request target',
        'target object',
      ],
      token: false,
      make: (w) => {
        const system = {
          platform: 'win32' as const,
          arch: 'x64',
          env: {},
          readHead:
            (w.hostile('snc system readHead') as never) ?? (async () => null),
          readRegistryValue:
            (w.hostile('snc system readRegistryValue') as never) ??
            (async () => undefined),
        };
        const locator = w.hostile('snc locator')
          ? { locate: w.hostile('snc locator') as never }
          : w.hostile('snc system readHead')
            ? new lib.DefaultSncLibraryLocator(system, 'C:\\sap\\sapcrypto.dll')
            : w.hostile('snc system readRegistryValue')
              ? new lib.DefaultSncLibraryLocator(system)
              : w.hostile('logger')
                ? {
                    // A plain failure: the H4 line is written, to the
                    // hostile logger.
                    locate: async () => {
                      throw new Error('not found');
                    },
                  }
                : {
                    locate: async () => ({
                      path: 'C:\\sap\\sapcrypto.dll',
                      archs: ['x64' as const],
                    }),
                  };
        const probe = w.hostile('snc probe');
        return new lib.SncLogonProvider({
          partnerName: 'p:CN=SID',
          locator,
          probes: [
            probe
              ? { product: 'probe', appliesTo: probe as never }
              : new lib.SecureLoginClientProbe(system),
          ],
          ...(logger(w) ? { logger: logger(w) as never } : {}),
        });
      },
    },
    {
      provider: 'ClientCredentialsProvider',
      collaborators: [...CLIENT, ...TOKEN_COMMON],
      token: true,
      make: (w) =>
        new lib.ClientCredentialsProvider({
          renewal: lib.refreshThenLogin(),
          uaaUrl: w.base,
          clientId: 'cid',
          ...client(w),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'AuthorizationCodeProvider',
      collaborators: [...INTERACTIVE, ...CLIENT, ...TOKEN_COMMON],
      token: true,
      make: (w) =>
        new lib.AuthorizationCodeProvider({
          renewal: lib.refreshThenLogin(),
          uaaUrl: w.base,
          clientId: 'cid',
          authorization: interactive(w, () => codeStrategy(() => 'code')),
          ...client(w),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'OidcBrowserProvider',
      collaborators: [...INTERACTIVE, ...CLIENT, ...TOKEN_COMMON],
      token: true,
      make: (w) =>
        new lib.OidcBrowserProvider({
          renewal: lib.refreshThenLogin(),
          clientId: 'cid',
          authorizationEndpoint: `${w.base}/authorize`,
          tokenEndpoint: `${w.base}/token`,
          authorization: interactive(w, () =>
            codeStrategy((state) => ({
              code: 'code',
              ...(state ? { state } : {}),
            })),
          ),
          ...(clientAuthentication(w)
            ? { clientAuthentication: clientAuthentication(w) }
            : {}),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'OidcDeviceFlowProvider',
      collaborators: ['device-code presenter', ...CLIENT, ...TOKEN_COMMON],
      token: true,
      make: (w) =>
        new lib.OidcDeviceFlowProvider({
          renewal: lib.refreshThenLogin(),
          clientId: 'cid',
          tokenEndpoint: `${w.base}/token`,
          deviceAuthorizationEndpoint: `${w.base}/device`,
          presenter: {
            present:
              (w.hostile('device-code presenter') as never) ??
              (async () => undefined),
          },
          ...(clientAuthentication(w)
            ? { clientAuthentication: clientAuthentication(w) }
            : {}),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'OidcPasswordProvider',
      collaborators: [...CLIENT, ...TOKEN_COMMON],
      token: true,
      make: (w) =>
        new lib.OidcPasswordProvider({
          renewal: lib.refreshThenLogin(),
          clientId: 'cid',
          username: 'u',
          password: 'p',
          tokenEndpoint: `${w.base}/token`,
          ...(clientAuthentication(w)
            ? { clientAuthentication: clientAuthentication(w) }
            : {}),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'OidcTokenExchangeProvider',
      collaborators: [...CLIENT, ...TOKEN_COMMON],
      token: true,
      make: (w) =>
        new lib.OidcTokenExchangeProvider({
          renewal: lib.refreshThenLogin(),
          clientId: 'cid',
          subjectToken: 'subject',
          subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
          tokenEndpoint: `${w.base}/token`,
          ...(clientAuthentication(w)
            ? { clientAuthentication: clientAuthentication(w) }
            : {}),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'Saml2BearerProvider',
      collaborators: [
        'interactive strategy',
        'assertion validator',
        'replay store',
        ...CLIENT,
        ...TOKEN_COMMON,
      ],
      token: true,
      make: (w) =>
        new lib.Saml2BearerProvider({
          renewal: lib.refreshThenLogin(),
          ...saml(w, 'assertion'),
          tokenUrl: `${w.base}/token`,
          clientId: 'cid',
          ...client(w),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'Saml2PureProvider',
      collaborators: [
        'interactive strategy',
        'assertion validator',
        'replay store',
        'cookie provider',
        ...TOKEN_COMMON,
      ],
      token: true,
      make: (w) =>
        new lib.Saml2PureProvider({
          renewal: lib.refreshThenLogin(),
          ...saml(w, 'response'),
          cookieProvider:
            (w.hostile('cookie provider') as never) ??
            (async () => `SAP_SESSIONID=${Math.random()}`),
          ...hooks(w),
        } as never),
    },
    {
      provider: 'UaaPasscodeProvider',
      collaborators: [
        'interactive strategy',
        'client authentication',
        ...TOKEN_COMMON,
      ],
      token: true,
      make: (w) =>
        new lib.UaaPasscodeProvider({
          renewal: lib.refreshThenLogin(),
          uaaUrl: w.base,
          clientId: 'cid',
          authorization: interactive(w, () => ({
            authorize: async () => ({
              payload: 'passcode',
              redirectUri: 'urn:passcode',
            }),
          })),
          ...client(w),
          ...hooks(w),
        } as never),
    },
  ];
}

/** A logon or request target whose every method is `fail`, or a good one. */
function targets(fail: Failing | undefined): {
  logon: ILogonTarget;
  request: IRequestTarget;
} {
  return {
    logon: {
      tlsMaterial: fail ?? (() => ({ ok: true })),
      logonParameters: fail ?? (() => ({ ok: true })),
    } as ILogonTarget,
    request: {
      header: fail ?? (() => undefined),
      cookies: fail ?? (() => undefined),
    } as IRequestTarget,
  };
}

/** Settles `run` or reports it hung; the bound is this test's own. */
async function settled(
  run: () => Promise<unknown>,
): Promise<
  | { status: 'fulfilled'; value: unknown }
  | { status: 'rejected'; reason: unknown }
  | { status: 'hung' }
> {
  let timer: NodeJS.Timeout | undefined;
  const hung = new Promise<{ status: 'hung' }>((resolve) => {
    timer = setTimeout(() => resolve({ status: 'hung' }), 10_000);
  });
  try {
    return await Promise.race([
      Promise.resolve()
        .then(run)
        .then(
          (value) => ({ status: 'fulfilled' as const, value }),
          (reason: unknown) => ({ status: 'rejected' as const, reason }),
        ),
      hung,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** JSON of anything, never throwing. */
function json(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '<unserialisable>';
  }
}

export async function run(
  lib: typeof Lib,
  errors: typeof Errors,
  signing: {
    generateKeyMaterial(): { certificatePem: string };
    signXml(xml: string, key: unknown, options?: unknown): string;
  },
  fixtures: string,
  only?: string,
): Promise<Rule1Report> {
  const certificate = {
    cert: readFileSync(join(fixtures, 'certificates', 'client.crt')),
    key: readFileSync(join(fixtures, 'certificates', 'client.key')),
  };
  const { server, base } = await tokenServer();
  const key = signing.generateKeyMaterial();
  let serial = 0;
  const iso = (offset: number) => new Date(Date.now() + offset).toISOString();
  const samlResponse = (signWhat: 'response' | 'assertion') => {
    serial += 1;
    const assertion =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a${serial}" IssueInstant="${iso(0)}" Version="2.0">` +
      `<saml:Issuer>${IDP}</saml:Issuer><saml:Subject><saml:NameID>user</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData Recipient="${ACS}" NotOnOrAfter="${iso(300_000)}"/>` +
      `</saml:SubjectConfirmation></saml:Subject>` +
      `<saml:Conditions NotBefore="${iso(-60_000)}" NotOnOrAfter="${iso(300_000)}">` +
      `<saml:AudienceRestriction><saml:Audience>${SP}</saml:Audience></saml:AudienceRestriction>` +
      `</saml:Conditions></saml:Assertion>`;
    const open =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${serial}" Destination="${ACS}">` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`;
    const xml =
      signWhat === 'assertion'
        ? `${open}${signing.signXml(assertion, key)}</samlp:Response>`
        : signing.signXml(`${open}${assertion}</samlp:Response>`, key, {
            referenceXPath: "//*[local-name(.)='Response']",
            location: {
              reference: "//*[local-name(.)='Response']",
              action: 'prepend',
            },
          });
    return Buffer.from(xml, 'utf8').toString('base64');
  };

  const combinations: string[] = [];
  const failures: string[] = [];
  let checks = 0;

  /**
   * `answered`: the collaborator answered the hostile value as its result
   * (a thenable resolving) — data the provider uses, not a thrown value. A
   * value the contract admits as a diagnostic (a registry path, say) may
   * then appear there, and so in the outcome's JSON; never in the words.
   */
  const checkOutcome = (
    where: string,
    result: Awaited<ReturnType<typeof settled>>,
    answered = false,
  ) => {
    checks += 1;
    if (result.status !== 'fulfilled') {
      failures.push(`${where}: ${result.status}`);
      return;
    }
    const outcome = result.value as AuthOutcome;
    if (
      outcome === null ||
      typeof outcome !== 'object' ||
      typeof outcome.ok !== 'boolean'
    ) {
      failures.push(`${where}: not an outcome`);
      return;
    }
    if (!answered && json(outcome).includes(MARKER))
      failures.push(`${where}: marker in JSON`);
    if (outcome.ok) return;
    const refusal = outcome.refusal;
    if (!errors.isMinted(refusal)) {
      failures.push(`${where}: refusal not minted`);
      return;
    }
    const rendered = [
      refusal.reason,
      refusal.hint ?? '',
      answered ? '' : (errors.renderDiagnostics(refusal) ?? ''),
    ];
    if (rendered.some((text) => text.includes(MARKER))) {
      failures.push(`${where}: marker in reason, hint or diagnostics`);
    }
  };
  const checkTokens = (
    where: string,
    result: Awaited<ReturnType<typeof settled>>,
  ) => {
    checks += 1;
    if (result.status === 'hung') {
      failures.push(`${where}: hung`);
      return;
    }
    if (result.status === 'fulfilled') return;
    const thrown = result.reason;
    if (!errors.isAuthProviderFailure(thrown)) {
      failures.push(`${where}: rejected with something else than a failure`);
      return;
    }
    const failure = errors.readFailure(thrown, 'unfamiliar-error');
    if (
      !errors.isMinted(failure) ||
      [json(thrown), String(thrown), json(failure), failure.reason].some(
        (text) => text.includes(MARKER),
      )
    ) {
      failures.push(`${where}: the failure holds the marker or is not minted`);
    }
  };

  try {
    for (const row of rows(lib)) {
      if (only !== undefined && row.provider !== only) continue;
      // The baseline: with nothing hostile, every moment is Ok — so a
      // combination below fails because of its collaborator, not its setup.
      {
        const provider = row.make({
          hostile: () => undefined,
          base,
          samlResponse,
          idpCertificate: key.certificatePem,
          certificate,
        });
        const { logon, request } = targets(undefined);
        for (const [moment, call] of [
          ['prepare', () => provider.prepare()],
          ['establish', () => provider.establish(logon)],
          ['authorize', () => provider.authorize(request)],
        ] as const) {
          const result = await settled(call);
          const outcome =
            result.status === 'fulfilled'
              ? (result.value as AuthOutcome)
              : undefined;
          if (outcome?.ok !== true) {
            failures.push(
              `${row.provider} · baseline · ${moment}: ${
                outcome && !outcome.ok ? outcome.refusal.reason : result.status
              }`,
            );
          }
        }
      }
      for (const collaborator of row.collaborators) {
        combinations.push(`${row.provider} · ${collaborator}`);
        for (const [valueName, value] of hostileValues()) {
          for (const mode of MODES) {
            // The hostile thenable as what a collaborator's answer resolves
            // with is adopted — the consumer's own code — and, its `then`
            // calling nothing back, never settles: a never-settling answer,
            // bounded by the consumer's AbortSignal, as any other
            // (`collaboratorThenables.test.ts`). Not a row of this matrix.
            if (
              valueName === 'a foreign thenable' &&
              mode === 'thenable resolving'
            )
              continue;
            const where = `${row.provider} · ${collaborator} · ${valueName} · ${mode}`;
            const resolvedAnswer = mode === 'thenable resolving';
            let called = 0;
            const fail = ((..._args: unknown[]) => {
              called += 1;
              if (mode === 'throws') throw value();
              if (mode === 'rejects') return Promise.reject(value());
              return {
                // biome-ignore lint/suspicious/noThenProperty: the hostile answer is a foreign thenable
                then(
                  resolve?: (v: unknown) => void,
                  reject?: (e: unknown) => void,
                ) {
                  answerThenCalls.count += 1;
                  if (mode === 'thenable resolving') resolve?.(value());
                  else if (mode === 'thenable rejecting') reject?.(value());
                  else throw value();
                },
              };
            }) as Failing;
            const wiring: Wiring = {
              hostile: (name) => (name === collaborator ? fail : undefined),
              base,
              samlResponse,
              idpCertificate: key.certificatePem,
              certificate,
            };
            let provider: IAuthProvider;
            try {
              provider = row.make(wiring);
            } catch (error) {
              failures.push(`${where}: construction threw ${json(error)}`);
              continue;
            }
            const targetFail =
              collaborator === 'logon target' ||
              collaborator === 'request target'
                ? fail
                : undefined;
            const { logon, request } = targets(targetFail);
            const asTarget = collaborator === 'target object';
            const establishWith = asTarget
              ? () => {
                  called += 1;
                  return value() as ILogonTarget;
                }
              : () => logon;
            const authorizeWith = asTarget
              ? () => {
                  called += 1;
                  return value() as IRequestTarget;
                }
              : () => request;
            if (row.token) {
              const tokens = provider as unknown as {
                getTokens(): Promise<unknown>;
                refreshTokens(): Promise<unknown>;
              };
              checkTokens(
                `${where} · getTokens`,
                await settled(() => tokens.getTokens()),
              );
            }
            checkOutcome(
              `${where} · prepare`,
              await settled(() => provider.prepare()),
              resolvedAnswer,
            );
            checkOutcome(
              `${where} · establish`,
              await settled(() => provider.establish(establishWith())),
              resolvedAnswer,
            );
            checkOutcome(
              `${where} · authorize`,
              await settled(() => provider.authorize(authorizeWith())),
              resolvedAnswer,
            );
            checkOutcome(
              `${where} · rejected 401`,
              await settled(() =>
                provider.rejected({
                  at: 'request',
                  status: 401,
                  error: value(),
                } as never),
              ),
              resolvedAnswer,
            );
            checkOutcome(
              `${where} · rejected RFC_LOGON_FAILURE`,
              await settled(() =>
                provider.rejected({
                  at: 'logon',
                  error: { key: 'RFC_LOGON_FAILURE', message: MARKER },
                } as never),
              ),
              resolvedAnswer,
            );
            checkOutcome(
              `${where} · rejected with the value itself`,
              await settled(() => provider.rejected(value() as never)),
              resolvedAnswer,
            );
            checkOutcome(
              `${where} · authorize again`,
              await settled(() => provider.authorize(authorizeWith())),
              resolvedAnswer,
            );
            if (row.token) {
              const tokens = provider as unknown as {
                refreshTokens(): Promise<unknown>;
              };
              checkTokens(
                `${where} · refreshTokens`,
                await settled(() => tokens.refreshTokens()),
              );
            }
            if (thenCalls.count > 0) {
              failures.push(
                `${where}: a classified thenable's then was called ${thenCalls.count} time(s)`,
              );
              thenCalls.count = 0;
            }
            if (
              mode.startsWith('thenable') &&
              !NOT_AWAITED.has(collaborator) &&
              answerThenCalls.count === 0
            )
              failures.push(`${where}: the answer was never followed`);
            answerThenCalls.count = 0;
            if (called === 0)
              failures.push(`${where}: collaborator never called`);
          }
        }
      }
    }
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
  return { combinations, checks, failures };
}
