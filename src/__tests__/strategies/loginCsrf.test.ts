/**
 * Login CSRF: the providers mint `state` (and, for UAA, the PKCE
 * pair) for every URL they build — a configured URL without one gets the
 * provider's; the named browser compositions refuse every callback
 * until the URL is built and the channel armed, then only this login's
 * `state` settles one; the manual paste compares a pasted URL's `state`.
 * The composer's order and the listener's gate are proven in
 * `authorization/composer.test.ts` and `listenerTransports.test.ts`.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, jest } from '@jest/globals';
import type {
  AuthorizationRequest,
  IAuthorizationStrategy,
  IBrowser,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { refreshThenLogin } from '../../renewal';
import {
  browserCallbackStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
  staticCodeStrategy,
} from '../../strategies';
import { manualPasteStrategy } from '../../strategies/manualStrategies';
import { callbackGet, ignoreCounter } from '../helpers/callbackHttp';
import { configurationOf } from '../helpers/minted';
import { recordingBrowser } from '../helpers/recordingBrowser';

const CALLBACK = 'http://localhost:61001/callback';

const stateOf = (url: string): string | null =>
  new URL(url).searchParams.get('state');
const challengeOf = (verifier: string): string =>
  createHash('sha256').update(verifier).digest('base64url');
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;

/** A JWT the provider can read an expiry from; never verified. */
const accessToken = (): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`;
};

/** A token endpoint on a real socket, recording every form it is sent. */
let tokenServer: http.Server;
let tokenBase = '';
const forms: Array<Record<string, string>> = [];
beforeAll(async () => {
  tokenServer = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => {
      body += chunk;
    });
    req.on('end', () => {
      forms.push(Object.fromEntries(new URLSearchParams(body)));
      res.setHeader('Content-Type', 'application/json');
      // No refresh token: the next renewal is a login.
      res.end(
        JSON.stringify({ access_token: accessToken(), expires_in: 3600 }),
      );
    });
  });
  await new Promise<void>((resolve) =>
    tokenServer.listen(0, '127.0.0.1', resolve),
  );
  tokenBase = `http://127.0.0.1:${(tokenServer.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((resolve) => tokenServer.close(() => resolve()));
});

/** A strategy that builds the URL `builds` times and answers a code. */
function recordingStrategy(
  urls: string[],
  builds = 1,
): IAuthorizationStrategy<string> {
  return {
    async authorize(request: AuthorizationRequest) {
      for (let i = 0; i < builds; i++) {
        urls.push(await request.buildAuthorizationUrl(CALLBACK));
      }
      return { payload: 'the-code', redirectUri: CALLBACK };
    },
  };
}

const uaaProvider = (
  authorization: IAuthorizationStrategy<string>,
  authorizationUrl?: string,
) =>
  new AuthorizationCodeProvider({
    renewal: refreshThenLogin(),
    uaaUrl: tokenBase,
    clientId: 'cid',
    clientSecret: 'sec',
    authorization,
    ...(authorizationUrl === undefined ? {} : { authorizationUrl }),
  });

describe('AuthorizationCodeProvider: state and PKCE for the URL it builds', () => {
  it('the URL carries state, code_challenge and S256; the exchange its code_verifier', async () => {
    forms.length = 0;
    const urls: string[] = [];
    await uaaProvider(recordingStrategy(urls)).getTokens();
    const url = new URL(urls[0] as string);
    expect(url.searchParams.get('state')).toMatch(BASE64URL_32);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    const verifier = forms[0]?.code_verifier as string;
    expect(verifier).toMatch(BASE64URL_32);
    expect(url.searchParams.get('code_challenge')).toBe(challengeOf(verifier));
  });

  it('mints a fresh state and verifier for every attempt', async () => {
    forms.length = 0;
    const urls: string[] = [];
    const provider = uaaProvider(recordingStrategy(urls));
    await provider.getTokens();
    await provider.refreshTokens();
    expect(urls).toHaveLength(2);
    expect(stateOf(urls[0] as string)).not.toBe(stateOf(urls[1] as string));
    expect(forms).toHaveLength(2);
    expect(forms[0]?.code_verifier).not.toBe(forms[1]?.code_verifier);
    expect(new URL(urls[1] as string).searchParams.get('code_challenge')).toBe(
      challengeOf(forms[1]?.code_verifier as string),
    );
  });

  it('mints anew for every call of the builder; the exchange sends the last one’s verifier', async () => {
    forms.length = 0;
    const urls: string[] = [];
    await uaaProvider(recordingStrategy(urls, 2)).getTokens();
    expect(stateOf(urls[0] as string)).not.toBe(stateOf(urls[1] as string));
    expect(new URL(urls[1] as string).searchParams.get('code_challenge')).toBe(
      challengeOf(forms[0]?.code_verifier as string),
    );
  });

  it('a configured authorizationUrl without state gets a minted state and nothing else; no code_verifier', async () => {
    forms.length = 0;
    const urls: string[] = [];
    // Escapes and `~` a reserialisation would change: kept byte for byte.
    const configured = `https://uaa.example/oauth/authorize?client_id=c%7Eid&redirect_uri=${encodeURIComponent(CALLBACK)}&scope=a%20b&response_type=code`;
    const provider = uaaProvider(recordingStrategy(urls), configured);
    await provider.getTokens();
    await provider.refreshTokens();
    expect(urls).toHaveLength(2);
    for (const url of urls) {
      expect(url.startsWith(`${configured}&state=`)).toBe(true);
      const state = url.slice(`${configured}&state=`.length);
      expect(state).toMatch(BASE64URL_32);
      expect(new URL(url).searchParams.getAll('state')).toEqual([state]);
      expect(new URL(url).searchParams.has('code_challenge')).toBe(false);
    }
    // Minted anew for every URL built.
    expect(stateOf(urls[0] as string)).not.toBe(stateOf(urls[1] as string));
    expect(forms[0]).not.toHaveProperty('code_verifier');
  });

  it.each([
    ['without a query', 'https://uaa.example/authorize', '?'],
    ['with an empty query', 'https://uaa.example/authorize?', ''],
    ['with a query ending in &', 'https://uaa.example/authorize?a=1&', ''],
  ])(
    'a configured URL %s gets its state appended in place',
    async (_c, configured, joint) => {
      const urls: string[] = [];
      await uaaProvider(recordingStrategy(urls), configured).getTokens();
      expect(urls[0]?.startsWith(`${configured}${joint}state=`)).toBe(true);
      expect(stateOf(urls[0] as string)).toMatch(BASE64URL_32);
    },
  );

  it('a configured URL with a fragment gets its state before the fragment', async () => {
    const urls: string[] = [];
    await uaaProvider(
      recordingStrategy(urls),
      'https://uaa.example/authorize?a=1#frag',
    ).getTokens();
    const url = new URL(urls[0] as string);
    expect(url.hash).toBe('#frag');
    expect(url.searchParams.get('a')).toBe('1');
    expect(url.searchParams.get('state')).toMatch(BASE64URL_32);
  });

  it.each([
    ['its own state', 'state=consumer-state', ['consumer-state']],
    ['an empty state', 'state=', ['']],
    ['two states', 'state=a&state=b', ['a', 'b']],
  ])(
    'a configured authorizationUrl with %s keeps it unchanged',
    async (_c, query, states) => {
      const urls: string[] = [];
      const configured = `https://uaa.example/oauth/authorize?client_id=cid&${query}`;
      await uaaProvider(recordingStrategy(urls), configured).getTokens();
      expect(urls).toEqual([configured]);
      expect(new URL(urls[0] as string).searchParams.getAll('state')).toEqual(
        states,
      );
    },
  );

  it.each([
    ['a leading space', ' https://uaa.example/authorize?client_id=cid'],
    ['a trailing space', 'https://uaa.example/authorize?client_id=cid '],
    ['a trailing newline', 'https://uaa.example/authorize?client_id=cid\n'],
  ])(
    'a configured authorizationUrl with %s is refused at construction (never appended after it)',
    (_c, configured) => {
      let thrown: unknown;
      try {
        uaaProvider(recordingStrategy([]), configured);
      } catch (error) {
        thrown = error;
      }
      expect(configurationOf(thrown)).toMatchObject({
        case: 'invalid-value',
        fields: ['authorizationUrl'],
      });
    },
  );

  it('no minted state reaches a log line', async () => {
    const lines: string[] = [];
    const record = (message: string, meta?: unknown) => {
      lines.push(`${message} ${JSON.stringify(meta ?? null)}`);
    };
    const urls: string[] = [];
    await new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: tokenBase,
      clientId: 'cid',
      clientSecret: 'sec',
      authorization: recordingStrategy(urls),
      authorizationUrl: 'https://uaa.example/authorize?client_id=cid',
      logger: { debug: record, info: record, warn: record, error: record },
    }).getTokens();
    const state = stateOf(urls[0] as string) as string;
    expect(state).toMatch(BASE64URL_32);
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(line).not.toContain(state);
      expect(line).not.toContain('uaa.example');
    }
  });

  it('a static code is exchanged without a code_verifier', async () => {
    forms.length = 0;
    await uaaProvider(
      staticCodeStrategy({ payload: 'the-code', redirectUri: CALLBACK }),
    ).getTokens();
    expect(forms[0]).toEqual({
      grant_type: 'authorization_code',
      code: 'the-code',
      redirect_uri: CALLBACK,
    });
  });
});

describe('OidcBrowserProvider: state beside its PKCE', () => {
  const oidcProvider = (
    urls: string[],
    authorizationEndpoint = 'https://idp.example/authorize',
  ) =>
    new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      authorizationEndpoint,
      tokenEndpoint: `${tokenBase}/token`,
      authorization: {
        async authorize(request: AuthorizationRequest) {
          const url = await request.buildAuthorizationUrl(CALLBACK);
          urls.push(url);
          return {
            payload: { code: 'the-code', state: stateOf(url) ?? undefined },
            redirectUri: CALLBACK,
          };
        },
      },
    });

  it('carries a fresh state and verifier for every attempt', async () => {
    forms.length = 0;
    const urls: string[] = [];
    const provider = oidcProvider(urls);
    await provider.getTokens();
    await provider.refreshTokens();
    expect(stateOf(urls[0] as string)).toMatch(BASE64URL_32);
    expect(stateOf(urls[0] as string)).not.toBe(stateOf(urls[1] as string));
    expect(forms[0]?.code_verifier).not.toBe(forms[1]?.code_verifier);
    for (const [i, url] of urls.entries()) {
      expect(new URL(url).searchParams.get('code_challenge')).toBe(
        challengeOf(forms[i]?.code_verifier as string),
      );
    }
  });

  it('an endpoint with a query keeps its parameters and gets its own beside them', async () => {
    const urls: string[] = [];
    await oidcProvider(
      urls,
      'https://idp.example/tenant/authorize?p=b2c_1_signin',
    ).getTokens();
    const url = new URL(urls[0] as string);
    expect(`${url.origin}${url.pathname}`).toBe(
      'https://idp.example/tenant/authorize',
    );
    expect(url.searchParams.getAll('p')).toEqual(['b2c_1_signin']);
    expect(url.searchParams.getAll('response_type')).toEqual(['code']);
    expect(url.searchParams.getAll('client_id')).toEqual(['cid']);
    expect(url.searchParams.getAll('redirect_uri')).toEqual([CALLBACK]);
    expect(url.searchParams.getAll('state')).toEqual([
      expect.stringMatching(BASE64URL_32),
    ]);
    expect(url.searchParams.getAll('code_challenge_method')).toEqual(['S256']);
    expect((urls[0] as string).split('?')).toHaveLength(2);
  });

  it.each([
    ['a fragment', 'https://idp.example/authorize#x'],
    ['an empty fragment', 'https://idp.example/authorize?p=1#'],
    ['no URL at all', 'not a url'],
  ])(
    'an endpoint with %s is refused (RFC 6749 §3.1), nothing opened',
    async (_c, endpoint) => {
      const urls: string[] = [];
      const thrown = await oidcProvider(urls, endpoint)
        .getTokens()
        .catch((error: unknown) => error);
      expect(configurationOf(thrown)).toMatchObject({
        case: 'invalid-value',
        fields: ['authorizationEndpoint'],
      });
      expect(urls).toEqual([]);
    },
  );

  it('every URL it builds carries exactly one state (never one without)', async () => {
    const urls: string[] = [];
    await oidcProvider(urls).getTokens();
    expect(new URL(urls[0] as string).searchParams.getAll('state')).toEqual([
      expect.stringMatching(BASE64URL_32),
    ]);
  });
});

/**
 * The consumer's IBrowser: answers each forged request, then the real
 * callback, on the port `portOf()` names (the one bound, read by the test).
 */
function forgeThenAnswer(
  forged: string[],
  real: (state: string) => string,
  portOf: () => number,
): {
  browser: IBrowser;
  statuses: number[];
} {
  const statuses: number[] = [];
  return {
    statuses,
    browser: recordingBrowser({
      onOpen: async (url) => {
        const port = portOf();
        const state = stateOf(url) as string;
        void (async () => {
          for (const path of forged) {
            statuses.push(
              (await callbackGet(port, path.replace('$STATE', state))).status,
            );
          }
          await callbackGet(port, real(state));
        })();
      },
    }),
  };
}

describe.each([
  ['browserCallbackStrategy', browserCallbackStrategy, 'real'],
  [
    'oidcCallbackStrategy',
    oidcCallbackStrategy,
    expect.objectContaining({ code: 'real' }),
  ],
] as const)('%s on a real port', (_name, make, expected) => {
  it('refuses forged callbacks sent while the URL is built and after; the login completes', async () => {
    const { logger, ignored } = ignoreCounter();
    let bound = 0;
    const { browser, statuses } = forgeThenAnswer(
      [
        '/callback?code=forged',
        '/callback?code=forged&state=another',
        '/callback?error=access_denied&state=another',
      ],
      (state) => `/callback?code=real&state=${state}`,
      () => bound,
    );
    const strategy = (make as typeof browserCallbackStrategy)({
      port: 0,
      browser,
    });
    let entered!: (redirectUri: string) => void;
    const building = new Promise<string>((resolve) => {
      entered = resolve;
    });
    let release!: (url: string) => void;
    const login = strategy.authorize({
      logger,
      buildAuthorizationUrl: (redirectUri) => {
        entered(redirectUri);
        return new Promise<string>((resolve) => {
          release = resolve;
        });
      },
    });
    // The builder is blocked: the socket listens, the gate is closed.
    const port = Number(new URL(await building).port);
    bound = port;
    expect((await callbackGet(port, '/callback?code=early')).status).toBe(400);
    expect(
      (await callbackGet(port, '/callback?error=access_denied')).status,
    ).toBe(400);
    expect(ignored()).toBe(2);
    release(
      `https://idp.example/authorize?state=${'S'.repeat(43)}&response_type=code`,
    );
    const outcome = await login;
    expect(outcome.payload).toEqual(expected);
    expect(statuses).toEqual([400, 400, 400]);
    expect(ignored()).toBe(5);
  }, 30000);
});

describe('samlCallbackStrategy: armed like every composition, bound by InResponseTo', () => {
  it('logs in through the loopback listener on the real port; its URL carries no state', async () => {
    let bound = 0;
    const strategy = samlCallbackStrategy({
      port: 0,
      browser: recordingBrowser({
        onOpen: async () => {
          void callbackGet(bound, '/callback?SAMLResponse=assertion');
        },
      }),
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async (redirectUri) => {
        bound = Number(new URL(redirectUri).port);
        return 'https://idp.example/sso?SAMLRequest=x';
      },
    });
    expect(outcome.payload).toBe('assertion');
  }, 30000);
});

describe('manualPasteStrategy compares a pasted URL’s state', () => {
  const built = `https://idp.example/authorize?state=${'S'.repeat(43)}`;
  const pastedUrl = (state: string) =>
    `http://localhost:61001/callback?code=pasted&state=${state}`;

  it('asks again on a wrong or missing state, then takes the right one', async () => {
    const answers = [
      pastedUrl('wrong'),
      'http://localhost:61001/callback?code=pasted',
      pastedUrl('S'.repeat(43)),
    ];
    const read = jest.fn(async () => answers.shift() ?? '');
    const outcome = await manualPasteStrategy({
      redirectUri: CALLBACK,
      read,
    }).authorize({
      buildAuthorizationUrl: async () => built,
    });
    expect(read).toHaveBeenCalledTimes(3);
    expect(outcome.payload).toBe('pasted');
  });

  it('reads anything with ?, &, =, / or # as a URL: a code smuggled past the state is refused', async () => {
    const answers = [
      'http://localhost:61001/callback&code=EVIL',
      'junk&code=EVIL',
      'code=EVIL',
      'callback/EVIL',
      pastedUrl('S'.repeat(43)),
    ];
    const read = jest.fn(async () => answers.shift() ?? '');
    const outcome = await manualPasteStrategy({
      redirectUri: CALLBACK,
      read,
    }).authorize({
      buildAuthorizationUrl: async () => built,
    });
    expect(read).toHaveBeenCalledTimes(5);
    expect(outcome.payload).toBe('pasted');
  });

  it('takes the code from the query, never from a fragment', async () => {
    const thrown = await manualPasteStrategy({
      redirectUri: CALLBACK,
      read: async () =>
        `http://localhost:61001/callback?state=${'S'.repeat(43)}#&code=EVIL`,
    })
      .authorize({ buildAuthorizationUrl: async () => built })
      .catch((e: unknown) => e);
    expect(String((thrown as Error).message)).not.toContain('EVIL');
    expect(thrown).toBeInstanceOf(Error);
  });

  it('accepts a bare code: the user typed it', async () => {
    // Bounded: a strategy that refused the bare code would ask forever.
    let asked = 0;
    const read = jest.fn(async () => {
      asked += 1;
      if (asked > 3) throw new Error('asked again for a bare code');
      return 'bare-code';
    });
    const outcome = await manualPasteStrategy({
      redirectUri: CALLBACK,
      read,
    }).authorize({
      buildAuthorizationUrl: async () => built,
    });
    expect(read).toHaveBeenCalledTimes(1);
    expect(outcome.payload).toBe('bare-code');
  });

  it('refuses a URL without state before anything is read (a provider always puts one there)', async () => {
    const read = jest.fn(async () => pastedUrl('anything'));
    const thrown = await manualPasteStrategy({ redirectUri: CALLBACK, read })
      .authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/authorize',
      })
      .catch((e: unknown) => e);
    expect(configurationOf(thrown)).toMatchObject({
      case: 'invalid-value',
      fields: ['authorizationUrl'],
    });
    expect(read).not.toHaveBeenCalled();
  });
});

describe('the comparison is constant time (source)', () => {
  const read = (file: string) =>
    readFileSync(path.join(__dirname, '../..', file), 'utf8');

  it('secrets compares through timingSafeEqual over equal-length digests', () => {
    const source = read('authorization/secrets.ts');
    expect(source).toContain('timingSafeEqual(');
    expect(source).toContain("createHash('sha256')");
  });

  it.each([
    ['authorization/transport/httpListener.ts', 'sameSecret('],
    ['authorization/protocol/readPaste.ts', 'sameSecret('],
    ['authorization/protocol/codeProtocols.ts', 'sameSecret('],
  ])('%s compares the armed secret only through sameSecret', (file, call) => {
    const source = read(file);
    expect(source).toContain(call);
    // Our own source, not untrusted input: a regex is fine here.
    expect(source).not.toMatch(
      /(===|!==)\s*(gate\.)?(bound|formToken|expected)\b/,
    );
    expect(source).not.toMatch(
      // `typeof expected === 'string'` checks the type, not the secret.
      /(?<!typeof )\b(bound|formToken|expected)\s*(===|!==)(?!\s*(null|undefined)\b)/,
    );
    expect(source).not.toContain('timingSafeEqual');
  });
});
