/**
 * `openInBrowser({ browser })` (spec §6d.2, §6d.5, C8): `browser` is an
 * `IBrowser` — a shipped one or the consumer's — used as given: `open` is
 * called on it with exactly the URL and the login's signal. A browser that
 * rejects or throws is a presentation failure: the URL is prompted once, to
 * stderr only; the composer writes one line in fixed words; the login keeps
 * waiting on the same port and a callback then finishes it. No browser
 * opens: every `IBrowser` here is the test's — `recordingBrowser()`, or a
 * consumer-shaped one where the contract itself is under test (`this`, a
 * synchronous throw, a getter).
 *
 * No browser is named by a string: a string (or anything without an `open`
 * function) is refused at construction, and `browser: 'chrome'` does not
 * compile (`compositions.typecheck.ts`).
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  IBrowser,
} from '@mcp-abap-adt/interfaces-auth';
import { composeAuthorization } from '../../authorization/compose';
import { openInBrowser } from '../../authorization/presentation';
import { oauthCode } from '../../authorization/protocol';
import { loopback4 } from '../../authorization/transport';
import { bindable, capturingLogger, send } from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';
import { recordingBrowser } from '../helpers/recordingBrowser';

const STATE = 'browser-state_abcdefghijklmnopqrstuvwxyz0123';
const urlFor = (redirectUri: string) =>
  `https://idp.example/oauth/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;

let stderr: string[];
let stdout: string[];
beforeEach(() => {
  stderr = [];
  stdout = [];
  jest.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    stderr.push(String(chunk));
    return true;
  });
  jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    stdout.push(String(chunk));
    return true;
  });
});
afterEach(() => {
  jest.restoreAllMocks();
  expect(stdout).toEqual([]);
});

const request = (
  overrides: Partial<AuthorizationRequest> = {},
): AuthorizationRequest => ({
  buildAuthorizationUrl: async (redirectUri) => urlFor(redirectUri),
  ...overrides,
});

async function stillWaiting(promise: Promise<unknown>): Promise<boolean> {
  let done = false;
  promise.then(
    () => {
      done = true;
    },
    () => {
      done = true;
    },
  );
  await new Promise((resolve) => setTimeout(resolve, 300));
  return !done;
}

const occurrences = (text: string, part: string) => text.split(part).length - 1;

const factsOf = (error: unknown) =>
  readFailure(error, 'browser-login').facts as Record<string, unknown>;

function thrownBy(make: () => unknown): unknown {
  try {
    make();
  } catch (error) {
    return error;
  }
  return undefined;
}

const failing = () =>
  recordingBrowser({
    rejectWith: Object.assign(new Error(`spawn SECRET-PATH ${STATE}`), {
      code: 'ENOENT',
    }),
  });

describe('a consumer IBrowser is used as given', () => {
  it('open is called on it, once, with exactly the URL and the login’s signal; nothing printed', async () => {
    const port = await getAvailablePort();
    const calls: { self: unknown; url: string; signal: AbortSignal }[] = [];
    class MyBrowser implements IBrowser {
      async open(url: string, signal: AbortSignal): Promise<void> {
        calls.push({ self: this, url, signal });
      }
    }
    const browser = new MyBrowser();
    // A URL the shipped launchers would re-serialise: the consumer gets it as is.
    const raw = (redirectUri: string) =>
      `https://IDP.example/a b?redirect_uri=${redirectUri}&state=${STATE}`;
    const login = composeAuthorization({
      presentation: openInBrowser({ browser }),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    }).authorize(
      request({ buildAuthorizationUrl: async (redirect) => raw(redirect) }),
    );
    expect(await stillWaiting(login)).toBe(true);
    const redirect = `http://127.0.0.1:${port}/callback`;
    expect(calls).toHaveLength(1);
    expect(calls[0]?.self).toBe(browser);
    expect(calls[0]?.url).toBe(raw(redirect));
    expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);
    expect(calls[0]?.signal.aborted).toBe(false);
    expect(stderr.join('')).toBe('');
    await send(port, `/callback?code=C1&state=${STATE}`);
    await expect(login).resolves.toMatchObject({ payload: 'C1' });
    // The signal tells the browser the login has ended.
    expect(calls[0]?.signal.aborted).toBe(true);
  });
});

describe('a browser that fails is a presentation failure (§6d.5)', () => {
  it.each([
    ['rejects', failing()],
    [
      'throws synchronously',
      {
        open: () => {
          throw Object.assign(new Error(`SECRET-PATH ${STATE}`), {
            code: 'ENOENT',
          });
        },
      } as IBrowser,
    ],
  ] as const)(
    'a browser that %s: the URL prompted once on stderr, one failure line, the login waiting; a callback finishes it',
    async (_name, browser) => {
      const port = await getAvailablePort();
      const { logger, lines, text } = capturingLogger();
      const login = composeAuthorization({
        presentation: openInBrowser({ browser }),
        transport: loopback4({ port }),
        protocol: oauthCode(),
        endpoint: '/callback',
      }).authorize(request({ logger }));
      expect(await stillWaiting(login)).toBe(true);
      const redirect = `http://127.0.0.1:${port}/callback`;
      expect(occurrences(stderr.join(''), urlFor(redirect))).toBe(1);
      const failures = lines.filter(
        (line) => line.level === 'error' || line.level === 'warn',
      );
      expect(failures.map((line) => [line.level, line.message])).toEqual([
        [
          'error',
          'Failed to present the authorization URL: presenting the authorization URL failed (unknown error, ENOENT)',
        ],
      ]);
      expect(lines.map((line) => line.message)).toContain(
        'the authorization URL was shown',
      );
      expect(text()).not.toContain('idp.example');
      expect(text()).not.toContain(STATE);
      expect(text()).not.toContain('SECRET-PATH');
      expect(stderr.join('')).not.toContain('SECRET-PATH');
      expect(
        (await send(port, `/callback?code=C3&state=${STATE}`)).status,
      ).toBe(200);
      await expect(login).resolves.toMatchObject({ payload: 'C3' });
      expect(await bindable(port)).toBe(true);
    },
  );

  it('the signal then ends it aborted and the port is free; the IdP’s ?error= ends it refused', async () => {
    const port = await getAvailablePort();
    const controller = new AbortController();
    const strategy = composeAuthorization({
      presentation: openInBrowser({ browser: failing() }),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const first = strategy
      .authorize(request({ signal: controller.signal }))
      .catch((e: unknown) => e);
    expect(await stillWaiting(first)).toBe(true);
    controller.abort();
    expect(factsOf(await first)).toEqual({
      outcome: 'aborted',
      strategy: 'browser',
    });
    expect(await bindable(port)).toBe(true);

    const second = strategy.authorize(request()).catch((e: unknown) => e);
    expect(await stillWaiting(second)).toBe(true);
    await send(port, `/callback?error=access_denied&state=${STATE}`);
    expect(factsOf(await second)).toEqual({
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
  });

  it('a browser that fails after the login ended prompts nothing', async () => {
    const port = await getAvailablePort();
    let rejectOpen!: (error: Error) => void;
    const browser = recordingBrowser({
      onOpen: () =>
        new Promise<void>((_resolve, reject) => {
          rejectOpen = reject;
        }),
    });
    const { logger, lines } = capturingLogger();
    const login = composeAuthorization({
      presentation: openInBrowser({ browser }),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    }).authorize(request({ logger }));
    expect(await stillWaiting(login)).toBe(true);
    await send(port, `/callback?code=C4&state=${STATE}`);
    await login;
    rejectOpen(Object.assign(new Error('late'), { code: 'ENOENT' }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(stderr.join('')).not.toContain('idp.example');
    expect(
      lines.filter((line) => line.level === 'error' || line.level === 'warn'),
    ).toEqual([]);
  });
});

describe('construction: no browser by name', () => {
  it('without browser → configuration required-fields-missing (presentation)', () => {
    expect(factsOf(thrownBy(() => openInBrowser({} as never)))).toEqual({
      case: 'required-fields-missing',
      fields: ['presentation'],
    });
  });

  it.each([
    ['chrome'],
    ['system'],
    ['auto'],
    ['none'],
    [42],
    [null],
    [{}],
    [{ open: 'chrome' }],
    [() => undefined],
  ])(
    'browser %j is no IBrowser → configuration invalid-value (presentation)',
    (browser) => {
      expect(
        factsOf(thrownBy(() => openInBrowser({ browser } as never))),
      ).toEqual({ case: 'invalid-value', fields: ['presentation'] });
    },
  );

  it('an object whose open is a getter is read once, at construction, guarded', () => {
    let reads = 0;
    const browser = {
      get open() {
        reads += 1;
        return async () => undefined;
      },
    };
    expect(typeof openInBrowser({ browser }).present).toBe('function');
    expect(reads).toBe(1);
    const throwing = {
      get open(): never {
        throw new Error('SECRET');
      },
    };
    expect(
      factsOf(thrownBy(() => openInBrowser({ browser: throwing } as never))),
    ).toEqual({ case: 'invalid-value', fields: ['presentation'] });
  });
});
