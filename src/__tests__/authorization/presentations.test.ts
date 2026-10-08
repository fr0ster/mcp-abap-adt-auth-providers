/**
 * The presentations, through the composer on real
 * loopback ports: `showUrl` writes the authorization URL to stderr only and
 * gives the logger fixed words; `consumerPresentation` is the consumer's
 * UI, and its failure prints no URL anywhere — one fixed log line, its
 * optional `onFailure`, and the login keeps waiting. Nothing reaches
 * stdout; no line carries the URL, its `state`, a code or the IdP's text.
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
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import { composeAuthorization } from '../../authorization/compose';
import {
  consumerPresentation,
  openInBrowser,
  showUrl,
} from '../../authorization/presentation';
import { oauthCode, samlResponse } from '../../authorization/protocol';
import { loopback4 } from '../../authorization/transport';
import { deferred, quiet } from '../helpers/attemptHarness';
import {
  bindable,
  capturingLogger,
  formTokenIn,
  send,
} from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';
import { recordingBrowser } from '../helpers/recordingBrowser';

const STATE = 'presentation-state_abcdefghijklmnopqrstuvwxyz';
const urlFor = (redirectUri: string) =>
  `https://idp.example/oauth/authorize?client_id=c&redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;

const factsOf = (error: unknown) =>
  readFailure(error, 'browser-login').facts as Record<string, unknown>;

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

async function waitFor<T>(run: () => Promise<T>): Promise<T> {
  for (let i = 0; ; i += 1) {
    try {
      return await run();
    } catch (error) {
      if (i > 50) throw error;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

/** Whether `promise` is still pending after the listener had time to end it. */
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
  await new Promise((resolve) => setTimeout(resolve, 200));
  return !done;
}

describe('showUrl (C8)', () => {
  it('the URL to stderr only; the logger gets the fixed line, where it waits and the route hint', async () => {
    const port = await getAvailablePort();
    const { logger, lines, text } = capturingLogger();
    const login = composeAuthorization({
      presentation: showUrl(),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    }).authorize(request({ logger }));
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    const redirect = `http://127.0.0.1:${port}/callback`;
    expect(stderr.join('')).toContain(urlFor(redirect));
    expect(lines.map((line) => line.message)).toEqual([
      'the authorization URL was shown',
      `Waiting for callback on ${redirect} ...`,
      expect.stringContaining(`ssh -L ${port}:127.0.0.1:${port}`),
    ]);
    expect(text()).not.toContain('idp.example');
    expect(text()).not.toContain(STATE);
    expect((await send(port, `/callback?code=C1&state=${STATE}`)).status).toBe(
      200,
    );
    await expect(login).resolves.toMatchObject({ payload: 'C1' });
    expect(await bindable(port)).toBe(true);
  });

  it('without a logger everything goes to stderr, never stdout', async () => {
    const port = await getAvailablePort();
    const strategy = composeAuthorization({
      presentation: showUrl(),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = strategy.authorize(request());
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    const all = stderr.join('');
    expect(all).toContain(urlFor(`http://127.0.0.1:${port}/callback`));
    expect(all).toContain(
      `Waiting for callback on http://127.0.0.1:${port}/callback`,
    );
    await strategy.dispose();
    expect(factsOf(await login.catch((e: unknown) => e)).outcome).toBe(
      'disposed',
    );
  });

  it('a URL a prompt cannot show is named in fixed words, never shown', async () => {
    const port = await getAvailablePort();
    const { logger, text } = capturingLogger();
    const strategy = composeAuthorization({
      presentation: showUrl(),
      transport: loopback4({ port }),
      protocol: samlResponse(),
      endpoint: '/callback',
    });
    const login = strategy.authorize(
      request({
        logger,
        buildAuthorizationUrl: async () => 'javascript:evil()//idp.example',
      }),
    );
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    expect(stderr.join('')).not.toContain('evil');
    expect(text()).toContain('not an http(s) URL that can be shown');
    await strategy.dispose();
    await login.catch(() => undefined);
  });
});

describe('consumerPresentation', () => {
  it('show receives the URL, the redirect and a signal aborted once the login ends', async () => {
    const port = await getAvailablePort();
    const seen: Array<{
      url: string;
      redirectUri: unknown;
      signal: AbortSignal;
    }> = [];
    const login = composeAuthorization({
      presentation: consumerPresentation({
        show: async (url, context) => {
          seen.push({ url, ...context });
        },
      }),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    }).authorize(request());
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    const redirect = `http://127.0.0.1:${port}/callback`;
    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toBe(urlFor(redirect));
    expect(seen[0]?.redirectUri).toBe(redirect);
    expect(seen[0]?.signal.aborted).toBe(false);
    await send(port, `/callback?code=C1&state=${STATE}`);
    await login;
    expect(seen[0]?.signal.aborted).toBe(true);
    expect(stderr.join('')).not.toContain('idp.example');
  });

  describe.each([
    [
      'throws',
      () => {
        throw Object.assign(new Error(`show failed for ${STATE}`), {
          code: 'ENOENT',
        });
      },
    ],
    [
      'rejects',
      async () => {
        throw Object.assign(new Error(`show failed for ${STATE}`), {
          code: 'ENOENT',
        });
      },
    ],
  ] as const)('a show that %s', (_name, show) => {
    it('one fixed line, no URL anywhere, the login waiting; a callback then logs in', async () => {
      const port = await getAvailablePort();
      const { logger, lines, text } = capturingLogger();
      const login = composeAuthorization({
        presentation: consumerPresentation({ show }),
        transport: loopback4({ port }),
        protocol: oauthCode(),
        endpoint: '/callback',
      }).authorize(request({ logger }));
      expect(await stillWaiting(login)).toBe(true);
      expect(lines.map((line) => [line.level, line.message])).toEqual([
        [
          'error',
          'Failed to present the authorization URL: presenting the authorization URL failed (unknown error, ENOENT)',
        ],
      ]);
      for (const surface of [text(), stderr.join('')]) {
        expect(surface).not.toContain('idp.example');
        expect(surface).not.toContain(STATE);
        expect(surface).not.toContain('show failed');
      }
      expect(
        (await send(port, `/callback?code=C2&state=${STATE}`)).status,
      ).toBe(200);
      await expect(login).resolves.toMatchObject({ payload: 'C2' });
    });

    it('the signal then ends it aborted, the port free', async () => {
      const port = await getAvailablePort();
      const controller = new AbortController();
      const login = composeAuthorization({
        presentation: consumerPresentation({ show }),
        transport: loopback4({ port }),
        protocol: oauthCode(),
        endpoint: '/callback',
      }).authorize(request({ signal: controller.signal }));
      const rejected = login.catch((e: unknown) => e);
      expect(await stillWaiting(login)).toBe(true);
      controller.abort();
      expect(factsOf(await rejected)).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
      expect(await bindable(port)).toBe(true);
    });

    it('its onFailure runs once with the URL; an onFailure that throws is logged in fixed words', async () => {
      const port = await getAvailablePort();
      const { logger, lines, text } = capturingLogger();
      const fallbacks: string[] = [];
      const strategy = composeAuthorization({
        presentation: consumerPresentation({
          show,
          onFailure: (url) => {
            fallbacks.push(url);
            throw new Error(`fallback failed ${url}`);
          },
        }),
        transport: loopback4({ port }),
        protocol: oauthCode(),
        endpoint: '/callback',
      });
      const login = strategy.authorize(request({ logger }));
      expect(await stillWaiting(login)).toBe(true);
      expect(fallbacks).toEqual([urlFor(`http://127.0.0.1:${port}/callback`)]);
      expect(lines.map((line) => line.message)).toEqual([
        'The consumer’s fallback for the authorization URL failed: presenting the authorization URL failed (unknown error)',
        'Failed to present the authorization URL: presenting the authorization URL failed (unknown error, ENOENT)',
      ]);
      expect(text()).not.toContain(STATE);
      expect(stderr.join('')).not.toContain(STATE);
      await strategy.dispose();
      await login.catch(() => undefined);
    });
  });

  it('a show rejecting after the login ended prompts nothing and logs nothing', async () => {
    const port = await getAvailablePort();
    const { logger, lines } = capturingLogger();
    const late = deferred<void>();
    const fallbacks: string[] = [];
    const login = composeAuthorization({
      presentation: consumerPresentation({
        show: () => late.promise,
        onFailure: (url) => {
          fallbacks.push(url);
        },
      }),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    }).authorize(request({ logger }));
    await waitFor(() => send(port, `/callback?code=C3&state=${STATE}`));
    await login;
    late.reject(new Error('late'));
    await quiet();
    expect(lines).toEqual([]);
    expect(fallbacks).toEqual([]);
    expect(stderr.join('')).toBe('');
  });
});

describe('construction', () => {
  it.each([
    [
      'consumerPresentation without show',
      () => consumerPresentation({} as never),
      'required-fields-missing',
      ['show'],
    ],
    [
      'openInBrowser without browser',
      () => openInBrowser({} as never),
      'required-fields-missing',
      ['presentation'],
    ],
  ] as const)('%s → configuration %s', (_name, make, outcome, fields) => {
    let thrown: unknown;
    try {
      make();
    } catch (error) {
      thrown = error;
    }
    expect(factsOf(thrown)).toEqual({ case: outcome, fields });
  });

  it('openInBrowser({ browser }) is a presentation', () => {
    expect(typeof openInBrowser({ browser: recordingBrowser() }).present).toBe(
      'function',
    );
  });
});

describe('nothing of an answer or the URL reaches a log line', () => {
  it('a login with forged callbacks, a refused paste and the IdP’s text: no code, state, form token, pasted text, URL or IdP text', async () => {
    const port = await getAvailablePort();
    const { logger, text } = capturingLogger();
    const login = composeAuthorization({
      presentation: showUrl(),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    }).authorize(request({ logger }));
    const rejected = login.catch((e: unknown) => e);
    await waitFor(() => send(port, '/callback?code=FORGED-CODE&state=wrong'));
    const page = await send(port, '/');
    const token = formTokenIn(page.body) ?? '';
    await send(port, '/submit', {
      form: { form_token: token, input: 'http://x/cb?code=PASTED&state=other' },
    });
    await send(
      port,
      `/callback?error=access_denied&error_description=IDP-TEXT&state=${STATE}`,
    );
    expect(factsOf(await rejected).outcome).toBe('identity-provider-refused');
    const logged = text();
    for (const secret of [
      'FORGED-CODE',
      STATE,
      token,
      'PASTED',
      'IDP-TEXT',
      'idp.example',
    ]) {
      expect(logged).not.toContain(secret);
    }
  });
});
