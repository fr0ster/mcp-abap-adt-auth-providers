/**
 * Appendix A.3 (K1–K17) and A2, A8, A9 of the error-contract spec: every
 * end of an interactive login is an `AuthProviderFailure` of
 * `interactive-login`, thrown by its real producer here — kind, facts and
 * words (verbatim) per row. K6 is Task 26's; K7 and K9 are gone with the
 * built-in timeout (§6a) — their type tests are in
 * noLoginTimeout.typecheck.ts.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  CallbackServerFactory,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { withBrowserCallbackServer } from '../../auth/callbackServer';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import {
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  externalCodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  oidcCallbackStrategy,
} from '../../strategies';
import { readFromTerminal } from '../../strategies/manualStrategies';
import { startTokenServer, type TokenServer } from '../helpers/attemptHarness';

const PORT = 7877;

/** The row a thrown value is: its kind, facts and words. */
function rowOf(thrown: unknown) {
  expect(isAuthProviderFailure(thrown)).toBe(true);
  const error = readFailure(thrown, 'browser-login');
  return {
    kind: error.kind,
    facts: error.facts,
    reason: error.reason,
    hint: error.hint,
  };
}

const rejection = (promise: Promise<unknown>): Promise<unknown> =>
  promise.then(
    () => {
      throw new Error('expected a rejection');
    },
    (error: unknown) => error,
  );

const request = (
  build: AuthorizationRequest['buildAuthorizationUrl'] = async () =>
    'https://idp.example/authorize',
): AuthorizationRequest => ({ buildAuthorizationUrl: build });

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

/** Opens the redirect with `query`, as a browser would. */
const visit =
  (query: string) =>
  async (_url: string, _browser: string, redirectUri: string) => {
    await new Promise<void>((resolve) => {
      const req = http.get(
        {
          host: '127.0.0.1',
          port: new URL(redirectUri).port,
          agent: false,
          path: `/callback?${query}`,
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve());
        },
      );
      req.on('error', () => resolve());
    });
  };

afterEach(async () => {
  expect(await portIsFree(PORT)).toBe(true);
});

describe('A.3 — browser login rows', () => {
  it('K1: a held port → port-in-use, "already in use" kept verbatim', async () => {
    const squatter = net.createServer();
    await new Promise<void>((resolve) => squatter.listen(PORT, resolve));
    try {
      const thrown = await rejection(
        browserCallbackStrategy({ port: PORT }).authorize(request()),
      );
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'port-in-use', port: PORT },
        reason: `Port ${PORT} is already in use. Please specify a different port or free the port.`,
        hint: undefined,
      });
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });

  it('K2: a disposed strategy → disposed, strategy browser', async () => {
    const strategy = browserCallbackStrategy({ port: PORT });
    await strategy.dispose?.();
    expect(rowOf(await rejection(strategy.authorize(request())))).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'disposed', strategy: 'browser' },
      reason: 'BrowserCallbackStrategy has been disposed',
      hint: undefined,
    });
  });

  it('K3: an overlapping authorize → busy', async () => {
    const consumer = new AbortController();
    const strategy = browserCallbackStrategy({
      port: PORT,
      signal: consumer.signal,
      openUrl: async () => undefined,
    });
    const first = rejection(strategy.authorize(request()));
    expect(rowOf(await rejection(strategy.authorize(request())))).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'busy' },
      reason:
        'BrowserCallbackStrategy is already authorizing; it holds a single port',
      hint: undefined,
    });
    consumer.abort();
    await first;
  });

  describe('K4: aborted, strategy browser — each of the three moments', () => {
    const aborted = {
      kind: 'interactive-login',
      facts: { outcome: 'aborted', strategy: 'browser' },
      reason: 'the browser login was aborted',
      hint: undefined,
    };

    it('before the bind (a signal already aborted)', async () => {
      const thrown = await rejection(
        browserCallbackStrategy({
          port: PORT,
          signal: AbortSignal.abort(),
        }).authorize(request()),
      );
      expect(rowOf(thrown)).toEqual(aborted);
    });

    it('the callback server given an aborted signal never binds', async () => {
      let ran = false;
      const thrown = await rejection(
        withBrowserCallbackServer(
          { port: PORT, signal: AbortSignal.abort() },
          async () => {
            ran = true;
            return 'unreachable';
          },
        ),
      );
      expect(rowOf(thrown)).toEqual(aborted);
      expect(ran).toBe(false);
    });

    it('while waiting, with the ignored-callback tally', async () => {
      const consumer = new AbortController();
      const thrown = await rejection(
        browserCallbackStrategy({
          port: PORT,
          signal: consumer.signal,
          openUrl: async (url, browser, redirectUri) => {
            await visit('')(url, browser, redirectUri);
            await visit('state=only')(url, browser, redirectUri);
            consumer.abort();
          },
        }).authorize(request()),
      );
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'aborted', strategy: 'browser', ignoredCallbacks: 2 },
        reason:
          'the browser login was aborted; 2 incomplete request(s) reached /callback and were ignored',
        hint: undefined,
      });
    });

    it('a request signal (the attempt) aborts it the same way', async () => {
      const attempt = new AbortController();
      const thrown = await rejection(
        browserCallbackStrategy({
          port: PORT,
          openUrl: async () => {
            attempt.abort();
          },
        }).authorize({ ...request(), signal: attempt.signal } as never),
      );
      expect(rowOf(thrown)).toEqual(aborted);
    });
  });

  it('K5: a launcher that fails → browser-launch-failed, its allowlisted code only', async () => {
    const lines: unknown[][] = [];
    const prompts: unknown[][] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: (...args: unknown[]) => {
        prompts.push(args);
      },
      warn: () => undefined,
      error: (...args: unknown[]) => {
        lines.push(args);
      },
    };
    const thrown = await rejection(
      browserCallbackStrategy({
        port: PORT,
        openUrl: async () => {
          throw Object.assign(new Error('spawn SECRET-PATH'), {
            code: 'ENOENT',
          });
        },
      }).authorize({ ...request(), logger }),
    );
    expect(rowOf(thrown)).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'browser-launch-failed', code: 'ENOENT' },
      reason: 'the browser could not be opened (ENOENT)',
      hint: 'open the authorization URL from the log by hand',
    });
    // H7: the URL is in neither the failure nor the error line.
    expect((thrown as Error).message).not.toContain('idp.example');
    const [line] = lines;
    expect(String(line?.[0])).toBe(
      'Failed to open browser: opening the browser failed (unknown error, ENOENT)',
    );
    expect(JSON.stringify(lines)).not.toContain('idp.example');
    expect(JSON.stringify(prompts)).not.toContain('idp.example');
    expect(JSON.stringify(lines)).not.toContain('SECRET-PATH');
  });

  it('K8: waiting after the scope ended → callback-closed', async () => {
    const ended = await withBrowserCallbackServer(
      { port: PORT },
      async (srv) => srv,
    );
    expect(rowOf(await rejection(ended.waitForResult()))).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'callback-closed' },
      reason: 'the callback server closed before a result arrived',
      hint: undefined,
    });
  });

  it('K8: a pending wait when the body returns → callback-closed', async () => {
    let dangling: Promise<string> | undefined;
    await withBrowserCallbackServer({ port: PORT }, async (srv) => {
      dangling = srv.waitForResult();
      return 'returned without awaiting';
    });
    expect(rowOf(await rejection(dangling as Promise<string>)).facts).toEqual({
      outcome: 'callback-closed',
    });
  });

  it.each([
    ['UAA', browserCallbackStrategy],
    ['OIDC', oidcCallbackStrategy],
  ] as const)(
    'K10 / A8 (%s): the IdP refuses with a registered code → identity-provider-refused',
    async (_name, make) => {
      const DESCRIPTION = 'REVIEW_TEST_IDP_TEXT_7a31';
      const strategy = (make as typeof browserCallbackStrategy)({
        port: PORT,
        openUrl: visit(
          `error=access_denied&error_description=${DESCRIPTION}&error_uri=https%3A%2F%2F${DESCRIPTION}`,
        ),
      });
      const thrown = await rejection(strategy.authorize(request()));
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: {
          outcome: 'identity-provider-refused',
          oauthError: 'access_denied',
        },
        reason: 'the identity provider refused the login (access_denied)',
        hint: 'check the identity provider: the user, the client and the scopes it allows',
      });
      expect(JSON.stringify(thrown)).not.toContain(DESCRIPTION);
      expect((thrown as Error).message).not.toContain(DESCRIPTION);
    },
  );

  it('K10: an unregistered code → no oauthError, its own words', async () => {
    const thrown = await rejection(
      browserCallbackStrategy({
        port: PORT,
        openUrl: visit('error=REVIEW_TEST_NOT_A_CODE'),
      }).authorize(request()),
    );
    expect(rowOf(thrown)).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'identity-provider-refused' },
      reason:
        'the identity provider refused the login (an unregistered error code)',
      hint: 'check the identity provider: the user, the client and the scopes it allows',
    });
    expect((thrown as Error).message).not.toContain('REVIEW_TEST_NOT_A_CODE');
  });

  describe('K11 / A9: anything else → failed', () => {
    const throwing =
      (value: unknown): CallbackServerFactory<string> =>
      async () => {
        throw value;
      };

    it('with a status and a registered error, verbatim, and A9’s new hint', async () => {
      const thrown = await rejection(
        new BrowserCallbackStrategy<string>({
          callbackServer: throwing(
            Object.assign(new Error('REVIEW_TEST_SERVER_TEXT'), {
              response: {
                status: 400,
                data: { error: 'invalid_grant', error_description: 'x' },
              },
            }),
          ),
        }).authorize(request()),
      );
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'failed', status: 400, oauthError: 'invalid_grant' },
        reason: 'the browser login failed (HTTP 400, invalid_grant)',
        hint: 'complete the login, or abort it',
      });
      expect((thrown as Error).message).not.toContain(
        'REVIEW_TEST_SERVER_TEXT',
      );
    });

    it('with nothing safe to name → unknown error', async () => {
      const thrown = await rejection(
        new BrowserCallbackStrategy<string>({
          callbackServer: throwing(new Error('REVIEW_TEST_SERVER_TEXT')),
        }).authorize(request()),
      );
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'failed' },
        reason: 'the browser login failed (unknown error)',
        hint: 'complete the login, or abort it',
      });
    });
  });
});

describe('A.3 — manual and code strategy rows', () => {
  it('K12: the terminal reader given an aborted signal → input-abandoned', async () => {
    expect(
      rowOf(await rejection(readFromTerminal('p', AbortSignal.abort()))),
    ).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'input-abandoned' },
      reason: 'the manual input was abandoned before it began',
      hint: undefined,
    });
  });

  it('K13: no terminal → no-terminal', async () => {
    const tty = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', {
      value: false,
      configurable: true,
    });
    try {
      const write = jest
        .spyOn(process.stderr, 'write')
        .mockImplementation(() => true);
      const thrown = await rejection(
        manualPasteStrategy().authorize(request()),
      ).finally(() => write.mockRestore());
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'no-terminal' },
        reason:
          'Manual input needs an interactive terminal. Supply `read` to source the value elsewhere.',
        hint: undefined,
      });
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', {
        value: tty,
        configurable: true,
      });
    }
  });

  it.each([
    [
      'manualSamlResponseStrategy',
      () => manualSamlResponseStrategy({ read: async () => '  ' }),
    ],
    [
      'externalCodeStrategy',
      () => externalCodeStrategy({ provide: async () => '' }),
    ],
  ])('K14 (%s): an empty value → no-input', async (_name, make) => {
    const write = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    try {
      expect(rowOf(await rejection(make().authorize(request())))).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'no-input' },
        reason: 'no input was received',
        hint: undefined,
      });
    } finally {
      write.mockRestore();
    }
  });

  it('K15: a disposed manual strategy → disposed, strategy manual', async () => {
    const strategy = manualPasteStrategy({ read: async () => 'code' });
    await strategy.dispose?.();
    expect(rowOf(await rejection(strategy.authorize(request())))).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'disposed', strategy: 'manual' },
      reason: 'the manual strategy was disposed',
      hint: undefined,
    });
  });

  it('K4 (manual): aborted → strategy manual, no tally', async () => {
    const consumer = new AbortController();
    const strategy = manualPasteStrategy({
      signal: consumer.signal,
      read: (_prompt, signal) =>
        new Promise<string>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('x')));
        }),
    });
    const write = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    try {
      const pending = rejection(strategy.authorize(request()));
      await new Promise((resolve) => setImmediate(resolve));
      consumer.abort();
      expect(rowOf(await pending)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'aborted', strategy: 'manual' },
        reason: 'the manual login was aborted',
        hint: undefined,
      });
    } finally {
      write.mockRestore();
    }
  });

  it('K4 (external code): aborted with no strategy → the authorization was aborted', async () => {
    const consumer = new AbortController();
    const strategy = externalCodeStrategy({
      signal: consumer.signal,
      provide: () => new Promise<string>(() => undefined),
    });
    const pending = rejection(strategy.authorize(request()));
    await new Promise((resolve) => setImmediate(resolve));
    consumer.abort();
    expect(rowOf(await pending)).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'aborted' },
      reason: 'the authorization was aborted',
      hint: undefined,
    });
  });

  it('K16: a paste with a malformed escape → unreadable-input, no URIError', async () => {
    const write = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    try {
      for (const pasted of ['code=%ZZ', 'https://x/cb?code=%E0%A4%A&state=s']) {
        const thrown = await rejection(
          manualPasteStrategy({ read: async () => pasted }).authorize(
            request(),
          ),
        );
        expect(rowOf(thrown).facts).toEqual({ outcome: 'unreadable-input' });
      }
    } finally {
      write.mockRestore();
    }
  });

  it('K16: an unreadable paste → unreadable-input', async () => {
    const write = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    try {
      const thrown = await rejection(
        manualPasteStrategy({ read: async () => 'no code here' }).authorize(
          request(),
        ),
      );
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'unreadable-input' },
        reason: 'Could not read an authorization code from that input',
        hint: undefined,
      });
    } finally {
      write.mockRestore();
    }
  });
});

describe('A.3 — the device code', () => {
  let server: TokenServer | undefined;
  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  it('K17 / A2: a presenter that throws → device-code-not-shown; H3 logs logFields only', async () => {
    server = await startTokenServer((held) =>
      held.answer(200, {
        device_code: 'dc',
        user_code: 'UC',
        verification_uri: 'https://idp.example/activate',
        interval: 0,
      }),
    );
    const warnings: unknown[][] = [];
    const provider = new OidcDeviceFlowProvider({
      clientId: 'cid',
      tokenEndpoint: `${server.url}/token`,
      deviceAuthorizationEndpoint: `${server.url}/device`,
      logger: {
        debug: () => undefined,
        info: () => undefined,
        warn: (...args: unknown[]) => {
          warnings.push(args);
        },
        error: () => undefined,
      },
      presenter: {
        present: async () => {
          throw new Error('REVIEW_TEST_PRESENTER_UC');
        },
      },
    });
    const thrown = await rejection(provider.getTokens());
    expect(rowOf(thrown)).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'device-code-not-shown' },
      reason: 'showing the device code failed',
      hint: undefined,
    });
    const line = warnings.find((w) =>
      String(w[0]).includes('presenter failed'),
    );
    expect(line?.[1]).toMatchObject({ kind: 'unknown' });
    expect(JSON.stringify(warnings)).not.toContain('REVIEW_TEST_PRESENTER_UC');
  });
});
