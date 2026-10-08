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
  AnswerTransportOptions,
  AuthorizationRequest,
  IAnswerChannel,
  IAnswerTransport,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { composeAuthorization } from '../../authorization/compose';
import { oauthCode } from '../../authorization/protocol';
import { loopback4 } from '../../authorization/transport';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { refreshThenLogin } from '../../renewal';
import {
  browserCallbackStrategy,
  externalCodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from '../../strategies';
import { readFromTerminal } from '../../strategies/manualStrategies';
import { startTokenServer, type TokenServer } from '../helpers/attemptHarness';

const PORT = 7877;
/** The state every URL here carries: the code protocols bind by it (C7). */
const STATE = 'S1';
const REGISTERED = 'http://localhost:61001/callback';

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
    `https://idp.example/authorize?state=${STATE}`,
): AuthorizationRequest => ({ buildAuthorizationUrl: build });

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

/**
 * Runs a login whose launcher fails: it keeps waiting (Task 30h), so the
 * test's own signal ends it, once the prompt has been shown.
 */
async function endedByAbort(
  start: (signal: AbortSignal) => Promise<unknown>,
): Promise<unknown> {
  const controller = new AbortController();
  const ended = rejection(start(controller.signal));
  await new Promise((resolve) => setTimeout(resolve, 100));
  controller.abort();
  return await ended;
}

/**
 * Opens the redirect with `query`, as a browser would — with this login's
 * `state` unless `bound` is false.
 */
const visit =
  (query: string, bound = true) =>
  async (_url: string, _browser: string, redirectUri: string) => {
    await new Promise<void>((resolve) => {
      const req = http.get(
        {
          host: '127.0.0.1',
          port: new URL(redirectUri).port,
          agent: false,
          path: `/callback?${query}${bound ? `&state=${STATE}` : ''}`,
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

    it('the listener given an aborted signal never binds', async () => {
      let ran = false;
      const thrown = await rejection(
        loopback4({ port: PORT }).open(
          {
            signal: AbortSignal.abort(),
            callbackMethods: ['GET'],
            endpoint: '/callback',
          },
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
            await visit('', false)(url, browser, redirectUri);
            await visit('state=only', false)(url, browser, redirectUri);
            consumer.abort();
          },
        }).authorize(request()),
      );
      expect(rowOf(thrown)).toEqual({
        kind: 'interactive-login',
        facts: { outcome: 'aborted', strategy: 'browser', ignoredCallbacks: 2 },
        reason:
          'the browser login was aborted; 2 request(s) to the callback server were refused and ignored',
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

  // Task 30h, generalised (spec §6d.5, C8): a presentation that fails is no
  // end of the login — one fixed-words line, and the consumer's own UI
  // having failed, no URL anywhere; the login waits — here the test's own
  // signal ends it.
  it('K5: an openUrl that fails → one fixed-words line, no URL anywhere, the login still waiting', async () => {
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
    const err: string[] = [];
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        err.push(String(chunk));
        return true;
      });
    let thrown: unknown;
    try {
      thrown = await endedByAbort((signal) =>
        browserCallbackStrategy({
          port: PORT,
          openUrl: async () => {
            throw Object.assign(new Error('spawn SECRET-PATH'), {
              code: 'ENOENT',
            });
          },
        }).authorize({ ...request(), logger, signal } as AuthorizationRequest),
      );
    } finally {
      stderr.mockRestore();
    }
    // Not the presentation's failure: the signal ended it.
    expect(readFailure(thrown, 'browser-login').facts).toEqual({
      outcome: 'aborted',
      strategy: 'browser',
    });
    expect((thrown as Error).message).not.toContain('idp.example');
    expect(lines.map((line) => line[0])).toEqual([
      'Failed to present the authorization URL: presenting the authorization URL failed (unknown error, ENOENT)',
    ]);
    for (const surface of [
      JSON.stringify(lines),
      JSON.stringify(prompts),
      err.join(''),
    ]) {
      expect(surface).not.toContain('idp.example');
      expect(surface).not.toContain('SECRET-PATH');
    }
  });

  it('K5 without a logger, showing the URL: stderr only, nothing on stdout', async () => {
    const err: string[] = [];
    const out: string[] = [];
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        err.push(String(chunk));
        return true;
      });
    const stdout = jest
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk: unknown) => {
        out.push(String(chunk));
        return true;
      });
    try {
      await endedByAbort((signal) =>
        browserCallbackStrategy({ port: PORT }).authorize({
          ...request(
            async (uri) =>
              `https://idp.example/authorize?r=${uri}&state=${STATE}`,
          ),
          signal,
        } as AuthorizationRequest),
      );
    } finally {
      stderr.mockRestore();
      stdout.mockRestore();
    }
    expect(err.slice(0, 3)).toEqual([
      '🔗 Open this URL in your browser to authenticate:\n',
      `   https://idp.example/authorize?r=http://localhost:${PORT}/callback&state=${STATE}\n`,
      `Waiting for callback on http://localhost:${PORT}/callback ...\n`,
    ]);
    expect(out).toEqual([]);
  });

  it('K5: a URL that is not promptable is named in fixed words, never shown', async () => {
    const prompts: unknown[][] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: (...args: unknown[]) => {
        prompts.push(args);
      },
      warn: () => undefined,
      error: () => undefined,
    };
    const err: string[] = [];
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        err.push(String(chunk));
        return true;
      });
    try {
      // SAML: its URL carries no state to bind by.
      await endedByAbort((signal) =>
        samlCallbackStrategy({ port: PORT }).authorize({
          ...request(async () => 'javascript:alert(1)//SECRET'),
          logger,
          signal,
        } as AuthorizationRequest),
      );
    } finally {
      stderr.mockRestore();
    }
    expect(prompts.slice(0, 2)).toEqual([
      ['The authorization URL is not an http(s) URL that can be shown.'],
      [`Waiting for callback on http://localhost:${PORT}/callback ...`],
    ]);
    expect(`${JSON.stringify(prompts)}${err.join('')}`).not.toContain('SECRET');
  });

  const listenerOptions: AnswerTransportOptions = {
    signal: new AbortController().signal,
    callbackMethods: ['GET'],
    endpoint: '/callback',
  };

  it('K8: a channel armed after its open ended → callback-closed', async () => {
    const ended = await loopback4({ port: PORT }).open(
      listenerOptions,
      async (channel: IAnswerChannel) => channel,
    );
    const armed = ended.arm(() => ({
      verdict: 'refuse',
      reason: 'no-payload',
    }));
    expect(rowOf(await rejection(armed.answer()))).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'callback-closed' },
      reason: 'the callback server closed before a result arrived',
      hint: undefined,
    });
  });

  it('K8: a pending wait when use returns → callback-closed', async () => {
    let dangling: Promise<void> | undefined;
    await loopback4({ port: PORT }).open(listenerOptions, async (channel) => {
      dangling = channel
        .arm(() => ({ verdict: 'refuse', reason: 'no-payload' }))
        .answer();
      return 'returned without awaiting';
    });
    expect(rowOf(await rejection(dangling as Promise<void>)).facts).toEqual({
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
    /** A composition whose transport's open throws `value`. */
    const throwing = (value: unknown) =>
      composeAuthorization({
        presentation: { present: () => undefined },
        transport: {
          label: 'browser',
          open: async () => {
            throw value;
          },
        } as IAnswerTransport,
        protocol: oauthCode(),
        endpoint: '/callback',
      });

    it('with a status and a registered error, verbatim, and A9’s new hint', async () => {
      const thrown = await rejection(
        throwing(
          Object.assign(new Error('REVIEW_TEST_SERVER_TEXT'), {
            response: {
              status: 400,
              data: { error: 'invalid_grant', error_description: 'x' },
            },
          }),
        ).authorize(request()),
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
        throwing(new Error('REVIEW_TEST_SERVER_TEXT')).authorize(request()),
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
        manualPasteStrategy({ redirectUri: REGISTERED }).authorize(request()),
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
      () =>
        manualSamlResponseStrategy({
          redirectUri: REGISTERED,
          read: async () => '  ',
        }),
    ],
    [
      'externalCodeStrategy',
      () =>
        externalCodeStrategy({
          redirectUri: REGISTERED,
          provide: async () => '',
        }),
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
    const strategy = manualPasteStrategy({
      redirectUri: REGISTERED,
      read: async () => 'code',
    });
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
      redirectUri: REGISTERED,
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

  it('K4 (external code): aborted → strategy consumer, the login was aborted', async () => {
    const consumer = new AbortController();
    const strategy = externalCodeStrategy({
      redirectUri: REGISTERED,
      signal: consumer.signal,
      provide: () => new Promise<string>(() => undefined),
    });
    const pending = rejection(strategy.authorize(request()));
    await new Promise((resolve) => setImmediate(resolve));
    consumer.abort();
    expect(rowOf(await pending)).toEqual({
      kind: 'interactive-login',
      facts: { outcome: 'aborted', strategy: 'consumer' },
      reason: 'the login was aborted',
      hint: undefined,
    });
  });

  it('K16 is not a malformed escape: a pasted URL of this login takes its code as the parser reads it, no URIError', async () => {
    const write = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    try {
      const outcome = await manualPasteStrategy({
        redirectUri: REGISTERED,
        read: async () => `https://x/cb?code=%ZZ&state=${STATE}`,
      }).authorize(request());
      expect(outcome.payload).toBe('%ZZ');
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
        manualPasteStrategy({
          redirectUri: REGISTERED,
          read: async () => 'no code here',
        }).authorize(request()),
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
      renewal: refreshThenLogin(),
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
