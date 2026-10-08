/**
 * The composer: the order of one
 * authorization — build the URL, `begin`, arm, present, wait — the payload
 * only the protocol accepted, the first terminal verdict latched, overlap
 * refused, abort and dispose, and `authorize` settling only once the
 * transport is released. Scripted parts where the order is the point; real
 * loopback listeners where a port is ("assert on the port").
 */

import net from 'node:net';
import { describe, expect, it } from '@jest/globals';
import {
  AuthProviderFailure,
  authError,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  AnswerVerdict,
  AuthorizationRequest,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationProtocol,
} from '@mcp-abap-adt/interfaces-auth';
import { composeAuthorization } from '../../authorization/compose';
import { showUrl } from '../../authorization/presentation';
import { oauthCode, oidcCode } from '../../authorization/protocol';
import {
  consumerAnswer,
  loopback4,
  terminalPaste,
} from '../../authorization/transport';
import { deferred, quiet } from '../helpers/attemptHarness';
import {
  heldRelease,
  recordingPresentation,
  scriptedTransport,
} from '../helpers/composedParts';
import { bindable, capturingLogger, send } from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';

const STATE = 'composer-state_0123456789abcdefghijklmnop';
const REDIRECT = 'http://127.0.0.1:61099/callback';
const urlFor = (redirectUri: string) =>
  `https://idp.example/oauth/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;

const factsOf = (error: unknown) =>
  readFailure(error, 'browser-login').facts as Record<string, unknown>;
const kindOf = (error: unknown) => readFailure(error, 'browser-login').kind;

const caught = (promise: Promise<unknown>): Promise<unknown> =>
  promise.then(
    () => {
      throw new Error('expected a rejection');
    },
    (error: unknown) => error,
  );

function request(
  overrides: Partial<AuthorizationRequest> = {},
  events?: string[],
): AuthorizationRequest {
  return {
    buildAuthorizationUrl: async (redirectUri) => {
      events?.push('build');
      return urlFor(redirectUri);
    },
    ...overrides,
  };
}

/** A protocol that records `begin`, delegating to `inner`. */
function recordingProtocol<T>(
  inner: IAuthorizationProtocol<T>,
  events: string[],
): IAuthorizationProtocol<T> {
  return {
    redirect: inner.redirect,
    callbackMethods: inner.callbackMethods,
    paste: inner.paste,
    begin(url) {
      events.push('begin');
      return inner.begin(url);
    },
  };
}

const rightCode = (code: string) => ({
  via: 'redirect' as const,
  method: 'GET' as const,
  params: new URLSearchParams({ code, state: STATE }),
});

describe('construction', () => {
  it.each(['presentation', 'transport', 'protocol'] as const)(
    'a missing %s is required-fields-missing naming it',
    (part) => {
      const parts: Record<string, unknown> = {
        presentation: showUrl(),
        transport: scriptedTransport({ redirectUri: REDIRECT }).transport,
        protocol: oauthCode(),
        endpoint: '/callback',
      };
      delete parts[part];
      let thrown: unknown;
      try {
        composeAuthorization(parts as never);
      } catch (error) {
        thrown = error;
      }
      expect(kindOf(thrown)).toBe('configuration');
      expect(factsOf(thrown)).toEqual({
        case: 'required-fields-missing',
        fields: [part],
      });
    },
  );

  it('a missing endpoint is required-fields-missing endpoint: no default', () => {
    let thrown: unknown;
    try {
      composeAuthorization({
        presentation: showUrl(),
        transport: scriptedTransport({ redirectUri: REDIRECT }).transport,
        protocol: oauthCode(),
      } as never);
    } catch (error) {
      thrown = error;
    }
    expect(factsOf(thrown)).toEqual({
      case: 'required-fields-missing',
      fields: ['endpoint'],
    });
  });

  it.each([
    '/auth/%2e%2e/finish',
    '/auth\\finish',
    '/auth path',
    '/auth\u0001finish',
    '/auth?x=1',
    '/auth#x',
    '/',
    '/submit',
    'callback',
  ])(
    'an endpoint URL parsing would change, or the listener’s own (%j), is invalid-value endpoint',
    (endpoint) => {
      let thrown: unknown;
      try {
        composeAuthorization({
          presentation: showUrl(),
          transport: scriptedTransport({ redirectUri: REDIRECT }).transport,
          protocol: oauthCode(),
          endpoint,
        });
      } catch (error) {
        thrown = error;
      }
      expect(factsOf(thrown)).toEqual({
        case: 'invalid-value',
        fields: ['endpoint'],
      });
    },
  );
});

describe('the order: build, begin, arm, present, wait', () => {
  it('opens, builds the URL from the channel’s redirect, begins, arms, presents — then waits', async () => {
    const events: string[] = [];
    const scripted = scriptedTransport({ redirectUri: REDIRECT, events });
    const shown = recordingPresentation(() => undefined, events);
    const strategy = composeAuthorization({
      presentation: shown.presentation,
      transport: scripted.transport,
      protocol: recordingProtocol(oauthCode(), events),
      endpoint: '/callback',
    });
    const login = strategy.authorize(request({}, events));
    const open = await scripted.armed(1);
    await quiet();
    expect(events).toEqual(['open', 'build', 'begin', 'arm', 'present']);
    expect(shown.calls[0]?.url).toBe(urlFor(REDIRECT));
    expect(shown.calls[0]?.context.redirectUri).toBe(REDIRECT);
    expect(open.options.endpoint).toBe('/callback');
    expect(open.deliver(rightCode('C1'))).toEqual({
      verdict: 'accept',
      payload: 'C1',
    });
    open.answer.resolve(undefined);
    await expect(login).resolves.toEqual({
      payload: 'C1',
      redirectUri: REDIRECT,
    });
    expect(events.at(-1)).toBe('released');
  });

  it('hands a consumer transport the composition’s endpoint, the protocol’s paste words and methods', async () => {
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const protocol = oidcCode();
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol,
      endpoint: '/auth/finish',
    });
    const login = caught(strategy.authorize(request()));
    const open = await scripted.armed(1);
    expect(open.options.endpoint).toBe('/auth/finish');
    expect(open.options.paste).toEqual(protocol.paste);
    expect(open.options.callbackMethods).toEqual(['GET']);
    await strategy.dispose();
    expect(factsOf(await login).outcome).toBe('disposed');
  });

  it('a redirect protocol over a channel with no redirect: required-fields-missing redirectUri, before the URL is built', async () => {
    const events: string[] = [];
    const scripted = scriptedTransport({ redirectUri: undefined, events });
    const shown = recordingPresentation();
    const strategy = composeAuthorization({
      presentation: shown.presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const thrown = await caught(strategy.authorize(request({}, events)));
    expect(factsOf(thrown)).toEqual({
      case: 'required-fields-missing',
      fields: ['redirectUri'],
    });
    expect(events).toEqual(['open', 'released']);
    expect(shown.calls).toHaveLength(0);
  });

  it('a builder’s minted failure passes as it is; a foreign throw is failed, nothing of it kept; nothing presented', async () => {
    // Built first: the constructor's parameter, a union, would widen the case.
    const configuration = authError.configuration({
      case: 'saml-idp-initiated-without-authorization-url',
      fields: ['idpInitiated', 'authorizationUrl'],
    });
    const minted = new AuthProviderFailure(configuration);
    for (const [thrownByBuilder, check] of [
      [minted, (e: unknown) => expect(e).toBe(minted)],
      [
        new Error('redirect_uri SECRET mismatch'),
        (e: unknown) => {
          expect(factsOf(e)).toEqual({ outcome: 'failed' });
          expect(String((e as Error).message)).not.toContain('SECRET');
          expect((e as { cause?: unknown }).cause).toBeUndefined();
        },
      ],
    ] as const) {
      const scripted = scriptedTransport({ redirectUri: REDIRECT });
      const shown = recordingPresentation();
      const strategy = composeAuthorization({
        presentation: shown.presentation,
        transport: scripted.transport,
        protocol: oauthCode(),
        endpoint: '/callback',
      });
      const thrown = await caught(
        strategy.authorize(
          request({
            buildAuthorizationUrl: async () => {
              throw thrownByBuilder;
            },
          }),
        ),
      );
      check(thrown);
      expect(shown.calls).toHaveLength(0);
      expect(scripted.opens[0]?.judge).toBeUndefined();
    }
  });

  it('aborted while the URL was built: aborted, nothing armed, nothing shown', async () => {
    const controller = new AbortController();
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const shown = recordingPresentation();
    const strategy = composeAuthorization({
      presentation: shown.presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const built = deferred<string>();
    const login = caught(
      strategy.authorize(
        request({
          signal: controller.signal,
          buildAuthorizationUrl: () => built.promise,
        }),
      ),
    );
    await quiet();
    controller.abort();
    built.resolve(urlFor(REDIRECT));
    expect(factsOf(await login)).toEqual({
      outcome: 'aborted',
      strategy: 'consumer',
    });
    expect(shown.calls).toHaveLength(0);
    expect(scripted.opens[0]?.judge).toBeUndefined();
  });
});

describe('only what the protocol accepted is returned', () => {
  it('a consumer transport whose answer() resolves without an accept → failed, no payload', async () => {
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = caught(strategy.authorize(request()));
    const open = await scripted.armed(1);
    // A transport claiming a payload of its own: the composer never takes it.
    open.answer.resolve('FORGED-CODE');
    const thrown = await login;
    expect(factsOf(thrown)).toEqual({ outcome: 'failed' });
    expect(JSON.stringify(thrown)).not.toContain('FORGED');
  });

  it('one that calls the judge with a wrong state and resolves → failed', async () => {
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = caught(strategy.authorize(request()));
    const open = await scripted.armed(1);
    expect(
      open.deliver({
        via: 'redirect',
        method: 'GET',
        params: new URLSearchParams({ code: 'EVIL', state: 'other' }),
      }),
    ).toEqual({ verdict: 'refuse', reason: 'state' });
    open.answer.resolve(undefined);
    expect(factsOf(await login)).toEqual({ outcome: 'failed' });
  });

  it('a second accept is refused already-answered; the first payload is returned', async () => {
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = strategy.authorize(request());
    const open = await scripted.armed(1);
    expect(open.deliver(rightCode('FIRST')).verdict).toBe('accept');
    expect(open.deliver(rightCode('SECOND'))).toEqual({
      verdict: 'refuse',
      reason: 'already-answered',
    });
    open.answer.resolve(undefined);
    await expect(login).resolves.toEqual({
      payload: 'FIRST',
      redirectUri: REDIRECT,
    });
  });

  it('C9: an end, then an accept whose response flushes first — the end wins', async () => {
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = caught(strategy.authorize(request()));
    const open = await scripted.armed(1);
    // The IdP's refusal arrives first; its error page's flush is deferred.
    const ended = open.deliver({
      via: 'redirect',
      method: 'GET',
      params: new URLSearchParams({ error: 'access_denied', state: STATE }),
    }) as Extract<AnswerVerdict<unknown>, { verdict: 'end' }>;
    expect(ended.verdict).toBe('end');
    // A forged accept arrives next and would flush first.
    expect(open.deliver(rightCode('LATE'))).toEqual({
      verdict: 'refuse',
      reason: 'already-answered',
    });
    // The transport settles its wait as if the later answer had won.
    open.answer.resolve(undefined);
    expect(factsOf(await login)).toEqual({
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
  });

  it('a judge that throws → failed, a fixed 500 page, no text of it anywhere', async () => {
    const port = await getAvailablePort();
    const { logger, text } = capturingLogger();
    const throwing: IAuthorizationProtocol<string> = {
      redirect: 'required',
      callbackMethods: ['GET'],
      begin: () => () => {
        throw new Error('JUDGE-SECRET');
      },
    };
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: loopback4({ port }),
      protocol: throwing,
      endpoint: '/callback',
    });
    const login = caught(strategy.authorize(request({ logger })));
    await quiet();
    const reply = await waitFor(() => send(port, '/callback?code=X'));
    expect(reply.status).toBe(500);
    expect(reply.body).not.toContain('JUDGE-SECRET');
    const thrown = await login;
    expect(factsOf(thrown)).toEqual({ outcome: 'failed' });
    expect(JSON.stringify(thrown)).not.toContain('JUDGE-SECRET');
    expect(String((thrown as Error).message)).not.toContain('JUDGE-SECRET');
    expect(text()).not.toContain('JUDGE-SECRET');
    expect(await bindable(port)).toBe(true);
  });
});

/** Retries `run` until the listener answers (it binds asynchronously). */
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

describe('overlap, dispose, abort', () => {
  const compositions: ReadonlyArray<
    [string, (port: number) => IAnswerTransport]
  > = [
    ['a listener', (port) => loopback4({ port })],
    [
      'a terminal',
      () =>
        terminalPaste({
          redirectUri: REDIRECT,
          read: (_prompt, signal) =>
            new Promise((_resolve, reject) =>
              signal.addEventListener('abort', () => reject(new Error('x'))),
            ),
        }),
    ],
    [
      'a consumer answer',
      () =>
        consumerAnswer({
          redirectUri: REDIRECT,
          receive: () => new Promise<string>(() => undefined),
        }),
    ],
  ];

  it.each(compositions)(
    '%s: an overlapping authorize is busy and opens nothing',
    async (_name, make) => {
      const port = await getAvailablePort();
      const counted = heldRelease(make(port));
      const strategy = composeAuthorization({
        presentation: recordingPresentation().presentation,
        transport: counted.transport,
        protocol: oauthCode(),
        endpoint: '/callback',
      });
      const first = caught(strategy.authorize(request()));
      await quiet();
      const second = await caught(strategy.authorize(request()));
      expect(factsOf(second)).toEqual({ outcome: 'busy' });
      expect(counted.opened()).toBe(1);
      counted.gates[0]?.resolve();
      await strategy.dispose();
      expect(factsOf(await first).outcome).toBe('disposed');
    },
  );

  it('dispose during authorize → disposed, the port free; idempotent; the next authorize is disposed', async () => {
    const port = await getAvailablePort();
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = caught(strategy.authorize(request()));
    await waitFor(() => send(port, '/nothing'));
    await strategy.dispose();
    await strategy.dispose();
    expect(factsOf(await login)).toEqual({
      outcome: 'disposed',
      strategy: 'browser',
    });
    expect(await bindable(port)).toBe(true);
    expect(factsOf(await caught(strategy.authorize(request())))).toEqual({
      outcome: 'disposed',
      strategy: 'browser',
    });
  });

  it('dispose before the transport is entered: disposed, nothing opened', async () => {
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = caught(strategy.authorize(request()));
    await strategy.dispose();
    expect(factsOf(await login)).toEqual({
      outcome: 'disposed',
      strategy: 'consumer',
    });
  });

  it('abort → aborted with the refused-request count; the port bound by the test afterwards', async () => {
    const port = await getAvailablePort();
    const controller = new AbortController();
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
      signal: controller.signal,
    });
    const login = caught(strategy.authorize(request()));
    await quiet();
    // Two forged callbacks: refused, counted, ignored.
    expect(
      (await waitFor(() => send(port, '/callback?code=EVIL&state=wrong')))
        .status,
    ).toBe(400);
    expect((await send(port, '/callback?code=EVIL')).status).toBe(400);
    controller.abort();
    expect(factsOf(await login)).toEqual({
      outcome: 'aborted',
      strategy: 'browser',
      ignoredCallbacks: 2,
    });
    expect(await bindable(port)).toBe(true);
    // Aborted, not disposed: the strategy stays usable for the next login.
    const next = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const nextLogin = next.authorize(request());
    await quiet();
    expect(
      (await waitFor(() => send(port, `/callback?code=C2&state=${STATE}`)))
        .status,
    ).toBe(200);
    await expect(nextLogin).resolves.toMatchObject({ payload: 'C2' });
  });

  it('the request’s signal aborts too; an already-aborted one opens nothing', async () => {
    const scripted = scriptedTransport({ redirectUri: REDIRECT });
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const thrown = await caught(
      strategy.authorize(request({ signal: AbortSignal.abort() })),
    );
    expect(factsOf(thrown)).toEqual({
      outcome: 'aborted',
      strategy: 'consumer',
    });
    expect(scripted.opens).toHaveLength(0);
    const optionAborted = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
      signal: AbortSignal.abort(),
    });
    expect(
      factsOf(await caught(optionAborted.authorize(request()))).outcome,
    ).toBe('aborted');
    expect(scripted.opens).toHaveLength(0);
  });
});

describe('authorize settles only once the transport is released', () => {
  it('with the release deferred, the aborted authorize stays pending, a second is busy and opens no second transport', async () => {
    const port = await getAvailablePort();
    const held = heldRelease(loopback4({ port }));
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: held.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const controller = new AbortController();
    let settled = false;
    const first = caught(
      strategy.authorize(request({ signal: controller.signal })),
    ).finally(() => {
      settled = true;
    });
    await quiet();
    controller.abort();
    // The listener itself has released; its open's settlement is held.
    await held.innerSettled(1);
    await quiet();
    expect(settled).toBe(false);
    const second = await caught(strategy.authorize(request()));
    expect(factsOf(second)).toEqual({ outcome: 'busy' });
    expect(held.opened()).toBe(1);
    held.gates[0]?.resolve();
    expect(factsOf(await first).outcome).toBe('aborted');
    // Released: the next authorize opens the transport again and logs in.
    const third = strategy.authorize(request());
    await quiet();
    held.gates[1]?.resolve();
    expect(
      (await waitFor(() => send(port, `/callback?code=C3&state=${STATE}`)))
        .status,
    ).toBe(200);
    await expect(third).resolves.toMatchObject({ payload: 'C3' });
    expect(held.opened()).toBe(2);
  });
});

describe('the page is delivered before the login settles', () => {
  it('a client that pauses before reading still gets the whole error page; then the login is refused and the port free', async () => {
    const port = await getAvailablePort();
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const login = caught(strategy.authorize(request()));
    await waitFor(() => send(port, '/nothing'));
    const description = `${'d'.repeat(12_000)}END-OF-DESCRIPTION`;
    const page = await new Promise<string>((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port });
      let text = '';
      socket.setEncoding('utf8');
      socket.pause();
      socket.on('data', (chunk: string) => {
        text += chunk;
      });
      socket.on('end', () => resolve(text));
      socket.on('error', reject);
      socket.write(
        `GET /callback?error=access_denied&error_description=${description}&state=${STATE} HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`,
      );
      setTimeout(() => socket.resume(), 300);
    });
    expect(page).toContain('END-OF-DESCRIPTION');
    expect(page).toContain('</html>');
    expect(factsOf(await login)).toEqual({
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
    expect(await bindable(port)).toBe(true);
  });
});

describe('only what use returned, never what open resolves with', () => {
  it('open resolving a forged outcome without calling use → failed; nothing built, nothing shown', async () => {
    const built: string[] = [];
    const shown = recordingPresentation();
    const strategy = composeAuthorization({
      presentation: shown.presentation,
      transport: {
        label: 'consumer',
        open: async () => ({ payload: 'FORGED', redirectUri: REDIRECT }),
      } as unknown as IAnswerTransport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const thrown = await caught(
      strategy.authorize(
        request({
          buildAuthorizationUrl: async (uri) => {
            built.push(uri);
            return urlFor(uri);
          },
        }),
      ),
    );
    expect(factsOf(thrown)).toEqual({ outcome: 'failed' });
    expect(JSON.stringify(thrown)).not.toContain('FORGED');
    expect(built).toEqual([]);
    expect(shown.calls).toEqual([]);
  });

  it('open resolving a forged outcome while use is still pending → failed', async () => {
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: {
        label: 'consumer',
        open: async (
          _options: unknown,
          use: (channel: IAnswerChannel) => Promise<unknown>,
        ) => {
          void use({
            redirectUri: REDIRECT,
            arm: () => ({ answer: () => new Promise<void>(() => undefined) }),
          }).catch(() => undefined);
          await quiet();
          return { payload: 'FORGED3', redirectUri: REDIRECT };
        },
      } as unknown as IAnswerTransport,
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const thrown = await caught(strategy.authorize(request()));
    expect(factsOf(thrown)).toEqual({ outcome: 'failed' });
    expect(JSON.stringify(thrown)).not.toContain('FORGED3');
  });
});

describe('a fast browser: the presentation answers at once', () => {
  it('the presentation itself sends the right callback the moment it is shown; the login completes on a real port', async () => {
    const port = await getAvailablePort();
    let reply: Promise<number> | undefined;
    const strategy = composeAuthorization({
      presentation: {
        present(url, context) {
          const state = new URL(url).searchParams.get('state') ?? '';
          const path = `${new URL(context.redirectUri ?? '').pathname}?code=FAST&state=${state}`;
          // The request leaves now; a channel not yet armed would refuse it.
          reply = send(port, path).then(
            (answered) => answered.status,
            () => 0,
          );
          // Its answer settles once the browser has its page: a composer
          // that waited for it before arming would have refused the request.
          return reply;
        },
      },
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
      signal: AbortSignal.timeout(5000),
    });
    await expect(strategy.authorize(request())).resolves.toMatchObject({
      payload: 'FAST',
    });
    expect(await reply).toBe(200);
  });
});
