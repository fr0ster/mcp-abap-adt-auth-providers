/**
 * The composer: the order of one
 * authorization — build the URL, `begin`, arm, present, wait — the payload
 * only the protocol accepted, the first terminal verdict latched, overlap
 * refused, abort and dispose, and `authorize` settling only once the
 * transport is released. Scripted parts where the order is the point; real
 * loopback listeners where a port is ("assert on the port").
 */

import assert from 'node:assert/strict';
import net from 'node:net';
import { describe, it } from 'node:test';
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
import {
  caseTitle,
  contains,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { bindable, capturingLogger, send } from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';

const STATE = 'composer-state_0123456789abcdefghijklmnop';
const REDIRECT = 'http://127.0.0.1:61099/callback';
const urlFor = (redirectUri: string) =>
  `https://idp.example/oauth/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;

const factsOf = (error: unknown) =>
  readFailure(error, 'browser-login').facts as Record<string, unknown>;

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
  for (const [caseIndex, caseRow] of [
    '/auth/%2e%2e/finish',
    '/auth\\finish',
    '/auth path',
    '/auth\u0001finish',
    '/auth?x=1',
    '/auth#x',
    '/',
    '/submit',
    'callback',
  ].entries()) {
    const endpoint = caseRow;
    it(
      caseTitle(
        'an endpoint URL parsing would change, or the listener’s own (%j), is invalid-value endpoint',
        caseRow,
        caseIndex,
      ),
      () => {
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
        assert.deepEqual(factsOf(thrown), {
          case: 'invalid-value',
          fields: ['endpoint'],
        });
      },
    );
  }
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
    assert.deepEqual(events, ['open', 'build', 'begin', 'arm', 'present']);
    assert.equal(shown.calls[0]?.url, urlFor(REDIRECT));
    assert.equal(shown.calls[0]?.context.redirectUri, REDIRECT);
    assert.equal(open.options.endpoint, '/callback');
    assert.deepEqual(open.deliver(rightCode('C1')), {
      verdict: 'accept',
      payload: 'C1',
    });
    open.answer.resolve(undefined);
    assert.deepEqual(await login, {
      payload: 'C1',
      redirectUri: REDIRECT,
    });
    assert.equal(events.at(-1), 'released');
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
    assert.equal(open.options.endpoint, '/auth/finish');
    assert.deepEqual(open.options.paste, protocol.paste);
    assert.deepEqual(open.options.callbackMethods, ['GET']);
    await strategy.dispose();
    assert.equal(factsOf(await login).outcome, 'disposed');
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
    assert.deepEqual(factsOf(thrown), {
      case: 'required-fields-missing',
      fields: ['redirectUri'],
    });
    assert.deepEqual(events, ['open', 'released']);
    assert.equal(shown.calls.length, 0);
  });

  it('a builder’s minted failure passes as it is; a foreign throw is failed, nothing of it kept; nothing presented', async () => {
    // Built first: the constructor's parameter, a union, would widen the case.
    const configuration = authError.configuration({
      case: 'saml-idp-initiated-without-authorization-url',
      fields: ['idpInitiated', 'authorizationUrl'],
    });
    const minted = new AuthProviderFailure(configuration);
    for (const [thrownByBuilder, check] of [
      [minted, (e: unknown) => assert.equal(e, minted)],
      [
        new Error('redirect_uri SECRET mismatch'),
        (e: unknown) => {
          assert.deepEqual(factsOf(e), { outcome: 'failed' });
          notContains(String((e as Error).message), 'SECRET');
          assert.equal((e as { cause?: unknown }).cause, undefined);
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
      assert.equal(shown.calls.length, 0);
      assert.equal(scripted.opens[0]?.judge, undefined);
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
    assert.deepEqual(factsOf(await login), {
      outcome: 'aborted',
      strategy: 'consumer',
    });
    assert.equal(shown.calls.length, 0);
    assert.equal(scripted.opens[0]?.judge, undefined);
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
    assert.deepEqual(factsOf(thrown), { outcome: 'failed' });
    notContains(JSON.stringify(thrown), 'FORGED');
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
    assert.deepEqual(
      open.deliver({
        via: 'redirect',
        method: 'GET',
        params: new URLSearchParams({ code: 'EVIL', state: 'other' }),
      }),
      { verdict: 'refuse', reason: 'state' },
    );
    open.answer.resolve(undefined);
    assert.deepEqual(factsOf(await login), { outcome: 'failed' });
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
    assert.equal(open.deliver(rightCode('FIRST')).verdict, 'accept');
    assert.deepEqual(open.deliver(rightCode('SECOND')), {
      verdict: 'refuse',
      reason: 'already-answered',
    });
    open.answer.resolve(undefined);
    assert.deepEqual(await login, {
      payload: 'FIRST',
      redirectUri: REDIRECT,
    });
  });

  it('an end, then an accept whose response flushes first — the end wins', async () => {
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
    assert.equal(ended.verdict, 'end');
    // A forged accept arrives next and would flush first.
    assert.deepEqual(open.deliver(rightCode('LATE')), {
      verdict: 'refuse',
      reason: 'already-answered',
    });
    // The transport settles its wait as if the later answer had won.
    open.answer.resolve(undefined);
    assert.deepEqual(factsOf(await login), {
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
    assert.equal(reply.status, 500);
    notContains(reply.body, 'JUDGE-SECRET');
    const thrown = await login;
    assert.deepEqual(factsOf(thrown), { outcome: 'failed' });
    notContains(JSON.stringify(thrown), 'JUDGE-SECRET');
    notContains(String((thrown as Error).message), 'JUDGE-SECRET');
    notContains(text(), 'JUDGE-SECRET');
    assert.equal(await bindable(port), true);
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

  for (const [caseIndex, caseRow] of compositions.entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: an overlapping authorize is busy and opens nothing',
        caseRow,
        caseIndex,
      ),
      async () => {
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
        assert.deepEqual(factsOf(second), { outcome: 'busy' });
        assert.equal(counted.opened(), 1);
        counted.gates[0]?.resolve();
        await strategy.dispose();
        assert.equal(factsOf(await first).outcome, 'disposed');
      },
    );
  }

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
    assert.deepEqual(factsOf(await login), {
      outcome: 'disposed',
      strategy: 'browser',
    });
    assert.equal(await bindable(port), true);
    assert.deepEqual(factsOf(await caught(strategy.authorize(request()))), {
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
    assert.deepEqual(factsOf(await login), {
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
    assert.equal(
      (await waitFor(() => send(port, '/callback?code=EVIL&state=wrong')))
        .status,
      400,
    );
    assert.equal((await send(port, '/callback?code=EVIL')).status, 400);
    controller.abort();
    assert.deepEqual(factsOf(await login), {
      outcome: 'aborted',
      strategy: 'browser',
      ignoredCallbacks: 2,
    });
    assert.equal(await bindable(port), true);
    // Aborted, not disposed: the strategy stays usable for the next login.
    const next = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const nextLogin = next.authorize(request());
    await quiet();
    assert.equal(
      (await waitFor(() => send(port, `/callback?code=C2&state=${STATE}`)))
        .status,
      200,
    );
    matchObject(await nextLogin, { payload: 'C2' });
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
    assert.deepEqual(factsOf(thrown), {
      outcome: 'aborted',
      strategy: 'consumer',
    });
    assert.equal(scripted.opens.length, 0);
    const optionAborted = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: oauthCode(),
      endpoint: '/callback',
      signal: AbortSignal.abort(),
    });
    assert.equal(
      factsOf(await caught(optionAborted.authorize(request()))).outcome,
      'aborted',
    );
    assert.equal(scripted.opens.length, 0);
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
    assert.equal(settled, false);
    const second = await caught(strategy.authorize(request()));
    assert.deepEqual(factsOf(second), { outcome: 'busy' });
    assert.equal(held.opened(), 1);
    held.gates[0]?.resolve();
    assert.equal(factsOf(await first).outcome, 'aborted');
    // Released: the next authorize opens the transport again and logs in.
    const third = strategy.authorize(request());
    await quiet();
    held.gates[1]?.resolve();
    assert.equal(
      (await waitFor(() => send(port, `/callback?code=C3&state=${STATE}`)))
        .status,
      200,
    );
    matchObject(await third, { payload: 'C3' });
    assert.equal(held.opened(), 2);
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
    contains(page, 'END-OF-DESCRIPTION');
    contains(page, '</html>');
    assert.deepEqual(factsOf(await login), {
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
    assert.equal(await bindable(port), true);
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
    assert.deepEqual(factsOf(thrown), { outcome: 'failed' });
    notContains(JSON.stringify(thrown), 'FORGED');
    assert.deepEqual(built, []);
    assert.deepEqual(shown.calls, []);
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
    assert.deepEqual(factsOf(thrown), { outcome: 'failed' });
    notContains(JSON.stringify(thrown), 'FORGED3');
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
    matchObject(await strategy.authorize(request()), {
      payload: 'FAST',
    });
    assert.equal(await reply, 200);
  });
});
