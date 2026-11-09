/**
 * A typed answer can still throw: a getter is a valid implementation of a
 * typed field. On every asynchronous callback path the collaborator's call
 * and every read of its answer share one failure boundary, so an answer
 * whose field throws ends the login exactly as a call that throws does —
 * the same failure, the same settling, the same release — and the thrown
 * text reaches nothing.
 *
 * Transport level: each shipped transport armed directly with a judge whose
 * verdict's `verdict` getter throws, compared with the same transport armed
 * with a judge that throws itself. Composer level: the composer's latching
 * judge given a protocol whose verdict throws. Provider level: a strategy
 * outcome, a SPNego source answer and an SNC locator answer whose field
 * throws.
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { describe, it } from 'node:test';
import { inspect } from 'node:util';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerTransportOptions,
  AnswerVerdict,
  AuthorizationOutcome,
  AuthorizationRequest,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationProtocol,
  IAuthorizationStrategy,
  INegotiateTokenSource,
  NegotiateTokenAnswer,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { composeAuthorization } from '../../authorization/compose';
import {
  consumerAnswer,
  consumerHandoff,
  loopback4,
  type TerminalRead,
  terminalPaste,
} from '../../authorization/transport';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { refreshThenLogin } from '../../renewal';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import { SpnegoAuthProvider } from '../../spnego/SpnegoAuthProvider';
import { mockedAxios } from '../helpers/axiosModuleMock';
import {
  recordingPresentation,
  scriptedTransport,
} from '../helpers/composedParts';
import { matchObject, notContains } from '../helpers/expectations';
import { bindable, send } from '../helpers/listenerHttp';
import { mintedRefusal } from '../helpers/minted';
import { resetMock } from '../helpers/mockOnce';

// Automocked: a token request is recorded, never sent.

const SECRET = 'SECRET';

/** A typed verdict whose `verdict` field throws when read. */
const throwingVerdict = (): AnswerVerdict<unknown> => ({
  get verdict(): 'accept' {
    throw new Error(SECRET);
  },
  payload: 'never-read',
});

/** A judge that answers the throwing verdict. */
const hostileJudge: AnswerJudge<unknown> = () => throwingVerdict();

/** A judge that throws itself: the failure every hostile answer must equal. */
const throwingJudge: AnswerJudge<unknown> = () => {
  throw new Error(SECRET);
};

/** Every rendering of a value a consumer might log. */
function expectNoSecret(value: unknown): void {
  notContains(String(value), SECRET);
  notContains(JSON.stringify(value) ?? '', SECRET);
  notContains(inspect(value, { depth: 10, showHidden: true }), SECRET);
}

/** The kind and the outcome of a thrown failure. */
function failureOf(thrown: unknown): { kind: string; outcome: unknown } {
  const read = readFailure(thrown, 'browser-login');
  return {
    kind: read.kind,
    outcome: (read.facts as { outcome?: unknown }).outcome,
  };
}

/** `promise`, or a rejection once the test's own bound has passed. */
function within<T>(promise: Promise<T>, ms = 1500): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const bound = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('did not settle')), ms);
  });
  return Promise.race([promise, bound]).finally(() => clearTimeout(timer));
}

/** What one open ended with: `answer()`'s rejection and `open`'s. */
interface Ended {
  readonly answered: unknown;
  readonly opened: unknown;
}

const caught = (promise: Promise<unknown>): Promise<unknown> =>
  promise.then(
    () => 'resolved',
    (error: unknown) => error,
  );

function optionsFor(signal: AbortSignal): AnswerTransportOptions {
  return {
    signal,
    paste: { prompt: 'Paste the answer: ', instructions: 'paste it' },
    callbackMethods: ['GET'],
    endpoint: '/callback',
  };
}

/** How a run is driven. */
interface RunOptions {
  /** `use` never returns: only the transport's own release settles `open`. */
  readonly hold?: boolean;
  /** Called the moment `open` settles, before anything else happens. */
  readonly onOpenSettled?: () => void;
}

/**
 * Opens `transport`, arms it with `judge`, lets `deliver` hand one answer
 * over, and records how `answer()` and `open` ended.
 */
async function runTransport(
  transport: IAnswerTransport,
  judge: AnswerJudge<unknown>,
  deliver: (channel: IAnswerChannel) => Promise<void>,
  { hold = false, onOpenSettled }: RunOptions = {},
): Promise<Ended> {
  const controller = new AbortController();
  let answering: Promise<unknown> | undefined;
  let delivering: Promise<void> | undefined;
  try {
    const opened = await caught(
      within(
        transport
          .open(optionsFor(controller.signal), async (channel) => {
            const waiting = channel.arm(judge).answer();
            answering = caught(waiting);
            delivering = deliver(channel);
            await delivering;
            const answered = await within(answering);
            if (hold) await new Promise<never>(() => undefined);
            if (answered !== 'resolved') throw answered;
          })
          .finally(() => onOpenSettled?.()),
      ),
    );
    // A transport may settle its open before `use` has (a listener ends at
    // its verdict): what was delivered and answered is awaited here.
    await within(delivering ?? Promise.resolve());
    const answered =
      answering === undefined ? 'not armed' : await within(answering);
    return { answered, opened };
  } finally {
    // Only a broken transport is still open here: let it go.
    controller.abort();
  }
}

describe('transport level: a verdict whose field throws', () => {
  describe('loopback', () => {
    async function run(judge: AnswerJudge<unknown>) {
      let port = 0;
      const bodies: string[] = [];
      const ended = await runTransport(
        loopback4({ port: 0 }),
        judge,
        async (channel) => {
          port = Number(new URL(channel.redirectUri as string).port);
          const reply = await send(port, '/callback?code=x');
          bodies.push(reply.body);
        },
        // The listener ends at the judge's failure itself, whatever `use`
        // does.
        { hold: true },
      );
      return { ...ended, port, bodies };
    }

    it('ends as a throwing judge does; no SECRET in any body; the port is free', async () => {
      const baseline = await run(throwingJudge);
      const hostile = await run(hostileJudge);
      assert.deepEqual(failureOf(baseline.opened), {
        kind: 'interactive-login',
        outcome: 'failed',
      });
      assert.deepEqual(
        failureOf(hostile.answered),
        failureOf(baseline.answered),
      );
      assert.deepEqual(failureOf(hostile.opened), failureOf(baseline.opened));
      expectNoSecret(hostile.answered);
      expectNoSecret(hostile.opened);
      assert.equal(hostile.bodies.length, 1);
      for (const body of hostile.bodies) notContains(body, SECRET);
      assert.equal(await bindable(hostile.port), true);
    });
  });

  describe('terminalPaste', () => {
    async function run(judge: AnswerJudge<unknown>) {
      let openSettled = false;
      const reads: AbortSignal[] = [];
      let abortedBeforeSettle = false;
      const read: TerminalRead = async (_prompt, signal) => {
        reads.push(signal);
        signal.addEventListener(
          'abort',
          () => {
            abortedBeforeSettle = !openSettled;
          },
          { once: true },
        );
        return 'pasted-line';
      };
      const transport = terminalPaste({ read });
      const ended = await runTransport(
        transport,
        judge,
        async () => undefined,
        {
          onOpenSettled: () => {
            openSettled = true;
          },
        },
      );
      return { ...ended, reads, abortedBeforeSettle };
    }

    it('ends as a throwing judge does, SECRET nowhere; the reader released before open settled', async () => {
      const baseline = await run(throwingJudge);
      const hostile = await run(hostileJudge);
      assert.deepEqual(failureOf(baseline.opened), {
        kind: 'interactive-login',
        outcome: 'failed',
      });
      assert.deepEqual(
        failureOf(hostile.answered),
        failureOf(baseline.answered),
      );
      assert.deepEqual(failureOf(hostile.opened), failureOf(baseline.opened));
      expectNoSecret(hostile.answered);
      expectNoSecret(hostile.opened);
      assert.equal(hostile.reads.length, 1);
      assert.equal(hostile.abortedBeforeSettle, true);
    });
  });

  describe('consumerAnswer', () => {
    const run = (judge: AnswerJudge<unknown>) =>
      runTransport(
        consumerAnswer({ receive: async () => 'the-answer' }),
        judge,
        async () => undefined,
      );

    it('ends as a throwing judge does, SECRET nowhere', async () => {
      const baseline = await run(throwingJudge);
      const hostile = await run(hostileJudge);
      assert.deepEqual(failureOf(baseline.opened), {
        kind: 'interactive-login',
        outcome: 'failed',
      });
      assert.deepEqual(
        failureOf(hostile.answered),
        failureOf(baseline.answered),
      );
      assert.deepEqual(failureOf(hostile.opened), failureOf(baseline.opened));
      expectNoSecret(hostile.answered);
      expectNoSecret(hostile.opened);
    });
  });

  describe('consumerHandoff', () => {
    const URL_SHOWN = 'https://idp.example/authorize?state=s';
    const context = (): PresentationContext => ({
      redirectUri: undefined,
      signal: new AbortController().signal,
    });

    async function run(judge: AnswerJudge<unknown>) {
      let provided = 0;
      const { presentation, transport } = consumerHandoff({
        provide: async () => {
          provided += 1;
          return 'the-answer';
        },
      });
      const ended = await runTransport(transport, judge, async () => {
        presentation.present(URL_SHOWN, context());
      });
      return { ...ended, presentation, provided: () => provided };
    }

    it('ends as a throwing judge does, SECRET nowhere; the scope is cleared', async () => {
      const baseline = await run(throwingJudge);
      const hostile = await run(hostileJudge);
      assert.deepEqual(failureOf(baseline.opened), {
        kind: 'interactive-login',
        outcome: 'failed',
      });
      assert.deepEqual(
        failureOf(hostile.answered),
        failureOf(baseline.answered),
      );
      assert.deepEqual(failureOf(hostile.opened), failureOf(baseline.opened));
      expectNoSecret(hostile.answered);
      expectNoSecret(hostile.opened);
      assert.equal(hostile.provided(), 1);
      // After `open` settled: no open in progress, so `provide` is not asked.
      hostile.presentation.present(URL_SHOWN, context());
      assert.equal(hostile.provided(), 1);
    });
  });
});

describe('composer level: a protocol whose verdict throws', () => {
  it('fails the login, the transport sees no SECRET, released before authorize settles, not busy after', async () => {
    const events: string[] = [];
    const scripted = scriptedTransport({
      redirectUri: 'http://localhost:61001/callback',
      events,
    });
    const protocol: IAuthorizationProtocol<unknown> = {
      redirect: 'required',
      callbackMethods: ['GET'],
      begin: () => hostileJudge,
    };
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol,
      endpoint: '/callback',
    });
    const request: AuthorizationRequest = {
      buildAuthorizationUrl: async () =>
        'https://idp.example/authorize?state=s',
    };
    const first = caught(strategy.authorize(request)).then((thrown) => {
      events.push('authorize settled');
      return thrown;
    });
    const open = await within(scripted.armed(1));
    // What the transport sees when the composer's judge throws.
    let seen: unknown = 'no throw';
    try {
      open.deliver({ via: 'consumer', text: 'x' });
    } catch (error) {
      seen = error;
    }
    open.answer.reject(seen);
    const thrown = await within(first);

    assert.deepEqual(failureOf(thrown), {
      kind: 'interactive-login',
      outcome: 'failed',
    });
    expectNoSecret(thrown);
    assert.deepEqual(failureOf(seen), {
      kind: 'interactive-login',
      outcome: 'failed',
    });
    expectNoSecret(seen);
    assert.ok(
      events.indexOf('released') >= 0,
      `${events.indexOf('released')} >= ${0}`,
    );
    assert.ok(
      events.indexOf('released') < events.indexOf('authorize settled'),
      `${events.indexOf('released')} < ${events.indexOf('authorize settled')}`,
    );

    // The next login opens again: the composer is not busy.
    const second = caught(strategy.authorize(request));
    await within(scripted.armed(2));
    await strategy.dispose();
    assert.equal(failureOf(await second).outcome, 'disposed');
  });
});

describe('composer level: a request whose field throws', () => {
  it('a logger getter that throws: authorize rejects, and no listener is left on the option signal', async () => {
    const option = new AbortController();
    const scripted = scriptedTransport({
      redirectUri: 'http://localhost:61001/callback',
      events: [],
    });
    const strategy = composeAuthorization({
      presentation: recordingPresentation().presentation,
      transport: scripted.transport,
      protocol: {
        redirect: 'required',
        callbackMethods: ['GET'],
        begin: () => hostileJudge,
      },
      endpoint: '/callback',
      signal: option.signal,
    });
    const request: AuthorizationRequest = {
      buildAuthorizationUrl: async () =>
        'https://idp.example/authorize?state=s',
      get logger(): ILogger {
        throw new Error(SECRET);
      },
    };
    const thrown = await caught(strategy.authorize(request));
    assert.notEqual(thrown, 'resolved');
    assert.equal(getEventListeners(option.signal, 'abort').length, 0);
  });
});

describe('provider level: an answer whose field throws', () => {
  it('regression of the outer boundary — a strategy outcome whose payload throws: getTokens() throws a classified failure, no token request', async () => {
    resetMock(mockedAxios);
    resetMock(mockedAxios.post);
    const strategy: IAuthorizationStrategy<string> = {
      authorize: async (): Promise<AuthorizationOutcome<string>> => ({
        get payload(): string {
          throw new Error(SECRET);
        },
        redirectUri: 'http://localhost:61001/callback',
      }),
    };
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'cid',
      clientSecret: 's',
      authorization: strategy,
    });
    const thrown = await caught(provider.getTokens());
    const failure = readFailure(thrown, 'token-request');
    assert.equal(failure.kind, 'unknown');
    expectNoSecret(thrown);
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });

  it('a SPNego source answer whose ok throws: unknown obtaining-negotiate-token, through the source-failure path', async () => {
    const lines: Array<[string, string]> = [];
    const log =
      (level: string) =>
      (message: string): void => {
        lines.push([level, message]);
      };
    const logger: ILogger = {
      debug: log('debug'),
      info: log('info'),
      warn: log('warn'),
      error: log('error'),
    };
    const tokenSource: INegotiateTokenSource = {
      token: async (): Promise<NegotiateTokenAnswer> => ({
        get ok(): true {
          throw new Error(SECRET);
        },
        token: 'never-read',
      }),
    };
    const provider = new SpnegoAuthProvider({
      servicePrincipal: 'HTTP@sap.example.com',
      tokenSource,
      logger,
    });
    const outcome = await provider.prepare();
    matchObject(mintedRefusal(outcome), {
      kind: 'unknown',
      facts: { operation: 'obtaining-negotiate-token' },
    });
    expectNoSecret(outcome);
    // The source's failure path: its fixed debug line, as for a source
    // that throws.
    assert.deepEqual(lines, [['debug', 'no SPNego token to present']]);
  });

  it('an SNC locator answer whose path throws: its fixed SNC refusal', async () => {
    const provider = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () => ({
          get path(): string {
            throw new Error(SECRET);
          },
          archs: [],
        }),
      },
      probes: [],
    });
    const outcome = await provider.prepare();
    matchObject(mintedRefusal(outcome), {
      kind: 'snc',
      facts: { problem: 'library-not-found' },
    });
    expectNoSecret(outcome);
  });
});
