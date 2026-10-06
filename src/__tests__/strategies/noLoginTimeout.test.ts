/**
 * RF1 (plan "Review Focus"; spec §6a): no interactive login has a bound of
 * the package's choosing. A browser, an OIDC and a SAML login, and each
 * manual strategy, stay open with fake timers advanced well past the old
 * 30 s and 300 s defaults — the scope observed still open, the port still
 * held — until the test's own `AbortController` aborts; the login then ends
 * `aborted`, the port is bound by the test afterwards, and nothing is left
 * reading stdin. An abort before the bind, during it and while waiting each
 * end the same way. And each shipped strategy settles only once it has
 * released (spec §6b, the drain handoff).
 */

import net from 'node:net';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  CallbackServerFactory,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import {
  runCallbackScope,
  withBrowserCallbackServer,
} from '../../auth/callbackServer';
import { withOidcCallbackServer } from '../../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../../auth/saml2Auth';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import * as browserStrategies from '../../strategies/BrowserCallbackStrategy';
import {
  browserCallbackStrategy,
  type CallbackStrategyOptions,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from '../../strategies/BrowserCallbackStrategy';
import * as manualModule from '../../strategies/manualStrategies';
import {
  type ManualStrategyOptions,
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
} from '../../strategies/manualStrategies';

import { certificate } from '../helpers/certificates';

const PORT = 7878;
/** Past the old browser default (30 s) and the passcode default (300 s). */
const WELL_PAST = 3_600_000;

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

/** One real turn of the event loop (setImmediate is never faked here). */
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

async function turns(n: number): Promise<void> {
  for (let i = 0; i < n; i++) await turn();
}

/** Fake timers for everything a deadline could hide behind. */
function fakeClock(): void {
  jest.useFakeTimers({
    doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'],
  });
}

const factsOf = (error: unknown) => readFailure(error, 'browser-login').facts;

/** Tracks whether a promise has settled, and how. */
function watch(promise: Promise<unknown>) {
  const state: { settled: boolean; error?: unknown } = { settled: false };
  promise.then(
    () => {
      state.settled = true;
    },
    (error: unknown) => {
      state.settled = true;
      state.error = error;
    },
  );
  return state;
}

const request = (): AuthorizationRequest => ({
  buildAuthorizationUrl: async () => 'https://idp.example/authorize',
});

afterEach(async () => {
  jest.useRealTimers();
  expect(await portIsFree(PORT)).toBe(true);
});

const browserKinds: ReadonlyArray<
  readonly [
    string,
    (
      options: CallbackStrategyOptions<never>,
    ) => IAuthorizationStrategy<unknown>,
  ]
> = [
  ['browser', (o) => browserCallbackStrategy(o as CallbackStrategyOptions)],
  ['OIDC', (o) => oidcCallbackStrategy(o as never)],
  ['SAML', (o) => samlCallbackStrategy(o as CallbackStrategyOptions)],
];

describe('RF1: a browser login has no bound of its own', () => {
  it.each(browserKinds)(
    '%s: stays open past the old defaults, then the abort ends it and frees the port',
    async (_name, make) => {
      const consumer = new AbortController();
      let opened = false;
      const strategy = make({
        port: PORT,
        signal: consumer.signal,
        openUrl: async () => {
          opened = true;
        },
      });
      fakeClock();
      const login = watch(strategy.authorize(request()));
      while (!opened) await turn();
      jest.advanceTimersByTime(WELL_PAST);
      await turns(5);
      // Still open: nothing settled, the port still held.
      expect(login.settled).toBe(false);
      expect(await portIsFree(PORT)).toBe(false);

      consumer.abort();
      while (!login.settled) await turn();
      expect(factsOf(login.error)).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
      expect(await portIsFree(PORT)).toBe(true);
    },
  );

  it.each(browserKinds)(
    '%s: an abort before the bind ends it, nothing bound',
    async (_name, make) => {
      const opened = jest.fn(async () => undefined);
      const login = make({
        port: PORT,
        signal: AbortSignal.abort(),
        openUrl: opened,
      }).authorize(request());
      expect(factsOf(await login.catch((e: unknown) => e))).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
      expect(opened).not.toHaveBeenCalled();
    },
  );

  it.each(browserKinds)(
    '%s: an abort during the bind ends it, the port free after',
    async (_name, make) => {
      const consumer = new AbortController();
      const opened = jest.fn(async () => undefined);
      const login = make({
        port: PORT,
        signal: consumer.signal,
        openUrl: opened,
      }).authorize(request());
      // Synchronously, while the port probe and the bind are under way.
      consumer.abort();
      expect(factsOf(await login.catch((e: unknown) => e))).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
      expect(opened).not.toHaveBeenCalled();
      expect(await portIsFree(PORT)).toBe(true);
    },
  );

  it.each(browserKinds)(
    '%s: an abort while the URL is built opens nothing (Task 23 fix round 1)',
    async (_name, make) => {
      const consumer = new AbortController();
      let built!: (url: string) => void;
      const opened = jest.fn(async () => undefined);
      const login = make({
        port: PORT,
        signal: consumer.signal,
        openUrl: opened,
      }).authorize({
        buildAuthorizationUrl: () =>
          new Promise<string>((resolve) => {
            built = resolve;
          }),
      });
      while (!built) await turn();
      consumer.abort();
      built('https://idp.example/authorize');
      expect(factsOf(await login.catch((e: unknown) => e))).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
      await turns(5);
      expect(opened).toHaveBeenCalledTimes(0);
      expect(await portIsFree(PORT)).toBe(true);
    },
  );

  it.each([
    ['browser', withBrowserCallbackServer],
    ['OIDC', withOidcCallbackServer],
    ['SAML', withSamlCallbackServer],
  ] as const)(
    '%s callback server: an abort right after the bind began releases the port',
    async (_name, factory) => {
      const consumer = new AbortController();
      let ran = false;
      const scope = (factory as CallbackServerFactory<unknown>)(
        {
          port: PORT,
          timeoutMs: Number.POSITIVE_INFINITY,
          signal: consumer.signal,
        },
        async () => {
          ran = true;
          return 'unreachable';
        },
      );
      consumer.abort();
      expect(factsOf(await scope.catch((e: unknown) => e))).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
      expect(ran).toBe(false);
      expect(await portIsFree(PORT)).toBe(true);
    },
  );

  it('the 4.x bound field is ignored: a scope given timeoutMs 1 stays open until aborted', async () => {
    const consumer = new AbortController();
    let waiting = false;
    fakeClock();
    const scope = watch(
      runCallbackScope<string, string>(
        { port: PORT, timeoutMs: 1, signal: consumer.signal },
        () => undefined,
        async (srv) => {
          waiting = true;
          return await srv.waitForResult();
        },
      ),
    );
    while (!waiting) await turn();
    jest.advanceTimersByTime(WELL_PAST);
    await turns(5);
    expect(scope.settled).toBe(false);
    expect(await portIsFree(PORT)).toBe(false);
    consumer.abort();
    while (!scope.settled) await turn();
    expect(factsOf(scope.error)).toEqual({
      outcome: 'aborted',
      strategy: 'browser',
    });
  });
});

describe('RF1: a manual login has no bound of its own', () => {
  const manualKinds = [
    ['manualPasteStrategy', manualPasteStrategy],
    ['manualSamlResponseStrategy', manualSamlResponseStrategy],
    ['manualPasscodeStrategy', manualPasscodeStrategy],
  ] as const;

  it.each(manualKinds)(
    '%s: stays open past the old defaults, then the abort ends it',
    async (_name, make) => {
      const consumer = new AbortController();
      let reading = false;
      let readerSignal: AbortSignal | undefined;
      const strategy = make({
        signal: consumer.signal,
        read: (_prompt, signal) => {
          reading = true;
          readerSignal = signal;
          return new Promise<string>((_resolve, reject) => {
            signal.addEventListener('abort', () => reject(new Error('gone')));
          });
        },
      } satisfies ManualStrategyOptions);
      const stderr = jest
        .spyOn(process.stderr, 'write')
        .mockImplementation(() => true);
      try {
        fakeClock();
        const login = watch(strategy.authorize(request()));
        while (!reading) await turn();
        jest.advanceTimersByTime(WELL_PAST);
        await turns(5);
        expect(login.settled).toBe(false);
        expect(readerSignal?.aborted).toBe(false);

        consumer.abort();
        while (!login.settled) await turn();
        expect(factsOf(login.error)).toEqual({
          outcome: 'aborted',
          strategy: 'manual',
        });
      } finally {
        stderr.mockRestore();
      }
    },
  );
});

describe('settle after release (spec §6b): a held release holds the rejection', () => {
  it.each([
    ['browser', browserCallbackStrategy, withBrowserCallbackServer],
    ['OIDC', oidcCallbackStrategy, withOidcCallbackServer],
    ['SAML', samlCallbackStrategy, withSamlCallbackServer],
  ] as const)(
    '%s: the rejection comes only after the factory has released, the port bindable',
    async (_name, make, shipped) => {
      let releaseGate!: () => void;
      const gate = new Promise<void>((resolve) => {
        releaseGate = resolve;
      });
      let factorySettled = false;
      // The shipped transport, whose settle is held after its own release —
      // as a slow socket close would hold it.
      const held: CallbackServerFactory<unknown> = async (options, use) => {
        try {
          return await (shipped as CallbackServerFactory<unknown>)(
            options,
            use,
          );
        } finally {
          await gate;
          factorySettled = true;
        }
      };
      const consumer = new AbortController();
      let opened = false;
      let freeAtRejection: Promise<boolean> | undefined;
      let factoryDoneAtRejection: boolean | undefined;
      const login = (make as typeof browserCallbackStrategy)({
        port: PORT,
        signal: consumer.signal,
        callbackServer: held as CallbackServerFactory<string>,
        openUrl: async () => {
          opened = true;
        },
      })
        .authorize(request())
        .catch((error: unknown) => {
          factoryDoneAtRejection = factorySettled;
          // The bind is attempted in this very turn.
          freeAtRejection = portIsFree(PORT);
          return error;
        });
      while (!opened) await turn();
      consumer.abort();
      await turns(10);
      expect(freeAtRejection).toBeUndefined();
      releaseGate();
      expect(factsOf(await login)).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
      expect(factoryDoneAtRejection).toBe(true);
      expect(await freeAtRejection).toBe(true);
    },
  );
});

describe('the static factories pass their signal to the strategy they compose', () => {
  const config = {
    uaaUrl: 'https://uaa.example',
    clientId: 'cid',
    clientSecret: 'secret',
  };
  const trust = { idpCertificates: [String(certificate().cert)] };
  const saml = {
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'sp',
    idpEntityId: 'idp',
    idpInitiated: true,
    ...config,
  };

  it.each([
    [
      'AuthorizationCodeProvider.inBrowser',
      'browserCallbackStrategy',
      (signal: AbortSignal) =>
        AuthorizationCodeProvider.inBrowser(config, { signal }),
    ],
    [
      'OidcBrowserProvider.inBrowser',
      'oidcCallbackStrategy',
      (signal: AbortSignal) =>
        OidcBrowserProvider.inBrowser(
          {
            clientId: 'cid',
            authorizationEndpoint: 'https://idp.example/authorize',
            tokenEndpoint: 'https://idp.example/token',
          },
          { signal },
        ),
    ],
    [
      'Saml2BearerProvider.inBrowser',
      'samlCallbackStrategy',
      (signal: AbortSignal) =>
        Saml2BearerProvider.inBrowser(saml, trust, { signal }),
    ],
    [
      'Saml2PureProvider.inBrowser',
      'samlCallbackStrategy',
      (signal: AbortSignal) =>
        Saml2PureProvider.inBrowser(
          {
            idpSsoUrl: 'https://idp.example/sso',
            spEntityId: 'sp',
            idpEntityId: 'idp',
            idpInitiated: true,
          } as never,
          trust,
          { signal },
        ),
    ],
  ] as const)('%s', (_name, factoryName, build) => {
    const spy = jest.spyOn(
      browserStrategies,
      factoryName as 'browserCallbackStrategy',
    );
    try {
      const signal = new AbortController().signal;
      build(signal);
      expect(spy).toHaveBeenCalledWith({ signal });
    } finally {
      spy.mockRestore();
    }
  });

  it('UaaPasscodeProvider.fromTerminal', () => {
    const spy = jest.spyOn(manualModule, 'manualPasscodeStrategy');
    try {
      const signal = new AbortController().signal;
      UaaPasscodeProvider.fromTerminal(
        { uaaUrl: 'https://uaa.example', clientId: 'cf', clientSecret: '' },
        { signal },
      );
      expect(spy).toHaveBeenCalledWith({ signal });
    } finally {
      spy.mockRestore();
    }
  });
});
