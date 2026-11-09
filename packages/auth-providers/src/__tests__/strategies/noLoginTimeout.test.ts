/**
 * No interactive login has a bound of
 * the package's choosing. A browser, an OIDC and a SAML login, and each
 * manual strategy, stay open with fake timers advanced well past the old
 * 30 s and 300 s defaults — the scope observed still open, the port still
 * held — until the test's own `AbortController` aborts; the login then ends
 * `aborted`, the port is bound by the test afterwards, and nothing is left
 * reading stdin. An abort before the bind, during it and while waiting each
 * end the same way. And each shipped strategy settles only once it has
 * released (the drain handoff).
 */

import assert from 'node:assert/strict';
import net from 'node:net';
import { afterEach, describe, it, mock } from 'node:test';

// The module objects themselves (a namespace import is a copy of getters,
// which mock.method cannot replace): the factories read them at each call.
import browserStrategies = require('../../strategies/callbackStrategies');
import manualModule = require('../../strategies/manualStrategies');

import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerTransportOptions,
  AuthorizationRequest,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationProtocol,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import { composeAuthorization } from '../../authorization/compose';
import { consumerPresentation } from '../../authorization/presentation';
import {
  oauthCode,
  oidcCode,
  samlResponse,
} from '../../authorization/protocol';
import { loopback, loopback4 } from '../../authorization/transport';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import {
  browserCallbackStrategy,
  type CallbackStrategyOptions,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from '../../strategies/callbackStrategies';
import {
  type ManualPasscodeStrategyOptions,
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
} from '../../strategies/manualStrategies';
import { certificate } from '../helpers/certificates';
import { calledWith, caseTitle } from '../helpers/expectations';
import {
  advanceTimersByTime,
  useFakeTimers,
  useRealTimers,
} from '../helpers/fakeTime';
import { recordingBrowser } from '../helpers/recordingBrowser';

const PORT = 7878;
const REGISTERED = 'http://localhost:61001/callback';
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
  useFakeTimers();
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

const URL_BUILT = 'https://idp.example/authorize?state=S1';
const request = (): AuthorizationRequest => ({
  buildAuthorizationUrl: async () => URL_BUILT,
});

afterEach(async () => {
  useRealTimers();
  assert.equal(await portIsFree(PORT), true);
});

const browserKinds: ReadonlyArray<
  readonly [
    string,
    (options: CallbackStrategyOptions) => IAuthorizationStrategy<unknown>,
  ]
> = [
  ['browser', browserCallbackStrategy],
  ['OIDC', oidcCallbackStrategy],
  ['SAML', samlCallbackStrategy],
];

describe('RF1: a browser login has no bound of its own', () => {
  for (const [caseIndex, caseRow] of browserKinds.entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: stays open past the old defaults, then the abort ends it and frees the port',
        caseRow,
        caseIndex,
      ),
      async () => {
        const consumer = new AbortController();
        let opened = false;
        const strategy = make({
          port: PORT,
          signal: consumer.signal,
          browser: recordingBrowser({
            onOpen: async () => {
              opened = true;
            },
          }),
        });
        fakeClock();
        const login = watch(strategy.authorize(request()));
        while (!opened) await turn();
        advanceTimersByTime(WELL_PAST);
        await turns(5);
        // Still open: nothing settled, the port still held.
        assert.equal(login.settled, false);
        assert.equal(await portIsFree(PORT), false);

        consumer.abort();
        while (!login.settled) await turn();
        assert.deepEqual(factsOf(login.error), {
          outcome: 'aborted',
          strategy: 'browser',
        });
        assert.equal(await portIsFree(PORT), true);
      },
    );
  }

  for (const [caseIndex, caseRow] of browserKinds.entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: an abort before the bind ends it, nothing bound',
        caseRow,
        caseIndex,
      ),
      async () => {
        const opened = mock.fn(async () => undefined);
        const login = make({
          port: PORT,
          signal: AbortSignal.abort(),
          browser: recordingBrowser({ onOpen: opened }),
        }).authorize(request());
        assert.deepEqual(factsOf(await login.catch((e: unknown) => e)), {
          outcome: 'aborted',
          strategy: 'browser',
        });
        assert.equal(opened.mock.callCount(), 0);
      },
    );
  }

  for (const [caseIndex, caseRow] of browserKinds.entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: an abort during the bind ends it, the port free after',
        caseRow,
        caseIndex,
      ),
      async () => {
        const consumer = new AbortController();
        const opened = mock.fn(async () => undefined);
        const login = make({
          port: PORT,
          signal: consumer.signal,
          browser: recordingBrowser({ onOpen: opened }),
        }).authorize(request());
        // Synchronously, while the port probe and the bind are under way.
        consumer.abort();
        assert.deepEqual(factsOf(await login.catch((e: unknown) => e)), {
          outcome: 'aborted',
          strategy: 'browser',
        });
        assert.equal(opened.mock.callCount(), 0);
        assert.equal(await portIsFree(PORT), true);
      },
    );
  }

  for (const [caseIndex, caseRow] of browserKinds.entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: an abort while the URL is built opens nothing',
        caseRow,
        caseIndex,
      ),
      async () => {
        const consumer = new AbortController();
        let built!: (url: string) => void;
        const opened = mock.fn(async () => undefined);
        const login = make({
          port: PORT,
          signal: consumer.signal,
          browser: recordingBrowser({ onOpen: opened }),
        }).authorize({
          buildAuthorizationUrl: () =>
            new Promise<string>((resolve) => {
              built = resolve;
            }),
        });
        while (!built) await turn();
        consumer.abort();
        built(URL_BUILT);
        assert.deepEqual(factsOf(await login.catch((e: unknown) => e)), {
          outcome: 'aborted',
          strategy: 'browser',
        });
        await turns(5);
        assert.equal(opened.mock.callCount(), 0);
        assert.equal(await portIsFree(PORT), true);
      },
    );
  }

  for (const [caseIndex, caseRow] of (
    [
      ['loopback', loopback],
      ['loopback4', loopback4],
    ] as const
  ).entries()) {
    const [_name, listener] = caseRow;
    it(
      caseTitle(
        '%s: an abort right after the bind began releases the port',
        caseRow,
        caseIndex,
      ),
      async () => {
        const consumer = new AbortController();
        let ran = false;
        const scope = listener({ port: PORT }).open(
          {
            signal: consumer.signal,
            callbackMethods: ['GET'],
            endpoint: '/callback',
          },
          async () => {
            ran = true;
            return 'unreachable';
          },
        );
        consumer.abort();
        assert.deepEqual(factsOf(await scope.catch((e: unknown) => e)), {
          outcome: 'aborted',
          strategy: 'browser',
        });
        assert.equal(ran, false);
        assert.equal(await portIsFree(PORT), true);
      },
    );
  }
});

describe('RF1: a manual login has no bound of its own', () => {
  const manualKinds: ReadonlyArray<
    readonly [
      string,
      (
        options: ManualPasscodeStrategyOptions,
      ) => IAuthorizationStrategy<string>,
    ]
  > = [
    [
      'manualPasteStrategy',
      (o) => manualPasteStrategy({ redirectUri: REGISTERED, ...o }),
    ],
    [
      'manualSamlResponseStrategy',
      (o) => manualSamlResponseStrategy({ redirectUri: REGISTERED, ...o }),
    ],
    ['manualPasscodeStrategy', manualPasscodeStrategy],
  ];

  for (const [caseIndex, caseRow] of manualKinds.entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: stays open past the old defaults, then the abort ends it',
        caseRow,
        caseIndex,
      ),
      async () => {
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
        } satisfies ManualPasscodeStrategyOptions);
        const stderr = mock.method(process.stderr, 'write', () => true);
        try {
          fakeClock();
          const login = watch(strategy.authorize(request()));
          while (!reading) await turn();
          advanceTimersByTime(WELL_PAST);
          await turns(5);
          assert.equal(login.settled, false);
          assert.equal(readerSignal?.aborted, false);

          consumer.abort();
          while (!login.settled) await turn();
          assert.deepEqual(factsOf(login.error), {
            outcome: 'aborted',
            strategy: 'manual',
          });
        } finally {
          stderr.mock.restore();
        }
      },
    );
  }
});

describe('settle after release: a held release holds the rejection', () => {
  for (const [caseIndex, caseRow] of (
    [
      ['oauthCode', oauthCode],
      ['oidcCode', oidcCode],
      ['samlResponse', samlResponse],
    ] as const
  ).entries()) {
    const [_name, protocol] = caseRow;
    it(
      caseTitle(
        'a composition over loopback (%s): the rejection comes only after the transport has released, the port bindable',
        caseRow,
        caseIndex,
      ),
      async () => {
        let releaseGate!: () => void;
        const gate = new Promise<void>((resolve) => {
          releaseGate = resolve;
        });
        let transportSettled = false;
        // The shipped transport, whose settle is held after its own release —
        // as a slow socket close would hold it.
        const shipped = loopback({ port: PORT });
        const held: IAnswerTransport = {
          label: shipped.label,
          async open<T>(
            options: AnswerTransportOptions,
            use: (channel: IAnswerChannel) => Promise<T>,
          ): Promise<T> {
            try {
              return await shipped.open(options, use);
            } finally {
              await gate;
              transportSettled = true;
            }
          },
        };
        const consumer = new AbortController();
        let opened = false;
        let freeAtRejection: Promise<boolean> | undefined;
        let transportDoneAtRejection: boolean | undefined;
        const login = composeAuthorization({
          presentation: consumerPresentation({
            show: async () => {
              opened = true;
            },
          }),
          transport: held,
          protocol: (protocol as () => IAuthorizationProtocol<unknown>)(),
          endpoint: '/callback',
          signal: consumer.signal,
        })
          .authorize(request())
          .catch((error: unknown) => {
            transportDoneAtRejection = transportSettled;
            // The bind is attempted in this very turn.
            freeAtRejection = portIsFree(PORT);
            return error;
          });
        while (!opened) await turn();
        consumer.abort();
        await turns(10);
        assert.equal(freeAtRejection, undefined);
        releaseGate();
        assert.deepEqual(factsOf(await login), {
          outcome: 'aborted',
          strategy: 'browser',
        });
        assert.equal(transportDoneAtRejection, true);
        assert.equal(await freeAtRejection, true);
      },
    );
  }
});

describe('the static factories pass their signal to the strategy they compose', () => {
  const config = {
    uaaUrl: 'https://uaa.example',
    clientId: 'cid',
    clientSecret: 'secret',
    renewal: refreshThenLogin(),
  };
  const trust = { idpCertificates: [String(certificate().cert)] };
  const saml = {
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'sp',
    idpEntityId: 'idp',
    idpInitiated: true,
    ...config,
  };

  for (const [caseIndex, caseRow] of (
    [
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
              renewal: refreshThenLogin(),
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
              renewal: refreshThenLogin(),
              idpSsoUrl: 'https://idp.example/sso',
              spEntityId: 'sp',
              idpEntityId: 'idp',
              idpInitiated: true,
            } as never,
            trust,
            { signal },
          ),
      ],
    ] as const
  ).entries()) {
    const [_name, factoryName, build] = caseRow;
    it(caseTitle('%s', caseRow, caseIndex), () => {
      const spy = mock.method(
        browserStrategies,
        factoryName as 'browserCallbackStrategy',
      );
      try {
        const signal = new AbortController().signal;
        build(signal);
        calledWith(spy, { signal });
      } finally {
        spy.mock.restore();
      }
    });
  }

  it('UaaPasscodeProvider.fromTerminal', () => {
    const spy = mock.method(manualModule, 'manualPasscodeStrategy');
    try {
      const signal = new AbortController().signal;
      UaaPasscodeProvider.fromTerminal(
        {
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa.example',
          clientId: 'cf',
          clientSecret: '',
        },
        { signal },
      );
      calledWith(spy, { signal });
    } finally {
      spy.mock.restore();
    }
  });
});
