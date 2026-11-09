/**
 * The loopback listener transports, on
 * real sockets: where each binds and what it advertises, literal dispatch
 * of the endpoint it was given, closed until armed, the paste page's form
 * token, the `Host` check with the loopback-peer rule, what each verdict
 * answers, and release before settle. Driven directly with the shipped
 * protocols' judges (the composer is tested apart).
 */

import assert from 'node:assert/strict';
import net from 'node:net';
import { afterEach, describe, it, mock } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerTransportOptions,
  AnswerVerdict,
  AuthorizationAnswer,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationProtocol,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { ANSWER_WORDS } from '../../authorization/answerWords';
import {
  oauthCode,
  oidcCode,
  passcode,
  samlResponse,
} from '../../authorization/protocol';
import { loopback, loopback4, loopback6 } from '../../authorization/transport';
import {
  cases,
  caseTitle,
  contains,
  matchObject,
  notContains,
  thrown,
} from '../helpers/expectations';
import {
  bindable,
  capturingLogger,
  connects,
  externalIpv4,
  formTokenIn,
  hasIpv6Loopback,
  type Reply,
  send,
} from '../helpers/listenerHttp';

const STATE = 'Xy9-state-of-this-login_0123456789abcdef';
const urlFor = (redirectUri: string) =>
  `https://idp.example/oauth/authorize?client_id=c&redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;

type Protocol = IAuthorizationProtocol<unknown>;

const PROTOCOLS: ReadonlyArray<[string, () => Protocol]> = [
  ['oauthCode', oauthCode],
  ['oidcCode', oidcCode],
  ['samlResponse', samlResponse],
  ['passcode', passcode],
];

/** The right answer per protocol: by redirect (when it takes one) and pasted. */
const RIGHT: Record<
  string,
  { redirect?: string; paste: string; payload: unknown; pastePayload: unknown }
> = {
  oauthCode: {
    redirect: `?code=the-code&state=${STATE}`,
    paste: 'the-code',
    payload: 'the-code',
    pastePayload: 'the-code',
  },
  oidcCode: {
    redirect: `?code=the-code&state=${STATE}`,
    paste: `http://localhost/callback?code=the-code&state=${STATE}`,
    payload: { code: 'the-code', state: STATE },
    pastePayload: { code: 'the-code', state: undefined },
  },
  samlResponse: {
    redirect: '?SAMLResponse=PHNhbWw%2B',
    paste: '  PHNhbWw+  ',
    payload: 'PHNhbWw+',
    pastePayload: 'PHNhbWw+',
  },
  passcode: { paste: ' 1a2b3c ', payload: '1a2b3c', pastePayload: '1a2b3c' },
};

let ipv6: boolean | undefined;
const v6 = async (): Promise<boolean> => {
  ipv6 ??= await hasIpv6Loopback();
  if (!ipv6) console.warn('no IPv6 loopback on this machine: case not run');
  return ipv6;
};
const EXTERNAL = externalIpv4();

const LISTENERS: ReadonlyArray<
  [string, (port: number) => IAnswerTransport, string, string]
> = [
  // name, factory, address to connect to, advertised host
  ['loopback', (port) => loopback({ port }), '127.0.0.1', 'localhost'],
  ['loopback4', (port) => loopback4({ port }), '127.0.0.1', '127.0.0.1'],
  ['loopback6', (port) => loopback6({ port }), '::1', '[::1]'],
];

interface Driving {
  readonly port: number;
  readonly channel: IAnswerChannel;
  /** Arms the channel with the protocol's judge for `urlFor(redirectUri)`. */
  arm(): void;
  /** How many answers reached the judge. */
  judged(): number;
}

interface Driven {
  readonly payload: unknown;
  readonly judged: number;
  readonly port: number;
}

/**
 * Opens `transport` for `protocol`; `act` sends what the case needs and
 * arms when it should. Returns once the armed wait has resolved.
 */
function drive(
  transport: IAnswerTransport,
  protocol: Protocol,
  act: (driving: Driving) => Promise<void>,
  extra: {
    signal?: AbortSignal;
    logger?: ILogger;
    endpoint?: string;
    onPort?: (port: number) => void;
  } = {},
): Promise<Driven> {
  const options: AnswerTransportOptions = {
    signal: extra.signal ?? new AbortController().signal,
    logger: extra.logger,
    paste: protocol.paste,
    callbackMethods: protocol.callbackMethods,
    endpoint: extra.endpoint ?? '/callback',
  };
  return transport.open(options, async (channel) => {
    const redirectUri = channel.redirectUri as string;
    const port = Number(new URL(redirectUri).port);
    extra.onPort?.(port);
    let payload: unknown;
    let judged = 0;
    let waiting: Promise<void> | undefined;
    const judge = protocol.begin(urlFor(redirectUri));
    const arm = () => {
      const armed = channel.arm((answer) => {
        judged += 1;
        const verdict = judge(answer);
        if (verdict.verdict === 'accept') payload = verdict.payload;
        return verdict;
      });
      waiting = armed.answer();
      void waiting.catch(() => undefined);
    };
    await act({ port, channel, arm, judged: () => judged });
    if (waiting === undefined) throw new Error('the case never armed');
    await waiting;
    return { payload, judged, port };
  });
}

/** `send` against the listener of `name` (its own address). */
const at = (name: string) =>
  LISTENERS.find(([n]) => n === name)?.[2] ?? '127.0.0.1';

let lastPort: number | undefined;
afterEach(async () => {
  if (lastPort !== undefined) {
    // Assert on the port: a settled open means it is free.
    assert.equal(await bindable(lastPort), true);
    lastPort = undefined;
  }
});

const failureOf = (thrown: unknown) => readFailure(thrown, 'browser-login');

describe('bind and advertise', () => {
  /** The host of every `listen` call made while `run` runs. */
  async function listenHosts(run: () => Promise<unknown>): Promise<string[]> {
    const hosts: string[] = [];
    const listen = net.Server.prototype.listen;
    const spy = mock.method(
      net.Server.prototype,
      'listen',
      function (this: net.Server, ...args: unknown[]) {
        const first = args[0];
        // The listeners bind with an options object; a probe of the test's
        // own (`listen(0, '::1')`) is not theirs.
        if (first !== null && typeof first === 'object') {
          hosts.push(String((first as { host?: unknown }).host));
        }
        return listen.apply(this, args as never);
      },
    );
    try {
      await run();
    } finally {
      spy.mock.restore();
    }
    return hosts;
  }

  it('loopback4 binds 127.0.0.1 only and advertises http://127.0.0.1:<port>/callback', async () => {
    let seen: { redirect: string | undefined; port: number } | undefined;
    const hosts = await listenHosts(() =>
      drive(
        loopback4({ port: 0 }),
        oauthCode(),
        async ({ port, channel, arm }) => {
          seen = { redirect: channel.redirectUri, port };
          assert.equal(await connects('127.0.0.1', port), true);
          if (await v6()) assert.equal(await connects('::1', port), false);
          if (EXTERNAL) assert.equal(await connects(EXTERNAL, port), false);
          arm();
          await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
        },
      ),
    );
    assert.deepEqual(hosts, ['127.0.0.1']);
    assert.equal(seen?.redirect, `http://127.0.0.1:${seen?.port}/callback`);
    lastPort = seen?.port;
  });

  it('loopback6 binds ::1 only and advertises http://[::1]:<port>/callback', async () => {
    if (!(await v6())) return;
    let seen: { redirect: string | undefined; port: number } | undefined;
    const hosts = await listenHosts(() =>
      drive(
        loopback6({ port: 0 }),
        oauthCode(),
        async ({ port, channel, arm }) => {
          seen = { redirect: channel.redirectUri, port };
          assert.equal(await connects('::1', port), true);
          assert.equal(await connects('127.0.0.1', port), false);
          arm();
          await send(port, `/callback${RIGHT.oauthCode?.redirect}`, {
            address: '::1',
          });
        },
      ),
    );
    assert.deepEqual(hosts, ['::1']);
    assert.equal(seen?.redirect, `http://[::1]:${seen?.port}/callback`);
    assert.equal(await bindable(seen?.port ?? 0, '::1'), true);
  });

  it('loopback binds 127.0.0.1, then ::1 on the same port, and advertises http://localhost:<port>/callback', async () => {
    const both = await v6();
    let seen: { redirect: string | undefined; port: number } | undefined;
    const hosts = await listenHosts(() =>
      drive(
        loopback({ port: 0 }),
        oauthCode(),
        async ({ port, channel, arm }) => {
          seen = { redirect: channel.redirectUri, port };
          assert.equal(await connects('127.0.0.1', port), true);
          if (both) assert.equal(await connects('::1', port), true);
          if (EXTERNAL) assert.equal(await connects(EXTERNAL, port), false);
          arm();
          await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
        },
      ),
    );
    assert.deepEqual(hosts, ['127.0.0.1', '::1']);
    assert.equal(seen?.redirect, `http://localhost:${seen?.port}/callback`);
    lastPort = seen?.port;
  });

  it('loopback with [::1]:<port> held fails port-in-use, nothing left bound (fixed port)', async () => {
    if (!(await v6())) return;
    const squatter = net.createServer();
    await new Promise<void>((resolve) => squatter.listen(0, '::1', resolve));
    const port = (squatter.address() as net.AddressInfo).port;
    let entered = false;
    try {
      const thrown = await loopback({ port })
        .open(
          {
            signal: new AbortController().signal,
            callbackMethods: ['GET'],
            endpoint: '/callback',
          },
          async () => {
            entered = true;
          },
        )
        .catch((error: unknown) => error);
      assert.deepEqual(failureOf(thrown).facts, {
        outcome: 'port-in-use',
        port,
      });
      assert.equal(entered, false);
      // Never 127.0.0.1 alone: that half was released.
      assert.equal(await bindable(port, '127.0.0.1'), true);
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });

  it('loopback on port 0 with the OS-given port taken on ::1 fails port-in-use — never 127.0.0.1 alone', async () => {
    if (!(await v6())) return;
    const squatter = net.createServer();
    const listen = net.Server.prototype.listen;
    const spy = mock.method(
      net.Server.prototype,
      'listen',
      function (this: net.Server, ...args: unknown[]) {
        const first = args[0] as { port?: number; host?: string };
        if (first?.host === '::1' && !squatter.listening && this !== squatter) {
          listen.call(squatter, { port: first.port, host: '::1' }, () => {
            listen.apply(this, args as never);
          });
          return this;
        }
        return listen.apply(this, args as never);
      },
    );
    let entered = false;
    try {
      const thrown = await loopback({ port: 0 })
        .open(
          {
            signal: new AbortController().signal,
            callbackMethods: ['GET'],
            endpoint: '/callback',
          },
          async () => {
            entered = true;
          },
        )
        .catch((error: unknown) => error);
      const squatted = (squatter.address() as net.AddressInfo).port;
      assert.deepEqual(failureOf(thrown).facts, {
        outcome: 'port-in-use',
        port: squatted,
      });
      assert.equal(entered, false);
      assert.equal(await bindable(squatted, '127.0.0.1'), true);
    } finally {
      spy.mock.restore();
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });

  it('loopback on a machine without ::1 (EADDRNOTAVAIL) listens on 127.0.0.1 alone and still logs in', async () => {
    const listen = net.Server.prototype.listen;
    const spy = mock.method(
      net.Server.prototype,
      'listen',
      function (this: net.Server, ...args: unknown[]) {
        const first = args[0] as { host?: string };
        if (first?.host === '::1') {
          const error = Object.assign(new Error('unavailable'), {
            code: 'EADDRNOTAVAIL',
          });
          process.nextTick(() => this.emit('error', error));
          return this;
        }
        return listen.apply(this, args as never);
      },
    );
    try {
      const driven = await drive(
        loopback({ port: 0 }),
        oauthCode(),
        async ({ port, channel, arm }) => {
          assert.equal(
            channel.redirectUri,
            `http://localhost:${port}/callback`,
          );
          arm();
          await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
        },
      );
      assert.equal(driven.payload, 'the-code');
      lastPort = driven.port;
    } finally {
      spy.mock.restore();
    }
  });

  for (const [caseIndex, caseRow] of cases([
    ['loopback4', '127.0.0.1'],
    ['loopback6', '::1'],
    ['loopback', '127.0.0.1'],
  ]).entries()) {
    const [name, address] = caseRow;
    it(
      caseTitle(
        '%s with its port held on %s fails port-in-use',
        caseRow,
        caseIndex,
      ),
      async () => {
        if (address === '::1' && !(await v6())) return;
        const squatter = net.createServer();
        await new Promise<void>((resolve) =>
          squatter.listen(0, address, resolve),
        );
        const port = (squatter.address() as net.AddressInfo).port;
        const factory = LISTENERS.find(([n]) => n === name)?.[1];
        try {
          const thrown = await factory?.(port)
            .open(
              {
                signal: new AbortController().signal,
                callbackMethods: ['GET'],
                endpoint: '/callback',
              },
              async () => undefined,
            )
            .catch((error: unknown) => error);
          assert.deepEqual(failureOf(thrown).facts, {
            outcome: 'port-in-use',
            port,
          });
        } finally {
          await new Promise<void>((resolve) => squatter.close(() => resolve()));
        }
      },
    );
  }

  for (const [caseIndex, caseRow] of [
    -1,
    65536,
    1.5,
    '61001',
    undefined,
    null,
    Number.NaN,
  ].entries()) {
    const port = caseRow;
    it(
      caseTitle('a port of %p is refused at construction', caseRow, caseIndex),
      () => {
        for (const factory of [loopback, loopback4, loopback6]) {
          let thrown: unknown;
          try {
            factory({ port } as never);
          } catch (error) {
            thrown = error;
          }
          matchObject(readFailure(thrown, 'browser-login'), {
            kind: 'configuration',
            facts: { case: 'callback-port-invalid', fields: ['port'] },
          });
        }
      },
    );
  }

  it('names where it waits and, with paste words, the SSH tunnel to its own address', async () => {
    for (const [name, factory, address, host] of LISTENERS) {
      if (address === '::1' && !(await v6())) continue;
      await drive(factory(0), oauthCode(), async ({ port, channel, arm }) => {
        assert.equal(channel.waitingOn, `http://${host}:${port}/callback`);
        const tunnelTo = name === 'loopback' ? 'localhost' : host;
        contains(
          channel.routeHint,
          `ssh -L ${port}:${tunnelTo}:${port} <this machine>`,
        );
        contains(channel.routeHint, `http://${host}:${port}/`);
        arm();
        await send(port, `/callback${RIGHT.oauthCode?.redirect}`, { address });
      });
    }
    // Without paste words: no paste page, so no route to name.
    const bare: Protocol = {
      redirect: 'required',
      callbackMethods: ['GET'],
      begin: () => () => ({ verdict: 'accept', payload: 'x' }),
    };
    await drive(
      loopback4({ port: 0 }),
      bare,
      async ({ port, channel, arm }) => {
        assert.equal(channel.routeHint, undefined);
        arm();
        // No paste page: `/` and `/submit` are not this listener's.
        assert.equal((await send(port, '/')).status, 404);
        assert.equal((await send(port, '/submit', { form: {} })).status, 404);
        await send(port, '/callback?x=1');
      },
    );
  });
});

describe('the matrix: every protocol over every listener', () => {
  for (const [name, factory, address] of LISTENERS) {
    for (const [protocolName, make] of PROTOCOLS) {
      const right = RIGHT[protocolName];
      it(`${protocolName} over ${name}: the right redirect logs in, the wrong one is refused and the login waits`, async () => {
        if (address === '::1' && !(await v6())) return;
        const { logger, reasons } = capturingLogger();
        const protocol = make();
        if (right?.redirect === undefined) {
          // A protocol that takes no redirect has no callback route.
          const driven = await drive(
            factory(0),
            protocol,
            async ({ port, arm }) => {
              arm();
              assert.equal(
                (await send(port, '/callback?code=x', { address })).status,
                404,
              );
              const page = await send(port, '/', { address });
              await send(port, '/submit', {
                address,
                form: {
                  form_token: formTokenIn(page.body) ?? '',
                  input: right?.paste ?? '',
                },
              });
            },
            { logger },
          );
          assert.deepEqual(driven.payload, right?.pastePayload);
          return;
        }
        const driven = await drive(
          factory(0),
          protocol,
          async ({ port, arm }) => {
            arm();
            const wrong =
              protocolName === 'samlResponse'
                ? '?RelayState=x'
                : `?state=${STATE}`;
            const refused = await send(port, `/callback${wrong}`, { address });
            assert.equal(refused.status, 400);
            assert.equal(refused.body, ANSWER_WORDS['no-payload']);
            const accepted = await send(port, `/callback${right.redirect}`, {
              address,
            });
            assert.equal(accepted.status, 200);
            contains(accepted.body, 'Authentication Successful');
          },
          { logger },
        );
        assert.deepEqual(driven.payload, right.payload);
        assert.deepEqual(reasons(), ['no-payload']);
      });

      it(`${protocolName} over ${name}'s paste page: the right paste logs in, the wrong one gets the form again`, async () => {
        if (address === '::1' && !(await v6())) return;
        const driven = await drive(
          factory(0),
          make(),
          async ({ port, arm }) => {
            arm();
            const page = await send(port, '/', { address });
            assert.equal(page.status, 200);
            const token = formTokenIn(page.body) ?? '';
            assert.notEqual(token, '');
            const wrongText =
              protocolName === 'oauthCode' || protocolName === 'oidcCode'
                ? `http://localhost/callback?code=c&state=another-login`
                : '   ';
            const wrongReason =
              protocolName === 'oauthCode' || protocolName === 'oidcCode'
                ? 'pasted-state'
                : 'no-payload';
            const again = await send(port, '/submit', {
              address,
              form: { form_token: token, input: wrongText },
            });
            assert.equal(again.status, 400);
            contains(again.body, ANSWER_WORDS[wrongReason]);
            // The form again, with the same token.
            assert.equal(formTokenIn(again.body), token);
            const done = await send(port, '/submit', {
              address,
              form: { form_token: token, input: right?.paste ?? '' },
            });
            assert.equal(done.status, 200);
            contains(done.body, 'Authentication Successful');
          },
        );
        assert.deepEqual(driven.payload, right?.pastePayload);
      });
    }
  }

  it('a SAMLResponse posted to the endpoint (urlencoded) logs in', async () => {
    const driven = await drive(
      loopback4({ port: 0 }),
      samlResponse(),
      async ({ port, arm }) => {
        arm();
        const reply = await send(port, '/callback', {
          form: { SAMLResponse: 'PHNhbWw+', RelayState: 'r' },
        });
        assert.equal(reply.status, 200);
      },
    );
    assert.equal(driven.payload, 'PHNhbWw+');
    lastPort = driven.port;
  });

  it('a POST to the endpoint of a GET-only protocol is not routed (404)', async () => {
    const driven = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, arm, judged }) => {
        arm();
        const reply = await send(port, '/callback', {
          form: { code: 'c', state: STATE },
        });
        assert.equal(reply.status, 404);
        assert.equal(judged(), 0);
        await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
      },
    );
    lastPort = driven.port;
  });

  it('a POST body that is not urlencoded carries nothing; one over 5 MB is refused 413', async () => {
    const driven = await drive(
      loopback4({ port: 0 }),
      samlResponse(),
      async ({ port, arm, judged }) => {
        arm();
        const json = await send(port, '/callback', {
          body: JSON.stringify({ SAMLResponse: 'PHNhbWw+' }),
          contentType: 'application/json',
        });
        assert.equal(json.status, 400);
        assert.equal(json.body, ANSWER_WORDS['no-payload']);
        const big = await send(port, '/callback', {
          body: `SAMLResponse=${'A'.repeat(5 * 1024 * 1024 + 1)}`,
        });
        assert.equal(big.status, 413);
        assert.equal(judged(), 1);
        await send(port, '/callback?SAMLResponse=PHNhbWw%2B');
      },
    );
    assert.equal(driven.payload, 'PHNhbWw+');
    lastPort = driven.port;
  });
});

describe('the endpoint: literal dispatch', () => {
  for (const [caseIndex, caseRow] of LISTENERS.entries()) {
    const [_name, factory, address, host] = caseRow;
    it(
      caseTitle(
        "%s's redirect is its origin plus the endpoint it was given, which alone receives it",
        caseRow,
        caseIndex,
      ),
      async () => {
        if (address === '::1' && !(await v6())) return;
        const driven = await drive(
          factory(0),
          oauthCode(),
          async ({ port, channel, arm }) => {
            assert.equal(
              channel.redirectUri,
              `http://${host}:${port}/auth/finish`,
            );
            arm();
            const old = await send(
              port,
              `/callback${RIGHT.oauthCode?.redirect}`,
              {
                address,
              },
            );
            assert.equal(old.status, 404);
            const reply = await send(
              port,
              `/auth/finish${RIGHT.oauthCode?.redirect}`,
              {
                address,
              },
            );
            assert.equal(reply.status, 200);
          },
          { endpoint: '/auth/finish' },
        );
        assert.equal(driven.payload, 'the-code');
      },
    );
  }

  it('/callback/ and /CALLBACK answer 404 for the endpoint /callback, reaching no judge', async () => {
    const driven = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, arm, judged }) => {
        arm();
        for (const path of [
          '/callback/',
          '/CALLBACK',
          '/Callback',
          '/callback/x',
          '//callback',
          '/callback%2F',
          // No dot-segment resolution: the raw target, compared as a string.
          '/./callback',
          '/x/../callback',
          '/%2e/callback',
          '/x/%2E%2E/callback',
        ]) {
          const reply = await send(port, `${path}${RIGHT.oauthCode?.redirect}`);
          assert.deepEqual([path, reply.status], [path, 404]);
          assert.equal(reply.body, 'Not found');
        }
        assert.equal(judged(), 0);
        await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
      },
    );
    lastPort = driven.port;
  });

  for (const [caseIndex, caseRow] of [
    '/SUBMIT',
    '/submit/',
    '/:answer',
  ].entries()) {
    const endpoint = caseRow;
    it(
      caseTitle(
        'the endpoint %s never shares a handler with /submit, and is reached only at its own path',
        caseRow,
        caseIndex,
      ),
      async () => {
        const driven = await drive(
          loopback4({ port: 0 }),
          oauthCode(),
          async ({ port, arm, judged }) => {
            arm();
            // `/submit` still requires its form token: refused before any judge.
            const forged = await send(port, '/submit', {
              form: { input: 'forged-code' },
            });
            assert.equal(forged.status, 400);
            assert.equal(forged.body, ANSWER_WORDS['form-token']);
            for (const path of ['/submit', '/x', '/answer', '/submit/x']) {
              if (path === endpoint) continue;
              const reply = await send(
                port,
                `${path}${RIGHT.oauthCode?.redirect}`,
              );
              assert.deepEqual([path, reply.status], [path, 404]);
            }
            assert.equal(judged(), 0);
            const reply = await send(
              port,
              `${endpoint}${RIGHT.oauthCode?.redirect}`,
            );
            assert.equal(reply.status, 200);
          },
          { endpoint },
        );
        assert.equal(driven.payload, 'the-code');
        lastPort = driven.port;
      },
    );
  }

  for (const [caseIndex, caseRow] of cases([
    ['/auth/%2e%2e/finish'],
    ['/auth/../finish'],
    ['/auth\\finish'],
    ['/auth path'],
    ['/auth\u0001finish'],
    ['/auth\tfinish'],
    ['/auth?finish'],
    ['/auth#finish'],
    ['/'],
    ['/submit'],
    [''],
    ['callback'],
    ['//evil.example/callback'],
    ['http://localhost/callback'],
    [undefined],
    [42],
  ]).entries()) {
    const [endpoint] = caseRow;
    it(
      caseTitle(
        'an endpoint URL parsing would change, or a listener route (%p), is refused before anything binds',
        caseRow,
        caseIndex,
      ),
      async () => {
        let entered = false;
        const thrown = await loopback4({ port: 0 })
          .open(
            {
              signal: new AbortController().signal,
              paste: oauthCode().paste,
              callbackMethods: ['GET'],
              endpoint: endpoint as string,
            },
            async () => {
              entered = true;
            },
          )
          .catch((error: unknown) => error);
        assert.equal(entered, false);
        matchObject(failureOf(thrown), {
          kind: 'configuration',
          facts: { case: 'invalid-value', fields: ['endpoint'] },
        });
      },
    );
  }
});

describe('closed until armed', () => {
  for (const [caseIndex, caseRow] of PROTOCOLS.entries()) {
    const [protocolName, make] = caseRow;
    it(
      caseTitle(
        '%s: a forged code, a forged ?error=, GET / and POST /submit before arming are 400, counted, ignored; then the login completes',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { logger, reasons } = capturingLogger();
        const protocol = make();
        const right = RIGHT[protocolName];
        const takesRedirect = protocol.callbackMethods.length > 0;
        const driven = await drive(
          loopback4({ port: 0 }),
          protocol,
          async ({ port, arm, judged }) => {
            const replies: Reply[] = [];
            if (takesRedirect) {
              replies.push(
                await send(port, `/callback?code=forged&state=${STATE}`),
              );
              replies.push(
                await send(
                  port,
                  `/callback?error=access_denied&state=${STATE}`,
                ),
              );
              replies.push(await send(port, '/callback?SAMLResponse=forged'));
            }
            if (protocol.callbackMethods.includes('POST')) {
              replies.push(
                await send(port, '/callback', {
                  form: { SAMLResponse: 'forged' },
                }),
              );
            }
            const page = await send(port, '/');
            replies.push(page);
            // No form, so no token, exists yet.
            assert.equal(formTokenIn(page.body), undefined);
            replies.push(
              await send(port, '/submit', {
                form: { form_token: 'guess', input: 'forged' },
              }),
            );
            for (const reply of replies) {
              assert.equal(reply.status, 400);
              assert.equal(reply.body, ANSWER_WORDS['not-armed']);
            }
            assert.equal(judged(), 0);
            assert.deepEqual(
              reasons(),
              replies.map(() => 'not-armed'),
            );
            arm();
            if (right?.redirect !== undefined) {
              await send(port, `/callback${right.redirect}`);
            } else {
              const form = await send(port, '/');
              await send(port, '/submit', {
                form: {
                  form_token: formTokenIn(form.body) ?? '',
                  input: right?.paste ?? '',
                },
              });
            }
          },
          { logger },
        );
        assert.deepEqual(
          driven.payload,
          right?.redirect !== undefined ? right.payload : right?.pastePayload,
        );
        lastPort = driven.port;
      },
    );
  }

  it('arms once: a second arm is refused', async () => {
    const driven = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, channel, arm }) => {
        arm();
        assert.throws(
          () => channel.arm(() => ({ verdict: 'accept', payload: 'other' })),
          thrown(),
        );
        await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
      },
    );
    assert.equal(driven.payload, 'the-code');
    lastPort = driven.port;
  });
});

describe('the state binds a redirect (through the listener)', () => {
  for (const [caseIndex, caseRow] of (
    [
      ['oauthCode', oauthCode],
      ['oidcCode', oidcCode],
    ] as const
  ).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: none, two, a wrong and then the right state — the first three 400, counted, ignored',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { logger, reasons } = capturingLogger();
        const driven = await drive(
          loopback4({ port: 0 }),
          make() as Protocol,
          async ({ port, arm }) => {
            arm();
            for (const query of [
              '?code=c',
              `?code=c&state=${STATE}&state=${STATE}`,
              '?code=c&state=another',
              '?error=access_denied&state=another',
            ]) {
              const reply = await send(port, `/callback${query}`);
              assert.equal(reply.status, 400);
              assert.equal(reply.body, ANSWER_WORDS.state);
            }
            await send(port, `/callback?code=c&state=${STATE}`);
          },
          { logger },
        );
        assert.deepEqual(reasons(), ['state', 'state', 'state', 'state']);
        assert.deepEqual(
          driven.payload,
          _name === 'oauthCode' ? 'c' : { code: 'c', state: STATE },
        );
        lastPort = driven.port;
      },
    );
  }
});

describe('the form token', () => {
  it('no token, a wrong one and two are refused before the protocol sees anything; the right one with a bare code logs in', async () => {
    const { logger, reasons } = capturingLogger();
    const driven = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, arm, judged }) => {
        arm();
        const page = await send(port, '/');
        const token = formTokenIn(page.body) ?? '';
        assert.ok(token.length >= 43, `${token.length} >= ${43}`);
        for (const form of [
          { input: 'forged' },
          { form_token: 'not-the-token', input: 'forged' },
          { form_token: [token, token], input: 'forged' },
          { form_token: '', input: 'forged' },
        ]) {
          const reply = await send(port, '/submit', { form });
          assert.equal(reply.status, 400);
          assert.equal(reply.body, ANSWER_WORDS['form-token']);
          // Refused in fixed words: no fresh form, so no token.
          assert.equal(formTokenIn(reply.body), undefined);
        }
        assert.equal(judged(), 0);
        // `/submit` is a POST.
        const get = await send(
          port,
          `/submit?form_token=${encodeURIComponent(token)}&input=forged`,
        );
        assert.equal(get.status, 404);
        assert.equal(judged(), 0);
        const done = await send(port, '/submit', {
          form: { form_token: token, input: 'bare-code' },
        });
        assert.equal(done.status, 200);
      },
      { logger },
    );
    assert.equal(driven.payload, 'bare-code');
    assert.deepEqual(reasons(), [
      'form-token',
      'form-token',
      'form-token',
      'form-token',
    ]);
    lastPort = driven.port;
  });

  it('the token differs per attempt', async () => {
    const tokens: string[] = [];
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const driven = await drive(
        loopback4({ port: 0 }),
        oauthCode(),
        async ({ port, arm }) => {
          arm();
          const token = formTokenIn((await send(port, '/')).body) ?? '';
          tokens.push(token);
          await send(port, '/submit', {
            form: { form_token: token, input: 'c' },
          });
        },
      );
      lastPort = driven.port;
    }
    assert.notEqual(tokens[0], tokens[1]);
  });

  it('the page carries the protocol’s words, escaped, and posts to /submit', async () => {
    const protocol: Protocol = {
      ...oauthCode(),
      paste: { prompt: 'Paste <b>it</b>:', instructions: 'Go & "find" it' },
    };
    const driven = await drive(
      loopback4({ port: 0 }),
      protocol,
      async ({ port, arm }) => {
        arm();
        const page = await send(port, '/');
        assert.equal(page.headers['content-type'], 'text/html; charset=utf-8');
        contains(page.body, 'Paste &lt;b&gt;it&lt;/b&gt;:');
        contains(page.body, 'Go &amp; &quot;find&quot; it');
        notContains(page.body, '<b>it</b>');
        contains(page.body, '<form action="/submit" method="post">');
        await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
      },
    );
    lastPort = driven.port;
  });
});

describe('the Host check, before any route', () => {
  it('a DNS-rebound Host, another port, none at all: 400, counted, no token, nothing judged', async () => {
    const { logger, reasons } = capturingLogger();
    const driven = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, arm, judged }) => {
        arm();
        let refused = 0;
        for (const host of [
          `attacker.example:${port}`,
          `localhost:${port + 1}`,
          'localhost',
          `0.0.0.0:${port}`,
          `user@localhost:${port}`,
        ]) {
          for (const [path, form] of [
            ['/', undefined],
            [`/callback?code=forged&state=${STATE}`, undefined],
            ['/submit', { form_token: 'x', input: 'forged' }],
            ['/nowhere', undefined],
          ] as const) {
            const reply = await send(port, path, {
              host,
              ...(form === undefined ? {} : { form }),
            });
            assert.deepEqual([host, path, reply.status], [host, path, 400]);
            assert.equal(reply.body, ANSWER_WORDS.host);
            assert.equal(formTokenIn(reply.body), undefined);
            refused += 1;
          }
        }
        assert.equal(judged(), 0);
        assert.deepEqual(
          reasons(),
          Array.from({ length: refused }, () => 'host'),
        );
        await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
      },
      { logger },
    );
    assert.equal(driven.payload, 'the-code');
    lastPort = driven.port;
  });

  it('every spelling the URL parser reads as a loopback authority with the bound port is answered', async () => {
    const driven = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, arm }) => {
        arm();
        for (const host of [
          `LOCALHOST:${port}`,
          `localhost.:${port}`,
          `127.1:${port}`,
          `127.8.9.10:${port}`,
          `[0:0:0:0:0:0:0:1]:${port}`,
          `[::ffff:127.0.0.1]:${port}`,
        ]) {
          const page = await send(port, '/', { host });
          assert.deepEqual([host, page.status], [host, 200]);
        }
        await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
      },
    );
    lastPort = driven.port;
  });

  const withExternal = EXTERNAL ? it : it.skip;
  withExternal(
    'a non-loopback peer sending Host: localhost is refused (the loopback-peer rule)',
    async () => {
      const { logger, reasons } = capturingLogger();
      const driven = await drive(
        loopback4({ port: 0 }),
        oauthCode(),
        async ({ port, arm }) => {
          arm();
          for (const host of [`localhost:${port}`, `127.0.0.1:${port}`]) {
            const page = await send(port, '/', {
              host,
              localAddress: EXTERNAL as string,
            });
            assert.equal(page.status, 400);
            assert.equal(formTokenIn(page.body), undefined);
            const forged = await send(
              port,
              `/callback?code=forged&state=${STATE}`,
              { host, localAddress: EXTERNAL as string },
            );
            assert.equal(forged.status, 400);
          }
          await send(port, `/callback${RIGHT.oauthCode?.redirect}`);
        },
        { logger },
      );
      assert.deepEqual(reasons(), ['host', 'host', 'host', 'host']);
      assert.equal(driven.payload, 'the-code');
      lastPort = driven.port;
    },
  );

  it('every response carries nosniff, the policy and Connection: close', async () => {
    const driven = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, arm }) => {
        // Asked to keep the connection: answered `Connection: close` anyway.
        const keep = { headers: { Connection: 'keep-alive' } };
        const replies = [
          await send(port, '/', keep),
          await send(port, '/nowhere', keep),
        ];
        arm();
        replies.push(await send(port, '/', { host: 'evil.example' }));
        replies.push(await send(port, `/callback${RIGHT.oauthCode?.redirect}`));
        for (const reply of replies) {
          assert.equal(reply.headers['x-content-type-options'], 'nosniff');
          // One answer per connection: nothing pipelined queues behind it.
          assert.equal(reply.headers.connection, 'close');
          contains(
            reply.headers['content-security-policy'],
            "default-src 'none'",
          );
          contains(
            reply.headers['content-security-policy'],
            "form-action 'self'",
          );
        }
      },
    );
    lastPort = driven.port;
  });
});

describe('what an end, a throwing judge and an abort answer', () => {
  it('end: the escaped error page, the wait rejects with the error, the port is free', async () => {
    let port = 0;
    const thrown = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async (driving) => {
        port = driving.port;
        driving.arm();
        const reply = await send(
          driving.port,
          `/callback?state=${STATE}&error=access_denied&error_description=${encodeURIComponent('<script>x</script>')}`,
        );
        assert.equal(reply.status, 400);
        contains(reply.body, 'access_denied: &lt;script&gt;x&lt;/script&gt;');
        notContains(reply.body, '<script>');
      },
    ).catch((error: unknown) => error);
    assert.deepEqual(failureOf(thrown).facts, {
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
    assert.equal(await bindable(port), true);
  });

  for (const [caseIndex, caseRow] of cases([
    [
      'throws',
      (() => {
        throw new Error('judge secret text');
      }) as AnswerJudge<unknown>,
    ],
  ]).entries()) {
    const [_how, judge] = caseRow;
    it(
      caseTitle(
        'a judge that %s: a fixed 500 page, the login fails, no text of it anywhere',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { logger, text } = capturingLogger();
        let port = 0;
        const thrown = await loopback4({ port: 0 })
          .open(
            {
              signal: new AbortController().signal,
              logger,
              paste: undefined,
              callbackMethods: ['GET'],
              endpoint: '/callback',
            },
            async (channel) => {
              port = Number(new URL(channel.redirectUri as string).port);
              const waiting = channel.arm(judge).answer();
              void waiting.catch(() => undefined);
              const reply = await send(port, '/callback?x=1');
              assert.equal(reply.status, 500);
              notContains(reply.body, 'judge secret text');
              await waiting;
            },
          )
          .catch((error: unknown) => error);
        assert.deepEqual(failureOf(thrown).facts, { outcome: 'failed' });
        notContains(String(thrown), 'judge secret text');
        notContains(text(), 'judge secret text');
        assert.equal(await bindable(port), true);
      },
    );
  }

  it('an abort ends the login aborted (browser) with the refused-request count; the port is free', async () => {
    const controller = new AbortController();
    let port = 0;
    const thrown = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async (driving) => {
        port = driving.port;
        driving.arm();
        await send(driving.port, '/callback?code=x&state=wrong');
        await send(driving.port, '/', { host: 'evil.example' });
        controller.abort();
      },
      { signal: controller.signal },
    ).catch((error: unknown) => error);
    assert.deepEqual(failureOf(thrown).facts, {
      outcome: 'aborted',
      strategy: 'browser',
      ignoredCallbacks: 2,
    });
    assert.equal(await bindable(port), true);
  });

  it('an abort ends an open whose use never returns: settled, released, its late settlement discarded', async () => {
    const controller = new AbortController();
    let port = 0;
    let finish: (() => void) | undefined;
    const opened = loopback4({ port: 0 }).open(
      {
        signal: controller.signal,
        callbackMethods: ['GET'],
        endpoint: '/callback',
      },
      async (channel) => {
        port = Number(new URL(channel.redirectUri as string).port);
        await new Promise<void>((resolve) => {
          finish = resolve;
          setImmediate(() => controller.abort());
        });
        return 'late';
      },
    );
    const thrown = await opened.catch((error: unknown) => error);
    matchObject(failureOf(thrown).facts, { outcome: 'aborted' });
    assert.equal(await bindable(port), true);
    finish?.();
  });

  it('an already-aborted signal binds nothing', async () => {
    const controller = new AbortController();
    controller.abort();
    const listen = mock.method(net.Server.prototype, 'listen');
    try {
      const thrown = await loopback4({ port: 0 })
        .open(
          {
            signal: controller.signal,
            callbackMethods: ['GET'],
            endpoint: '/callback',
          },
          async () => 'never',
        )
        .catch((error: unknown) => error);
      assert.deepEqual(failureOf(thrown).facts, {
        outcome: 'aborted',
        strategy: 'browser',
      });
      assert.equal(listen.mock.callCount(), 0);
    } finally {
      listen.mock.restore();
    }
  });

  it('open settles only once released: the port binds the moment it resolves', async () => {
    for (const [, factory, address] of LISTENERS) {
      if (address === '::1' && !(await v6())) continue;
      let port = 0;
      await drive(factory(0), oauthCode(), async (driving) => {
        port = driving.port;
        driving.arm();
        await send(driving.port, `/callback${RIGHT.oauthCode?.redirect}`, {
          address,
        });
      });
      // No turn of the loop in between.
      assert.equal(await bindable(port, address), true);
    }
  });

  it('a channel armed after its open settled is closed: answer() rejects callback-closed', async () => {
    let kept: IAnswerChannel | undefined;
    let port = 0;
    await loopback4({ port: 0 }).open(
      {
        signal: new AbortController().signal,
        callbackMethods: ['GET'],
        endpoint: '/callback',
      },
      async (channel) => {
        kept = channel;
        port = Number(new URL(channel.redirectUri as string).port);
      },
    );
    assert.equal(await bindable(port), true);
    const late = kept
      ?.arm(
        () => ({ verdict: 'accept', payload: 'x' }) as AnswerVerdict<unknown>,
      )
      .answer();
    const thrown = await late?.catch((error: unknown) => error);
    assert.deepEqual(failureOf(thrown).facts, { outcome: 'callback-closed' });
  });
});

describe('nothing of an answer reaches a log line', () => {
  it('no code, state, form token, pasted text, SAMLResponse, URL or IdP text in any line', async () => {
    const { logger, lines, text } = capturingLogger();
    const secrets = [
      STATE,
      'the-secret-code',
      'pasted-secret-text',
      'SAMLsecretPayload',
      'idp-secret-description',
      'idp.example',
    ];
    let token = '';
    const thrown = await drive(
      loopback4({ port: 0 }),
      oauthCode(),
      async ({ port, arm }) => {
        await send(port, `/callback?code=the-secret-code&state=${STATE}`);
        arm();
        token = formTokenIn((await send(port, '/')).body) ?? '';
        await send(port, '/submit', {
          form: { form_token: 'x', input: 'pasted-secret-text' },
        });
        await send(port, '/submit', {
          form: {
            form_token: token,
            input: `http://localhost/callback?code=the-secret-code&state=pasted-secret-text`,
          },
        });
        await send(port, '/callback?SAMLResponse=SAMLsecretPayload');
        await send(port, `/callback?code=the-secret-code&state=wrong`, {
          host: 'idp.example',
        });
        await send(
          port,
          `/callback?state=${STATE}&error=access_denied&error_description=idp-secret-description`,
        );
      },
      { logger },
    ).catch((error: unknown) => error);
    matchObject(failureOf(thrown).facts, {
      outcome: 'identity-provider-refused',
    });
    assert.ok(lines.length > 0, `${lines.length} > ${0}`);
    for (const secret of [...secrets, token]) {
      notContains(text(), secret);
    }
  });
});

// The type of a listener's own options, as the contract describes them.
const _typed: AnswerTransportOptions['callbackMethods'] = ['GET', 'POST'];
void _typed;
const _answer: AuthorizationAnswer = { via: 'form', text: '' };
void _answer;
