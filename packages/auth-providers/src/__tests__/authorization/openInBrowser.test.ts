/**
 * `openInBrowser({ browser })`: `browser` is an
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

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  IBrowser,
} from '@mcp-abap-adt/interfaces-auth';
import { composeAuthorization } from '../../authorization/compose';
import { openInBrowser } from '../../authorization/presentation';
import { oauthCode } from '../../authorization/protocol';
import { loopback4 } from '../../authorization/transport';
import {
  caseTitle,
  contains,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { bindable, capturingLogger, send } from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';
import { recordingBrowser } from '../helpers/recordingBrowser';
import { watchStdout } from '../helpers/stdoutWrites';

const STATE = 'browser-state_abcdefghijklmnopqrstuvwxyz0123';
const urlFor = (redirectUri: string) =>
  `https://idp.example/oauth/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;

let stderr: string[];
let stdout: string[];
beforeEach(() => {
  stderr = [];
  stdout = [];
  mock.method(process.stderr, 'write', (chunk: unknown) => {
    stderr.push(String(chunk));
    return true;
  });
  watchStdout((text) => {
    stdout.push(text);
  });
});
afterEach(() => {
  mock.restoreAll();
  assert.deepEqual(stdout, []);
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
    assert.equal(await stillWaiting(login), true);
    const redirect = `http://127.0.0.1:${port}/callback`;
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.self, browser);
    assert.equal(calls[0]?.url, raw(redirect));
    assert.ok(calls[0]?.signal instanceof AbortSignal);
    assert.equal(calls[0]?.signal.aborted, false);
    assert.equal(stderr.join(''), '');
    await send(port, `/callback?code=C1&state=${STATE}`);
    matchObject(await login, { payload: 'C1' });
    // The signal tells the browser the login has ended.
    assert.equal(calls[0]?.signal.aborted, true);
  });
});

describe('a browser that fails is a presentation failure', () => {
  for (const [caseIndex, caseRow] of (
    [
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
      [
        'answers a thenable whose then getter throws',
        {
          open: () => ({
            // biome-ignore lint/suspicious/noThenProperty: the hostile answer under test
            get then(): never {
              throw Object.assign(new Error(`SECRET-PATH ${STATE}`), {
                code: 'ENOENT',
              });
            },
          }),
        } as unknown as IBrowser,
      ],
      [
        'answers a Proxy whose trap throws',
        {
          open: () =>
            new Proxy(
              {},
              {
                get: () => {
                  throw Object.assign(new Error(`SECRET-PATH ${STATE}`), {
                    code: 'ENOENT',
                  });
                },
              },
            ),
        } as unknown as IBrowser,
      ],
    ] as const
  ).entries()) {
    const [_name, browser] = caseRow;
    it(
      caseTitle(
        'a browser that %s: the URL prompted once on stderr, one failure line, the login waiting; a callback finishes it',
        caseRow,
        caseIndex,
      ),
      async () => {
        const port = await getAvailablePort();
        const { logger, lines, text } = capturingLogger();
        const login = composeAuthorization({
          presentation: openInBrowser({ browser }),
          transport: loopback4({ port }),
          protocol: oauthCode(),
          endpoint: '/callback',
        }).authorize(request({ logger }));
        assert.equal(await stillWaiting(login), true);
        const redirect = `http://127.0.0.1:${port}/callback`;
        assert.equal(occurrences(stderr.join(''), urlFor(redirect)), 1);
        const failures = lines.filter(
          (line) => line.level === 'error' || line.level === 'warn',
        );
        assert.deepEqual(
          failures.map((line) => [line.level, line.message]),
          [
            [
              'error',
              'Failed to present the authorization URL: presenting the authorization URL failed (unknown error, ENOENT)',
            ],
          ],
        );
        contains(
          lines.map((line) => line.message),
          'the authorization URL was shown',
        );
        notContains(text(), 'idp.example');
        notContains(text(), STATE);
        notContains(text(), 'SECRET-PATH');
        notContains(stderr.join(''), 'SECRET-PATH');
        assert.equal(
          (await send(port, `/callback?code=C3&state=${STATE}`)).status,
          200,
        );
        matchObject(await login, { payload: 'C3' });
        assert.equal(await bindable(port), true);
      },
    );
  }

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
    assert.equal(await stillWaiting(first), true);
    controller.abort();
    assert.deepEqual(factsOf(await first), {
      outcome: 'aborted',
      strategy: 'browser',
    });
    assert.equal(await bindable(port), true);

    const second = strategy.authorize(request()).catch((e: unknown) => e);
    assert.equal(await stillWaiting(second), true);
    await send(port, `/callback?error=access_denied&state=${STATE}`);
    assert.deepEqual(factsOf(await second), {
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
    assert.equal(await stillWaiting(login), true);
    await send(port, `/callback?code=C4&state=${STATE}`);
    await login;
    rejectOpen(Object.assign(new Error('late'), { code: 'ENOENT' }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    notContains(stderr.join(''), 'idp.example');
    assert.deepEqual(
      lines.filter((line) => line.level === 'error' || line.level === 'warn'),
      [],
    );
  });
});
