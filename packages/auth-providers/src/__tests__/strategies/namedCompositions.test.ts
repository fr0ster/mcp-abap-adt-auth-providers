/**
 * The named compositions: each keeps today's name and options and composes the
 * parts the table names — checked by what each does on a real port or an
 * injected reader: the presentation (where the URL goes), the transport (what
 * it binds and advertises, what it reads), the protocol (what it accepts). The
 * manual and external ones require `redirectUri`; `manualPasscodeStrategy`
 * takes none.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import {
  browserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  externalCodeStrategy,
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
  staticCodeStrategy,
} from '../../strategies';
import { quiet } from '../helpers/attemptHarness';
import {
  anyOf,
  caseTitle,
  contains,
  deepEqualWith,
} from '../helpers/expectations';
import { bindable, capturingLogger, send } from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';
import { recordingBrowser } from '../helpers/recordingBrowser';
import { watchStdout } from '../helpers/stdoutWrites';

const STATE = 'named-state_abcdefghijklmnopqrstuvwxyz012345';
const REGISTERED = 'https://app.example/registered/callback';

const factsOf = (error: unknown) =>
  readFailure(error, 'browser-login').facts as Record<string, unknown>;

let stderr: string[];
beforeEach(() => {
  stderr = [];
  mock.method(process.stderr, 'write', (chunk: unknown) => {
    stderr.push(String(chunk));
    return true;
  });
  watchStdout(() => {
    throw new Error('nothing writes to stdout');
  });
});
afterEach(() => {
  mock.restoreAll();
});

function recordingRequest(overrides: Partial<AuthorizationRequest> = {}): {
  request: AuthorizationRequest;
  redirects: string[];
} {
  const redirects: string[] = [];
  return {
    redirects,
    request: {
      buildAuthorizationUrl: async (redirectUri) => {
        redirects.push(redirectUri);
        return `https://idp.example/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;
      },
      ...overrides,
    },
  };
}

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

function thrownBy(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe('the browser compositions: loopback, showUrl by default', () => {
  for (const [caseIndex, caseRow] of (
    [
      [
        'browserCallbackStrategy',
        (port: number) => browserCallbackStrategy({ port }),
        `/callback?code=C1&state=${STATE}`,
        'C1',
      ],
      [
        'oidcCallbackStrategy',
        (port: number) => oidcCallbackStrategy({ port }),
        `/callback?code=C2&state=${STATE}`,
        { code: 'C2', state: STATE },
      ],
      [
        'samlCallbackStrategy',
        (port: number) => samlCallbackStrategy({ port }),
        '/callback?SAMLResponse=PHNhbWw%2B',
        'PHNhbWw+',
      ],
    ] as const
  ).entries()) {
    const [_name, make, path, payload] = caseRow;
    it(
      caseTitle(
        '%s binds loopback on its port, advertises localhost, shows the URL on stderr, accepts its protocol’s answer',
        caseRow,
        caseIndex,
      ),
      async () => {
        const port = await getAvailablePort();
        const strategy = make(port) as IAuthorizationStrategy<unknown>;
        const { request, redirects } = recordingRequest();
        const login = strategy.authorize(request);
        await waitFor(() => send(port, '/nothing'));
        await quiet();
        assert.deepEqual(redirects, [`http://localhost:${port}/callback`]);
        contains(stderr.join(''), 'https://idp.example/authorize');
        // A redirect to localhost reaches ::1 too, when the machine has it.
        assert.equal((await send(port, path)).status, 200);
        assert.deepEqual(await login, {
          payload,
          redirectUri: `http://localhost:${port}/callback`,
        });
        assert.equal(await bindable(port), true);
      },
    );
  }

  it('browserCallbackStrategy refuses a callback without this login’s state (oauthCode)', async () => {
    const port = await getAvailablePort();
    const strategy = browserCallbackStrategy({ port });
    const login = strategy.authorize(recordingRequest().request);
    assert.equal(
      (await waitFor(() => send(port, '/callback?code=EVIL'))).status,
      400,
    );
    await strategy.dispose?.();
    assert.equal(
      factsOf(await login.catch((e: unknown) => e)).outcome,
      'disposed',
    );
  });

  it(`the default port is DEFAULT_CALLBACK_PORT (${DEFAULT_CALLBACK_PORT})`, async () => {
    if (!(await bindable(DEFAULT_CALLBACK_PORT))) {
      // Runs where the port is free; elsewhere a login of this machine holds it.
      return;
    }
    const { request, redirects } = recordingRequest();
    const strategy = browserCallbackStrategy();
    const login = strategy.authorize(request);
    await waitFor(() => send(DEFAULT_CALLBACK_PORT, '/nothing'));
    assert.deepEqual(redirects, [
      `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`,
    ]);
    await strategy.dispose?.();
    await login.catch(() => undefined);
  });

  it('without browser the URL is shown (showUrl)', async () => {
    const port = await getAvailablePort();
    const { logger, lines } = capturingLogger();
    const strategy = browserCallbackStrategy({ port });
    const login = strategy.authorize(recordingRequest({ logger }).request);
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    contains(stderr.join(''), 'https://idp.example/authorize');
    contains(
      lines.map((line) => line.message),
      'the authorization URL was shown',
    );
    await strategy.dispose?.();
    await login.catch(() => undefined);
  });

  for (const [caseIndex, caseRow] of (
    [
      ['browserCallbackStrategy', browserCallbackStrategy],
      ['oidcCallbackStrategy', oidcCallbackStrategy],
      ['samlCallbackStrategy', samlCallbackStrategy],
    ] as const
  ).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: the browser given is used — exactly the URL, the login’s signal; nothing printed',
        caseRow,
        caseIndex,
      ),
      async () => {
        const port = await getAvailablePort();
        const browser = recordingBrowser();
        const urls: string[] = [];
        const strategy = make({ port, browser });
        const login = strategy.authorize(
          recordingRequest({
            buildAuthorizationUrl: async (redirectUri) => {
              const url = `https://idp.example/authorize?redirect_uri=${redirectUri}&state=${STATE}`;
              urls.push(url);
              return url;
            },
          }).request,
        );
        await waitFor(() => send(port, '/nothing'));
        await quiet();
        assert.equal(urls.length, 1);
        deepEqualWith(browser.calls, [
          { url: urls[0], signal: anyOf(AbortSignal) },
        ]);
        assert.equal(stderr.join(''), '');
        await strategy.dispose?.();
        await login.catch(() => undefined);
      },
    );
  }

  it('remoteHint replaces the channel’s route hint, built from the bound redirect', async () => {
    const port = await getAvailablePort();
    const { logger, lines } = capturingLogger();
    const strategy = browserCallbackStrategy({
      port,
      remoteHint: (redirectUri) =>
        `go through the bastion to ${redirectUri.length}`,
    });
    const login = strategy.authorize(recordingRequest({ logger }).request);
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    const messages = lines.map((line) => line.message);
    contains(
      messages,
      `go through the bastion to ${`http://localhost:${port}/callback`.length}`,
    );
    assert.equal(
      messages.some((m) => m.includes('ssh -L')),
      false,
    );
    await strategy.dispose?.();
    await login.catch(() => undefined);
  });

  it('without remoteHint the shipped listener names the SSH tunnel to localhost', async () => {
    const port = await getAvailablePort();
    const { logger, lines } = capturingLogger();
    const strategy = browserCallbackStrategy({ port });
    const login = strategy.authorize(recordingRequest({ logger }).request);
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    assert.equal(
      lines.some((line) =>
        line.message.includes(`ssh -L ${port}:localhost:${port}`),
      ),
      true,
    );
    await strategy.dispose?.();
    await login.catch(() => undefined);
  });

  for (const [caseIndex, caseRow] of [-1, 65536, 1.5].entries()) {
    const port = caseRow;
    it(
      caseTitle(
        'a port of %p is callback-port-invalid at construction',
        caseRow,
        caseIndex,
      ),
      () => {
        assert.deepEqual(
          factsOf(thrownBy(() => browserCallbackStrategy({ port }))),
          {
            case: 'callback-port-invalid',
            fields: ['port'],
          },
        );
      },
    );
  }
});

describe('the terminal compositions: showUrl, terminalPaste', () => {
  it('manualPasteStrategy: the consumer’s redirect, a pasted code (oauthCode)', async () => {
    const prompts: string[] = [];
    const strategy = manualPasteStrategy({
      redirectUri: REGISTERED,
      read: async (prompt) => {
        prompts.push(prompt);
        return prompts.length === 1
          ? `${REGISTERED}?code=WRONG&state=other`
          : `${REGISTERED}?code=C5&state=${STATE}`;
      },
    });
    const { request, redirects } = recordingRequest();
    assert.deepEqual(await strategy.authorize(request), {
      payload: 'C5',
      redirectUri: REGISTERED,
    });
    assert.deepEqual(redirects, [REGISTERED]);
    assert.equal(prompts.length, 2);
    contains(stderr.join(''), 'https://idp.example/authorize');
  });

  it('manualSamlResponseStrategy: the ACS, a pasted SAMLResponse (samlResponse)', async () => {
    const strategy = manualSamlResponseStrategy({
      redirectUri: REGISTERED,
      read: async () => '  PHNhbWw+  ',
    });
    assert.deepEqual(await strategy.authorize(recordingRequest().request), {
      payload: 'PHNhbWw+',
      redirectUri: REGISTERED,
    });
  });

  it('manualPasscodeStrategy: no redirect, a pasted passcode (passcode)', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => ' 123456 ' });
    const { request, redirects } = recordingRequest();
    assert.deepEqual(await strategy.authorize(request), {
      payload: '123456',
      redirectUri: '',
    });
    assert.deepEqual(redirects, ['']);
  });

  it('a second authorize while one reads is busy', async () => {
    const strategy = manualPasteStrategy({
      redirectUri: REGISTERED,
      read: (_prompt, signal) =>
        new Promise((_resolve, reject) =>
          signal.addEventListener('abort', () => reject(new Error('gone'))),
        ),
    });
    const first = strategy.authorize(recordingRequest().request);
    await quiet();
    assert.deepEqual(
      factsOf(
        await strategy
          .authorize(recordingRequest().request)
          .catch((e: unknown) => e),
      ),
      { outcome: 'busy' },
    );
    await strategy.dispose?.();
    assert.deepEqual(factsOf(await first.catch((e: unknown) => e)), {
      outcome: 'disposed',
      strategy: 'manual',
    });
  });
});

describe('the consumer’s code: externalCodeStrategy, staticCodeStrategy', () => {
  it('externalCodeStrategy hands provide the URL and returns its code verbatim', async () => {
    const seen: string[] = [];
    const strategy = externalCodeStrategy({
      redirectUri: REGISTERED,
      provide: async (url) => {
        seen.push(url);
        return 'C7';
      },
    });
    assert.deepEqual(await strategy.authorize(recordingRequest().request), {
      payload: 'C7',
      redirectUri: REGISTERED,
    });
    assert.deepEqual(seen, [
      `https://idp.example/authorize?redirect_uri=${encodeURIComponent(REGISTERED)}&state=${STATE}`,
    ]);
    assert.equal(stderr.join(''), '');
  });

  it('externalCodeStrategy: an empty code is no-input', async () => {
    const strategy = externalCodeStrategy({
      redirectUri: REGISTERED,
      provide: async () => '',
    });
    assert.deepEqual(
      factsOf(
        await strategy
          .authorize(recordingRequest().request)
          .catch((e: unknown) => e),
      ),
      { outcome: 'no-input' },
    );
  });

  it('staticCodeStrategy never calls the builder and keeps its default redirect', async () => {
    const { request, redirects } = recordingRequest();
    assert.deepEqual(
      await staticCodeStrategy({ payload: 'held' }).authorize(request),
      {
        payload: 'held',
        redirectUri: `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`,
      },
    );
    assert.deepEqual(redirects, []);
  });
});
