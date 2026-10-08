/**
 * The named compositions (spec §6d.7): each keeps today's name and options
 * and composes the parts the table names — checked by what each does on a
 * real port or an injected reader: the presentation (where the URL goes),
 * the transport (what it binds and advertises, what it reads), the protocol
 * (what it accepts). The manual and external ones require `redirectUri`
 * (C4); `manualPasscodeStrategy` takes none.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
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
import { bindable, capturingLogger, send } from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';

const STATE = 'named-state_abcdefghijklmnopqrstuvwxyz012345';
const REGISTERED = 'https://app.example/registered/callback';

const factsOf = (error: unknown) =>
  readFailure(error, 'browser-login').facts as Record<string, unknown>;

let stderr: string[];
beforeEach(() => {
  stderr = [];
  jest.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    stderr.push(String(chunk));
    return true;
  });
  jest.spyOn(process.stdout, 'write').mockImplementation(() => {
    throw new Error('nothing writes to stdout');
  });
});
afterEach(() => {
  jest.restoreAllMocks();
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
  it.each([
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
  ] as const)(
    '%s binds loopback on its port, advertises localhost, shows the URL on stderr, accepts its protocol’s answer',
    async (_name, make, path, payload) => {
      const port = await getAvailablePort();
      const strategy = make(port) as IAuthorizationStrategy<unknown>;
      const { request, redirects } = recordingRequest();
      const login = strategy.authorize(request);
      await waitFor(() => send(port, '/nothing'));
      await quiet();
      expect(redirects).toEqual([`http://localhost:${port}/callback`]);
      expect(stderr.join('')).toContain('https://idp.example/authorize');
      // A redirect to localhost reaches ::1 too, when the machine has it.
      expect((await send(port, path)).status).toBe(200);
      await expect(login).resolves.toEqual({
        payload,
        redirectUri: `http://localhost:${port}/callback`,
      });
      expect(await bindable(port)).toBe(true);
    },
  );

  it('browserCallbackStrategy refuses a callback without this login’s state (oauthCode)', async () => {
    const port = await getAvailablePort();
    const strategy = browserCallbackStrategy({ port });
    const login = strategy.authorize(recordingRequest().request);
    expect((await waitFor(() => send(port, '/callback?code=EVIL'))).status).toBe(
      400,
    );
    await strategy.dispose?.();
    expect(factsOf(await login.catch((e: unknown) => e)).outcome).toBe(
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
    expect(redirects).toEqual([
      `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`,
    ]);
    await strategy.dispose?.();
    await login.catch(() => undefined);
  });

  it.each(['none', 'headless', undefined])(
    'browser %s shows the URL (showUrl)',
    async (browser) => {
      const port = await getAvailablePort();
      const { logger, lines } = capturingLogger();
      const strategy = browserCallbackStrategy({ port, browser });
      const login = strategy.authorize(recordingRequest({ logger }).request);
      await waitFor(() => send(port, '/nothing'));
      await quiet();
      expect(stderr.join('')).toContain('https://idp.example/authorize');
      expect(lines.map((line) => line.message)).toContain(
        'the authorization URL was shown',
      );
      await strategy.dispose?.();
      await login.catch(() => undefined);
    },
  );

  it('openUrl is the consumer’s presentation: called with the URL, the browser and the bound redirect; nothing printed', async () => {
    const port = await getAvailablePort();
    const calls: unknown[][] = [];
    const strategy = browserCallbackStrategy({
      port,
      browser: 'system',
      openUrl: async (...args) => {
        calls.push(args);
      },
    });
    const login = strategy.authorize(recordingRequest().request);
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    expect(calls).toEqual([
      [
        expect.stringContaining('https://idp.example/authorize'),
        'system',
        `http://localhost:${port}/callback`,
      ],
    ]);
    expect(stderr.join('')).toBe('');
    await strategy.dispose?.();
    await login.catch(() => undefined);
  });

  it('remoteHint replaces the channel’s route hint, built from the bound redirect', async () => {
    const port = await getAvailablePort();
    const { logger, lines } = capturingLogger();
    const strategy = browserCallbackStrategy({
      port,
      remoteHint: (redirectUri) => `go through the bastion to ${redirectUri.length}`,
    });
    const login = strategy.authorize(recordingRequest({ logger }).request);
    await waitFor(() => send(port, '/nothing'));
    await quiet();
    const messages = lines.map((line) => line.message);
    expect(messages).toContain(
      `go through the bastion to ${`http://localhost:${port}/callback`.length}`,
    );
    expect(messages.some((m) => m.includes('ssh -L'))).toBe(false);
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
    expect(
      lines.some((line) =>
        line.message.includes(`ssh -L ${port}:localhost:${port}`),
      ),
    ).toBe(true);
    await strategy.dispose?.();
    await login.catch(() => undefined);
  });

  it.each([-1, 65536, 1.5])('a port of %p is callback-port-invalid at construction', (port) => {
    expect(factsOf(thrownBy(() => browserCallbackStrategy({ port })))).toEqual({
      case: 'callback-port-invalid',
      fields: ['port'],
    });
  });

  it('an unknown browser is refused at construction; edge is msedge', () => {
    expect(
      factsOf(thrownBy(() => browserCallbackStrategy({ browser: 'lynx' }))),
    ).toEqual({ case: 'invalid-value', fields: ['presentation'] });
    expect(thrownBy(() => browserCallbackStrategy({ browser: 'edge' }))).toBe(
      undefined,
    );
  });
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
    await expect(strategy.authorize(request)).resolves.toEqual({
      payload: 'C5',
      redirectUri: REGISTERED,
    });
    expect(redirects).toEqual([REGISTERED]);
    expect(prompts).toHaveLength(2);
    expect(stderr.join('')).toContain('https://idp.example/authorize');
  });

  it('manualSamlResponseStrategy: the ACS, a pasted SAMLResponse (samlResponse)', async () => {
    const strategy = manualSamlResponseStrategy({
      redirectUri: REGISTERED,
      read: async () => '  PHNhbWw+  ',
    });
    await expect(
      strategy.authorize(recordingRequest().request),
    ).resolves.toEqual({ payload: 'PHNhbWw+', redirectUri: REGISTERED });
  });

  it('manualPasscodeStrategy: no redirect, a pasted passcode (passcode)', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => ' 123456 ' });
    const { request, redirects } = recordingRequest();
    await expect(strategy.authorize(request)).resolves.toEqual({
      payload: '123456',
      redirectUri: '',
    });
    expect(redirects).toEqual(['']);
  });

  it.each([
    ['manualPasteStrategy', () => manualPasteStrategy({} as never)],
    [
      'manualSamlResponseStrategy',
      () => manualSamlResponseStrategy({} as never),
    ],
    [
      'externalCodeStrategy',
      () => externalCodeStrategy({ provide: async () => 'c' } as never),
    ],
  ])('%s without redirectUri: required-fields-missing redirectUri at construction (C4)', (_name, make) => {
    expect(factsOf(thrownBy(make))).toEqual({
      case: 'required-fields-missing',
      fields: ['redirectUri'],
    });
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
    expect(
      factsOf(await strategy.authorize(recordingRequest().request).catch((e: unknown) => e)),
    ).toEqual({ outcome: 'busy' });
    await strategy.dispose?.();
    expect(factsOf(await first.catch((e: unknown) => e))).toEqual({
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
    await expect(
      strategy.authorize(recordingRequest().request),
    ).resolves.toEqual({ payload: 'C7', redirectUri: REGISTERED });
    expect(seen).toEqual([
      `https://idp.example/authorize?redirect_uri=${encodeURIComponent(REGISTERED)}&state=${STATE}`,
    ]);
    expect(stderr.join('')).toBe('');
  });

  it('externalCodeStrategy: an empty code is no-input; no provide is required-fields-missing provide', async () => {
    const strategy = externalCodeStrategy({
      redirectUri: REGISTERED,
      provide: async () => '',
    });
    expect(
      factsOf(await strategy.authorize(recordingRequest().request).catch((e: unknown) => e)),
    ).toEqual({ outcome: 'no-input' });
    expect(
      factsOf(thrownBy(() => externalCodeStrategy({ redirectUri: REGISTERED } as never))),
    ).toEqual({ case: 'required-fields-missing', fields: ['provide'] });
  });

  it('staticCodeStrategy never calls the builder and keeps its default redirect', async () => {
    const { request, redirects } = recordingRequest();
    await expect(
      staticCodeStrategy({ payload: 'held' }).authorize(request),
    ).resolves.toEqual({
      payload: 'held',
      redirectUri: `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`,
    });
    expect(redirects).toEqual([]);
  });
});
