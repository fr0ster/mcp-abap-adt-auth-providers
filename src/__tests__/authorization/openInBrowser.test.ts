/**
 * `openInBrowser` failing (spec §6d.5, Task 30h generalised, C8): the
 * default launcher that fails — `open` rejecting for a named browser, or
 * for `auto` — prompts the URL once, to stderr only; one log line in fixed
 * words; the login keeps waiting on the same port and a callback then
 * finishes it. `open` is mocked: no browser opens.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';

const openMock = jest.fn(async (_url: string, _opts?: unknown) => {
  throw Object.assign(new Error('spawn SECRET-PATH'), { code: 'ENOENT' });
});
jest.mock('open', () => ({
  __esModule: true,
  default: (url: string, opts?: unknown) => openMock(url, opts),
}));

import { composeAuthorization } from '../../authorization/compose';
import { openInBrowser } from '../../authorization/presentation';
import { oauthCode } from '../../authorization/protocol';
import { loopback4 } from '../../authorization/transport';
import { bindable, capturingLogger, send } from '../helpers/listenerHttp';
import { getAvailablePort } from '../helpers/netHelpers';

const STATE = 'browser-state_abcdefghijklmnopqrstuvwxyz0123';
const urlFor = (redirectUri: string) =>
  `https://idp.example/oauth/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;

let stderr: string[];
let stdout: string[];
beforeEach(() => {
  stderr = [];
  stdout = [];
  openMock.mockClear();
  jest.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    stderr.push(String(chunk));
    return true;
  });
  jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    stdout.push(String(chunk));
    return true;
  });
});
afterEach(() => {
  jest.restoreAllMocks();
  expect(stdout).toEqual([]);
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

const occurrences = (text: string, part: string) =>
  text.split(part).length - 1;

describe('the default launcher failing', () => {
  it.each([
    [
      'a named browser whose open rejects',
      'chrome',
      [
        'error',
        'Failed to present the authorization URL: presenting the authorization URL failed (unknown error, ENOENT)',
      ],
    ],
    [
      'auto, whose open rejects',
      'auto',
      [
        'warn',
        '⚠️  Could not open browser automatically: opening the browser failed (unknown error, ENOENT)',
      ],
    ],
  ] as const)(
    '%s: the URL prompted once on stderr, one failure line, the login waiting; a callback finishes it',
    async (_name, browser, failureLine) => {
      const port = await getAvailablePort();
      const { logger, lines, text } = capturingLogger();
      const login = composeAuthorization({
        presentation: openInBrowser({ browser }),
        transport: loopback4({ port }),
        protocol: oauthCode(),
        endpoint: '/callback',
      }).authorize(request({ logger }));
      expect(await stillWaiting(login)).toBe(true);
      expect(openMock).toHaveBeenCalledTimes(1);
      const redirect = `http://127.0.0.1:${port}/callback`;
      expect(occurrences(stderr.join(''), urlFor(redirect))).toBe(1);
      const failures = lines.filter(
        (line) => line.level === 'error' || line.level === 'warn',
      );
      expect(failures.map((line) => [line.level, line.message])).toEqual([
        failureLine,
      ]);
      expect(lines.map((line) => line.message)).toContain(
        'the authorization URL was shown',
      );
      expect(text()).not.toContain('idp.example');
      expect(text()).not.toContain(STATE);
      expect(text()).not.toContain('SECRET-PATH');
      expect(stderr.join('')).not.toContain('SECRET-PATH');
      expect(
        (await send(port, `/callback?code=C3&state=${STATE}`)).status,
      ).toBe(200);
      await expect(login).resolves.toMatchObject({ payload: 'C3' });
      expect(await bindable(port)).toBe(true);
    },
  );

  it('the signal then ends it aborted and the port is free; the IdP’s ?error= ends it refused', async () => {
    const port = await getAvailablePort();
    const controller = new AbortController();
    const strategy = composeAuthorization({
      presentation: openInBrowser({ browser: 'chrome' }),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    const first = strategy
      .authorize(request({ signal: controller.signal }))
      .catch((e: unknown) => e);
    expect(await stillWaiting(first)).toBe(true);
    controller.abort();
    expect(readFailure(await first, 'browser-login').facts).toEqual({
      outcome: 'aborted',
      strategy: 'browser',
    });
    expect(await bindable(port)).toBe(true);

    const second = strategy.authorize(request()).catch((e: unknown) => e);
    expect(await stillWaiting(second)).toBe(true);
    await send(port, `/callback?error=access_denied&state=${STATE}`);
    expect(readFailure(await second, 'browser-login').facts).toEqual({
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
  });

  it('a launcher that fails after the login ended prompts nothing', async () => {
    const port = await getAvailablePort();
    let rejectOpen!: (error: Error) => void;
    openMock.mockImplementationOnce(
      () =>
        new Promise((_resolve, reject) => {
          rejectOpen = reject;
        }),
    );
    const { logger, lines } = capturingLogger();
    const login = composeAuthorization({
      presentation: openInBrowser({ browser: 'chrome' }),
      transport: loopback4({ port }),
      protocol: oauthCode(),
      endpoint: '/callback',
    }).authorize(request({ logger }));
    expect(await stillWaiting(login)).toBe(true);
    await send(port, `/callback?code=C4&state=${STATE}`);
    await login;
    rejectOpen(new Error('late'));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(stderr.join('')).not.toContain('idp.example');
    expect(
      lines.filter((line) => line.level === 'error' || line.level === 'warn'),
    ).toEqual([]);
  });
});
