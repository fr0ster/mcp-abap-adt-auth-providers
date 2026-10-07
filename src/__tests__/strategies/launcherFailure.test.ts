/**
 * Task 30h (spec §6a0, "A launcher that fails does not end the login"): where
 * no browser can be opened (SSH, a host without a desktop) the authorization
 * URL the user is shown is the only way to finish the login, so it must still
 * be live when shown. A launcher that throws, or whose answer rejects, is
 * logged in fixed words and prompted once; the callback keeps listening on
 * the same port with this attempt's own state, and the login ends on its
 * result, the IdP's refusal or the consumer's signal — no timer.
 * Real callback ports throughout; `open` is mocked, so no browser opens.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';

const openMock = jest.fn(async (_url: string, _opts?: unknown) => {
  throw Object.assign(new Error('spawn SECRET-PATH'), { code: 'ENOENT' });
});
jest.mock('open', () => ({
  __esModule: true,
  default: (url: string, opts?: unknown) => openMock(url, opts),
}));

import {
  browserCallbackStrategy,
  oidcCallbackStrategy,
} from '../../strategies/BrowserCallbackStrategy';

const PORT = 7882;
const URL_SHOWN = 'https://idp.example/authorize?state=S1';

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

/** What a browser does with the redirect: one GET to the callback. */
function callback(query: string): Promise<number | undefined> {
  return new Promise((resolve) => {
    const req = http.get(
      {
        host: '127.0.0.1',
        port: PORT,
        agent: false,
        path: `/callback?${query}`,
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      },
    );
    req.on('error', () => resolve(undefined));
  });
}

const settled = async (promise: Promise<unknown>) => {
  const state: { done: boolean } = { done: false };
  promise.then(
    () => {
      state.done = true;
    },
    () => {
      state.done = true;
    },
  );
  // Long enough for a login that wrongly ended to have ended.
  await new Promise((resolve) => setTimeout(resolve, 300));
  return state.done;
};

function recorder() {
  const errors: unknown[][] = [];
  const prompts: unknown[][] = [];
  const logger: ILogger = {
    debug: () => undefined,
    info: (...args: unknown[]) => {
      prompts.push(args);
    },
    warn: () => undefined,
    error: (...args: unknown[]) => {
      errors.push(args);
    },
  };
  return { errors, prompts, logger };
}

const request = (logger: ILogger, signal?: AbortSignal): AuthorizationRequest =>
  ({
    buildAuthorizationUrl: async () => URL_SHOWN,
    logger,
    ...(signal ? { signal } : {}),
  }) as AuthorizationRequest;

const THROWS = () => {
  throw Object.assign(new Error('spawn SECRET-PATH'), { code: 'ENOENT' });
};
const REJECTS = async () => {
  throw Object.assign(new Error('spawn SECRET-PATH'), { code: 'ENOENT' });
};

const PROMPT = [
  ['🔗 The browser could not be opened. The authorization URL:'],
  [`   ${URL_SHOWN}`],
  [`   Waiting for callback on http://localhost:${PORT}/callback ...`],
];
const LINE =
  'Failed to open browser: opening the browser failed (unknown error, ENOENT)';

afterEach(async () => {
  openMock.mockClear();
  expect(await portIsFree(PORT)).toBe(true);
});

describe.each([
  ['throws', THROWS],
  ['answers a rejection', REJECTS],
] as const)('a launcher that %s', (_name, openUrl) => {
  it('is logged once in fixed words, the URL prompted once, the login waiting; the callback then finishes it', async () => {
    const { errors, prompts, logger } = recorder();
    const login = browserCallbackStrategy({ port: PORT, openUrl }).authorize(
      request(logger),
    );
    expect(await settled(login)).toBe(false);
    expect(errors.map((e) => e[0])).toEqual([LINE]);
    expect(JSON.stringify(errors)).not.toContain('SECRET-PATH');
    expect(JSON.stringify(errors)).not.toContain('idp.example');
    expect(prompts).toEqual(PROMPT);
    // The port is still listening: this attempt's redirect is live.
    expect(await portIsFree(PORT)).toBe(false);
    expect(await callback('code=C1&state=S1')).toBe(200);
    expect((await login).payload).toBe('C1');
  });

  it('OIDC: the callback with the right state finishes it with that code and state', async () => {
    const { logger } = recorder();
    const login = oidcCallbackStrategy({ port: PORT, openUrl }).authorize(
      request(logger),
    );
    expect(await settled(login)).toBe(false);
    expect(await callback('code=C2&state=S1')).toBe(200);
    expect((await login).payload).toEqual({ code: 'C2', state: 'S1' });
  });

  it('the consumer’s signal aborts it → aborted, and the port is free', async () => {
    const { prompts, logger } = recorder();
    const controller = new AbortController();
    const login = browserCallbackStrategy({ port: PORT, openUrl }).authorize(
      request(logger, controller.signal),
    );
    const rejected = login.then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(await settled(login)).toBe(false);
    expect(prompts).toEqual(PROMPT);
    controller.abort();
    const thrown = await rejected;
    expect(readFailure(thrown, 'browser-login').facts).toEqual({
      outcome: 'aborted',
      strategy: 'browser',
    });
    expect(await portIsFree(PORT)).toBe(true);
  });

  it('the IdP’s ?error= → identity-provider-refused', async () => {
    const { prompts, logger } = recorder();
    const login = browserCallbackStrategy({ port: PORT, openUrl }).authorize(
      request(logger),
    );
    const rejected = login.then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(await settled(login)).toBe(false);
    expect(prompts).toEqual(PROMPT);
    await callback('error=access_denied');
    expect(readFailure(await rejected, 'browser-login').facts).toEqual({
      outcome: 'identity-provider-refused',
      oauthError: 'access_denied',
    });
  });
});

describe('the default launcher failing', () => {
  it.each([
    ['a named browser whose open rejects', 'chrome'],
    ['auto, whose open rejects', 'auto'],
  ] as const)(
    '%s prompts the URL once, not twice, and the login waits',
    async (_name, browser) => {
      const { prompts, logger } = recorder();
      const login = browserCallbackStrategy({ port: PORT, browser }).authorize(
        request(logger),
      );
      expect(await settled(login)).toBe(false);
      expect(openMock).toHaveBeenCalledTimes(1);
      const shown = prompts.filter((p) => String(p[0]).includes(URL_SHOWN));
      expect(shown).toHaveLength(1);
      expect(await callback('code=C3&state=S1')).toBe(200);
      expect((await login).payload).toBe('C3');
    },
  );
});
