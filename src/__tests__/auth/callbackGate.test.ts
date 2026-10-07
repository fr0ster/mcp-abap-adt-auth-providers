/**
 * Spec §6a1: the shipped OAuth transports opened `gated` — closed from the
 * bind until `expectState` arms them, then admitting only this login's
 * `state`. Every refused request is answered `400`, counted and ignored; the
 * login keeps waiting and completes with the real callback. All on a real
 * port.
 */

import net from 'node:net';
import { afterEach, describe, expect, it } from '@jest/globals';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
} from '@mcp-abap-adt/interfaces-auth';
import { withBrowserCallbackServer } from '../../auth/callbackServer';
import { withOidcCallbackServer } from '../../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../../auth/saml2Auth';
import {
  callbackGet,
  formTokenIn,
  ignoreCounter,
} from '../helpers/callbackHttp';

const PORT = 7891;
const STATE = 'the-state-of-this-login';

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

afterEach(async () => {
  expect(await portIsFree(PORT)).toBe(true);
});

const get = (path: string) => callbackGet(PORT, path);

type Transport = CallbackServerFactory<unknown>;
const OAUTH: ReadonlyArray<readonly [string, Transport, unknown]> = [
  ['UAA', withBrowserCallbackServer as Transport, 'real'],
  ['OIDC', withOidcCallbackServer as Transport, { code: 'real', state: STATE }],
];

describe.each(OAUTH)('%s transport, gated', (_name, transport, expected) => {
  it('refuses a forged code and a forged ?error= before the gate is armed, then logs in', async () => {
    const { logger, ignored } = ignoreCounter();
    const result = await transport(
      { port: PORT, gated: true, logger },
      async (srv: ICallbackServerHandle<unknown>) => {
        const waiting = srv.waitForResult();
        // Not armed: even the right state is refused, and so is an IdP error.
        expect((await get(`/callback?code=forged&state=${STATE}`)).status).toBe(
          400,
        );
        expect((await get('/callback?error=access_denied')).status).toBe(400);
        expect(
          (await get(`/callback?error=access_denied&state=${STATE}`)).status,
        ).toBe(400);
        expect(ignored()).toBe(3);
        srv.expectState?.(STATE);
        void get(`/callback?code=real&state=${STATE}`);
        return await waiting;
      },
    );
    expect(result).toEqual(expected);
    expect(ignored()).toBe(3);
  }, 30000);

  it('refuses a missing and a different state, then accepts the right one', async () => {
    const { logger, ignored } = ignoreCounter();
    const result = await transport(
      { port: PORT, gated: true, logger },
      async (srv: ICallbackServerHandle<unknown>) => {
        const waiting = srv.waitForResult();
        srv.expectState?.(STATE);
        expect((await get('/callback?code=forged')).status).toBe(400);
        expect(
          (await get('/callback?code=forged&state=another-state')).status,
        ).toBe(400);
        // Same length, one character off: not a prefix test.
        const near = `${STATE.slice(0, -1)}X`;
        expect((await get(`/callback?code=forged&state=${near}`)).status).toBe(
          400,
        );
        expect(ignored()).toBe(3);
        void get(`/callback?code=real&state=${STATE}`);
        return await waiting;
      },
    );
    expect(result).toEqual(expected);
  }, 30000);

  it('ignores a forged ?error= with a wrong state; the real one then ends the login', async () => {
    const { logger, ignored } = ignoreCounter();
    let armed!: () => void;
    const listening = new Promise<void>((resolve) => {
      armed = resolve;
    });
    const attempt = transport(
      { port: PORT, gated: true, logger },
      async (srv: ICallbackServerHandle<unknown>) => {
        srv.expectState?.(STATE);
        const waiting = srv.waitForResult();
        armed();
        return await waiting;
      },
    );
    const rejected = expect(attempt).rejects.toThrow(
      'the identity provider refused the login (access_denied)',
    );
    await listening;
    expect(
      (await get('/callback?error=access_denied&state=wrong')).status,
    ).toBe(400);
    expect((await get('/callback?error=access_denied')).status).toBe(400);
    expect(ignored()).toBe(2);
    await get(`/callback?error=access_denied&state=${STATE}`);
    await rejected;
  }, 30000);

  it('expectState(null) declares an unbound URL: callbacks are accepted as without a gate', async () => {
    const result = await transport(
      { port: PORT, gated: true },
      async (srv: ICallbackServerHandle<unknown>) => {
        const waiting = srv.waitForResult();
        srv.expectState?.(null);
        void get(`/callback?code=real&state=${STATE}`);
        return await waiting;
      },
    );
    expect(result).toEqual(expected);
  }, 30000);

  it('implements expectState', async () => {
    await transport({ port: PORT }, async (srv) => {
      expect(typeof srv.expectState).toBe('function');
    });
  }, 30000);
});

describe('UAA paste route, gated', () => {
  it('is closed before arming: no form, no token, /submit refused', async () => {
    const { logger, ignored } = ignoreCounter();
    await withBrowserCallbackServer(
      { port: PORT, gated: true, logger },
      async () => {
        const page = await get('/');
        expect(page.status).toBe(400);
        expect(formTokenIn(page.body)).toBeUndefined();
        expect((await get('/submit?input=forged')).status).toBe(400);
        expect(
          (await get('/submit?input=forged&form_token=guessed')).status,
        ).toBe(400);
        expect(ignored()).toBe(3);
      },
    );
  }, 30000);

  it('settles only with the served form token; a pasted URL needs this login’s state', async () => {
    const { logger, ignored } = ignoreCounter();
    const code = await withBrowserCallbackServer(
      { port: PORT, gated: true, logger },
      async (srv) => {
        const waiting = srv.waitForResult();
        srv.expectState?.(STATE);
        const page = await get('/');
        expect(page.status).toBe(200);
        const token = formTokenIn(page.body);
        expect(token).toEqual(expect.any(String));
        expect(token?.length).toBeGreaterThanOrEqual(43);

        // No token, a wrong token: refused, the input never read.
        expect((await get('/submit?input=forged')).status).toBe(400);
        expect(
          (await get('/submit?input=forged&form_token=wrong')).status,
        ).toBe(400);
        // The right token, a pasted URL with a wrong or no state.
        const pasted = (state: string) =>
          encodeURIComponent(
            `http://localhost:${PORT}/callback?code=forged${state}`,
          );
        expect(
          (
            await get(
              `/submit?input=${pasted('&state=wrong')}&form_token=${token}`,
            )
          ).status,
        ).toBe(400);
        expect(
          (await get(`/submit?input=${pasted('')}&form_token=${token}`)).status,
        ).toBe(400);
        expect(ignored()).toBe(4);

        // A bare code through the served form logs in.
        void get(`/submit?input=bare-code&form_token=${token}`);
        return await waiting;
      },
    );
    expect(code).toBe('bare-code');
    expect(ignored()).toBe(4);
  }, 30000);

  it('accepts a pasted URL carrying this login’s state', async () => {
    const code = await withBrowserCallbackServer(
      { port: PORT, gated: true },
      async (srv) => {
        const waiting = srv.waitForResult();
        srv.expectState?.(STATE);
        const token = formTokenIn((await get('/')).body);
        const pasted = encodeURIComponent(
          `http://localhost:${PORT}/callback?code=pasted&state=${STATE}`,
        );
        void get(`/submit?input=${pasted}&form_token=${token}`);
        return await waiting;
      },
    );
    expect(code).toBe('pasted');
  }, 30000);

  it('binds /submit by the form token even when the URL is unbound (expectState(null))', async () => {
    const { logger, ignored } = ignoreCounter();
    const code = await withBrowserCallbackServer(
      { port: PORT, gated: true, logger },
      async (srv) => {
        const waiting = srv.waitForResult();
        srv.expectState?.(null);
        expect((await get('/submit?input=forged')).status).toBe(400);
        expect(ignored()).toBe(1);
        const token = formTokenIn((await get('/')).body);
        void get(`/submit?input=bare&form_token=${token}`);
        return await waiting;
      },
    );
    expect(code).toBe('bare');
  }, 30000);

  it('mints a new form token for every login', async () => {
    const tokens: Array<string | undefined> = [];
    for (let i = 0; i < 2; i++) {
      await withBrowserCallbackServer(
        { port: PORT, gated: true },
        async (srv) => {
          srv.expectState?.(STATE);
          tokens.push(formTokenIn((await get('/')).body));
        },
      );
    }
    expect(tokens[0]).toEqual(expect.any(String));
    expect(tokens[1]).toEqual(expect.any(String));
    expect(tokens[0]).not.toBe(tokens[1]);
  }, 30000);
});

describe('SAML transport', () => {
  it('logs in without being armed when not gated', async () => {
    const response = await withSamlCallbackServer(
      { port: PORT },
      async (srv) => {
        const waiting = srv.waitForResult();
        void get('/callback?SAMLResponse=assertion');
        return await waiting;
      },
    );
    expect(response).toBe('assertion');
  }, 30000);
});
