/**
 * Spec §6a1: where the shipped transports listen, and which `Host` they
 * answer for. Loopback by default (127.0.0.1 and ::1 — the redirect URI says
 * `localhost`), the consumer's `host` when given; every request whose `Host`
 * is neither loopback with the bound port nor one of `allowedHosts` is
 * answered `400` before any page, form token or callback handling — a
 * DNS-rebound name reads nothing and settles nothing.
 */

import net from 'node:net';
import os from 'node:os';
import { afterEach, describe, expect, it } from '@jest/globals';
import { withBrowserCallbackServer } from '../../auth/callbackServer';
import { withOidcCallbackServer } from '../../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../../auth/saml2Auth';
import {
  callbackGet,
  formTokenIn,
  ignoreCounter,
} from '../helpers/callbackHttp';

const PORT = 7893;
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

/** Whether a TCP connection to `address:port` is accepted. */
function connects(address: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: address, port });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

/** Whether this machine can bind `::1` at all (IPv6 may be disabled). */
function hasIpv6Loopback(): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(0, '::1', () => s.close(() => resolve(true)));
  });
}

/** A non-loopback IPv4 address of this machine, if it has one. */
function externalIpv4(): string | undefined {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return entry.address;
    }
  }
  return undefined;
}

/** `GET /` with no `Host` header, over a raw socket: the whole answer. */
function withoutHost(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let answer = '';
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      answer += chunk;
    });
    socket.on('end', () => resolve(answer));
    socket.on('error', reject);
    socket.write('GET / HTTP/1.0\r\n\r\n');
  });
}

const EXTERNAL = externalIpv4();
const itWithExternal = EXTERNAL ? it : it.skip;

describe('bind address', () => {
  it('binds loopback by default — 127.0.0.1 and ::1, no other interface', async () => {
    const ipv6 = await hasIpv6Loopback();
    await withBrowserCallbackServer({ port: PORT }, async (srv) => {
      expect(await connects('127.0.0.1', srv.port)).toBe(true);
      if (ipv6) expect(await connects('::1', srv.port)).toBe(true);
      if (EXTERNAL) expect(await connects(EXTERNAL, srv.port)).toBe(false);
    });
  }, 30000);

  it.each([
    ['OIDC', withOidcCallbackServer],
    ['SAML', withSamlCallbackServer],
  ] as const)(
    '%s binds loopback by default too',
    async (_name, factory) => {
      await factory({ port: PORT }, async (srv: { port: number }) => {
        expect(await connects('127.0.0.1', srv.port)).toBe(true);
        if (EXTERNAL) expect(await connects(EXTERNAL, srv.port)).toBe(false);
      });
    },
    30000,
  );

  it('binds only the configured host when given', async () => {
    const ipv6 = await hasIpv6Loopback();
    await withBrowserCallbackServer(
      { port: PORT, host: '127.0.0.1' },
      async (srv) => {
        expect(await connects('127.0.0.1', srv.port)).toBe(true);
        if (ipv6) expect(await connects('::1', srv.port)).toBe(false);
      },
    );
  }, 30000);

  itWithExternal(
    'binds a wildcard host when configured — reachable on another interface',
    async () => {
      await withBrowserCallbackServer(
        { port: PORT, host: '0.0.0.0' },
        async (srv) => {
          expect(await connects(EXTERNAL as string, srv.port)).toBe(true);
        },
      );
    },
    30000,
  );
});

describe('Host check', () => {
  it('answers loopback authorities with the bound port, and nothing else', async () => {
    const { logger, ignored } = ignoreCounter();
    await withBrowserCallbackServer(
      { port: PORT, gated: true, logger },
      async (srv) => {
        srv.expectState?.(STATE);
        for (const host of [
          `localhost:${PORT}`,
          `127.0.0.1:${PORT}`,
          `[::1]:${PORT}`,
          `LOCALHOST:${PORT}`,
        ]) {
          const page = await callbackGet(PORT, '/', { host });
          expect(page.status).toBe(200);
          expect(formTokenIn(page.body)).toEqual(expect.any(String));
        }
        for (const host of [
          'attacker.example',
          `attacker.example:${PORT}`,
          `localhost:${PORT + 1}`,
          'localhost',
          `127.0.0.1.attacker.example:${PORT}`,
        ]) {
          const page = await callbackGet(PORT, '/', { host });
          expect(page.status).toBe(400);
          expect(formTokenIn(page.body)).toBeUndefined();
          expect(page.body).not.toContain('form_token');
        }
        // No Host at all (HTTP/1.0): answered for nothing either. Node's
        // client fills an empty Host in, so this one goes over a raw socket.
        const bare = await withoutHost(PORT);
        expect(bare.startsWith('HTTP/1.1 400')).toBe(true);
        expect(bare).not.toContain('form_token');
        expect(ignored()).toBe(6);
      },
    );
  }, 30000);

  it('refuses a foreign Host before any callback handling', async () => {
    const { logger, ignored } = ignoreCounter();
    const code = await withBrowserCallbackServer(
      { port: PORT, gated: true, logger },
      async (srv) => {
        const waiting = srv.waitForResult();
        srv.expectState?.(STATE);
        const host = `rebound.example:${PORT}`;
        // The right state, through a rebound name: refused, nothing settles.
        expect(
          (
            await callbackGet(PORT, `/callback?code=forged&state=${STATE}`, {
              host,
            })
          ).status,
        ).toBe(400);
        expect(
          (
            await callbackGet(
              PORT,
              `/callback?error=access_denied&state=${STATE}`,
              { host },
            )
          ).status,
        ).toBe(400);
        expect(ignored()).toBe(2);
        void callbackGet(PORT, `/callback?code=real&state=${STATE}`);
        return await waiting;
      },
    );
    expect(code).toBe('real');
  }, 30000);

  it('refuses a foreign Host on an ungated transport too', async () => {
    const result = await withOidcCallbackServer({ port: PORT }, async (srv) => {
      const waiting = srv.waitForResult();
      expect(
        (
          await callbackGet(PORT, '/callback?code=forged', {
            host: `rebound.example:${PORT}`,
          })
        ).status,
      ).toBe(400);
      void callbackGet(PORT, '/callback?code=real');
      return await waiting;
    });
    expect(result).toEqual({ code: 'real', state: undefined });
  }, 30000);

  it('answers the consumer’s allowedHosts on a wildcard bind, and refuses an unrelated Host', async () => {
    const authority = `${EXTERNAL ?? '192.0.2.10'}:${PORT}`;
    await withBrowserCallbackServer(
      { port: PORT, host: '0.0.0.0', allowedHosts: [authority], gated: true },
      async (srv) => {
        srv.expectState?.(STATE);
        // Over the real interface when there is one; else the header alone.
        const address = EXTERNAL ?? '127.0.0.1';
        const allowed = await callbackGet(PORT, '/', {
          address,
          host: authority,
        });
        expect(allowed.status).toBe(200);
        expect(formTokenIn(allowed.body)).toEqual(expect.any(String));
        const unrelated = await callbackGet(PORT, '/', {
          address,
          host: `unrelated.example:${PORT}`,
        });
        expect(unrelated.status).toBe(400);
        expect(formTokenIn(unrelated.body)).toBeUndefined();
      },
    );
  }, 30000);

  it('matches an allowedHosts entry without a port to the bound port only', async () => {
    await withBrowserCallbackServer(
      { port: PORT, allowedHosts: ['BuildHost.example'], gated: true },
      async (srv) => {
        srv.expectState?.(STATE);
        expect(
          (await callbackGet(PORT, '/', { host: `buildhost.example:${PORT}` }))
            .status,
        ).toBe(200);
        expect(
          (await callbackGet(PORT, '/', { host: 'buildhost.example:1234' }))
            .status,
        ).toBe(400);
      },
    );
  }, 30000);
});
