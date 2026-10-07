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
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import {
  allowedAuthorities,
  answersFor,
  isLoopbackPeer,
  parseAuthority,
  withBrowserCallbackServer,
} from '../../auth/callbackServer';
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

describe('loopback names count only from a loopback peer (spec §6a1)', () => {
  // Over a real socket from this machine's own non-loopback address: the
  // peer the server sees is that address, not loopback.
  itWithExternal(
    'a wildcard bind without allowedHosts refuses a network peer sending Host: localhost',
    async () => {
      const { logger, ignored } = ignoreCounter();
      const code = await withBrowserCallbackServer(
        { port: PORT, host: '0.0.0.0', gated: true, logger },
        async (srv) => {
          const waiting = srv.waitForResult();
          srv.expectState?.(STATE);
          const address = EXTERNAL as string;
          for (const host of [
            `localhost:${PORT}`,
            `127.0.0.1:${PORT}`,
            `[::1]:${PORT}`,
          ]) {
            const page = await callbackGet(PORT, '/', { address, host });
            expect(page.status).toBe(400);
            expect(formTokenIn(page.body)).toBeUndefined();
            expect(page.body).not.toContain('form_token');
            expect(
              (
                await callbackGet(
                  PORT,
                  `/callback?code=forged&state=${STATE}`,
                  { address, host },
                )
              ).status,
            ).toBe(400);
          }
          expect(ignored()).toBe(6);
          // Nothing settled: the real callback, from loopback, still lands.
          void callbackGet(PORT, `/callback?code=real&state=${STATE}`);
          return await waiting;
        },
      );
      expect(code).toBe('real');
    },
    30000,
  );

  it.each([
    ['127.0.0.1', true],
    ['127.8.9.10', true],
    ['::1', true],
    ['::ffff:127.0.0.1', true],
    ['::ffff:127.255.0.1', true],
    ['192.168.100.13', false],
    ['10.0.0.1', false],
    ['::ffff:192.168.1.1', false],
    ['::', false],
    ['0.0.0.0', false],
    ['fe80::1', false],
    ['128.0.0.1', false],
    ['::ffff:128.0.0.1', false],
    ['', false],
    [undefined, false],
  ])('isLoopbackPeer(%p) is %p', (address, expected) => {
    expect(isLoopbackPeer(address)).toBe(expected);
  });
});

describe('port 0 and the second family (spec §6a1)', () => {
  // The redirect URI says `localhost`, which resolves to ::1 first: staying
  // on 127.0.0.1 alone would hand the ::1 holder the code and the state
  // (measured in the re-review). Fail closed, as for a fixed port.
  it('fails port-in-use when the OS-given port is taken on ::1 — never 127.0.0.1 alone', async () => {
    if (!(await hasIpv6Loopback())) {
      console.warn('no IPv6 loopback on this machine: case not run');
      return;
    }
    // Occupy the port the OS gave 127.0.0.1 on ::1 — just before the
    // transport binds ::1 there.
    const squatter = net.createServer();
    const listen = net.Server.prototype.listen;
    const spy = jest
      .spyOn(net.Server.prototype, 'listen')
      .mockImplementation(function (this: net.Server, ...args: unknown[]) {
        const options = args[0] as { port?: number; host?: string };
        if (options?.host === '::1' && !squatter.listening) {
          listen.call(squatter, { port: options.port, host: '::1' }, () => {
            listen.apply(this, args as never);
          });
          return this;
        }
        return listen.apply(this, args as never);
      });
    let entered = false;
    try {
      const thrown = await withBrowserCallbackServer({ port: 0 }, async () => {
        entered = true;
        return 'never';
      }).catch((e: unknown) => e);
      const squatted = (squatter.address() as net.AddressInfo).port;
      expect(readFailure(thrown, 'browser-login').facts).toEqual({
        outcome: 'port-in-use',
        port: squatted,
      });
      // Nothing was served: no URL could be built on a half-bound port.
      expect(entered).toBe(false);
      // The 127.0.0.1 half was released: binding it again succeeds.
      await new Promise<void>((resolve, reject) => {
        const probe = net.createServer();
        probe.once('error', reject);
        probe.listen(squatted, '127.0.0.1', () => probe.close(() => resolve()));
      });
    } finally {
      spy.mockRestore();
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  }, 30000);

  it('a fixed port taken on ::1 still fails the login: port in use', async () => {
    if (!(await hasIpv6Loopback())) {
      console.warn('no IPv6 loopback on this machine: case not run');
      return;
    }
    const squatter = net.createServer();
    await new Promise<void>((resolve) => squatter.listen(PORT, '::1', resolve));
    try {
      await expect(
        withBrowserCallbackServer({ port: PORT }, async () => 'never'),
      ).rejects.toThrow(/already in use/);
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  }, 30000);
});

describe('a loopback name is never an allowed authority (spec §6a1)', () => {
  const LOOPBACK_ENTRIES = (port: number) => [
    `localhost:${port}`,
    '127.0.0.1',
    `[::1]:${port}`,
    'LOCALHOST',
  ];

  itWithExternal(
    'allowedHosts listing loopback names admits nothing from a network peer',
    async () => {
      const { logger, ignored } = ignoreCounter();
      const code = await withBrowserCallbackServer(
        {
          port: PORT,
          host: '0.0.0.0',
          allowedHosts: LOOPBACK_ENTRIES(PORT),
          gated: true,
          logger,
        },
        async (srv) => {
          const waiting = srv.waitForResult();
          srv.expectState?.(STATE);
          const address = EXTERNAL as string;
          for (const host of [
            `localhost:${PORT}`,
            `127.0.0.1:${PORT}`,
            `[::1]:${PORT}`,
          ]) {
            const page = await callbackGet(PORT, '/', { address, host });
            expect(page.status).toBe(400);
            expect(formTokenIn(page.body)).toBeUndefined();
          }
          expect(ignored()).toBe(3);
          void callbackGet(PORT, `/callback?code=real&state=${STATE}`);
          return await waiting;
        },
      );
      expect(code).toBe('real');
    },
    30000,
  );

  it('answersFor: a loopback name listed in allowedHosts counts only from a loopback peer', () => {
    const allowed = allowedAuthorities(LOOPBACK_ENTRIES(PORT));
    for (const host of [
      `localhost:${PORT}`,
      `127.0.0.1:${PORT}`,
      `[::1]:${PORT}`,
    ]) {
      expect(answersFor(host, '192.168.1.20', PORT, allowed)).toBe(false);
      expect(answersFor(host, '::ffff:10.0.0.1', PORT, allowed)).toBe(false);
      expect(answersFor(host, '127.0.0.1', PORT, allowed)).toBe(true);
    }
    // A real authority in the same list still answers a network peer.
    expect(
      answersFor(
        `buildhost.example:${PORT}`,
        '192.168.1.20',
        PORT,
        allowedAuthorities([...LOOPBACK_ENTRIES(PORT), 'buildhost.example']),
      ),
    ).toBe(true);
  });
});

describe('authorities are compared canonically (spec §6a1)', () => {
  /** Every other spelling of loopback, and the unspecified address. */
  const SPELLINGS = (port: number) => [
    `localhost.:${port}`,
    `127.1:${port}`,
    `127.0.0.2:${port}`,
    `[0:0:0:0:0:0:0:1]:${port}`,
    `[::ffff:127.0.0.1]:${port}`,
    `[::ffff:7f00:1]:${port}`,
    `0x7f.1:${port}`,
    `0.0.0.0:${port}`,
    `[::]:${port}`,
  ];

  itWithExternal(
    'other spellings of loopback listed in allowedHosts admit no network peer; a real authority still does',
    async () => {
      const code = await withBrowserCallbackServer(
        {
          port: PORT,
          host: '0.0.0.0',
          allowedHosts: [
            'localhost.',
            '127.1',
            '[0:0:0:0:0:0:0:1]',
            '[::ffff:127.0.0.1]',
            '0.0.0.0',
            ...SPELLINGS(PORT),
            'realhost.example',
          ],
          gated: true,
        },
        async (srv) => {
          const waiting = srv.waitForResult();
          srv.expectState?.(STATE);
          const address = EXTERNAL as string;
          for (const host of SPELLINGS(PORT)) {
            const page = await callbackGet(PORT, '/', { address, host });
            expect({ host, status: page.status }).toEqual({
              host,
              status: 400,
            });
            expect(formTokenIn(page.body)).toBeUndefined();
          }
          const real = await callbackGet(PORT, '/', {
            address,
            host: `realhost.example:${PORT}`,
          });
          expect(real.status).toBe(200);
          expect(formTokenIn(real.body)).toEqual(expect.any(String));
          void callbackGet(PORT, `/callback?code=real&state=${STATE}`);
          return await waiting;
        },
      );
      expect(code).toBe('real');
    },
    30000,
  );

  it('answersFor: from a loopback peer every canonical loopback authority with the bound port counts; from any other, none', () => {
    const none = allowedAuthorities([]);
    for (const host of [
      `localhost:${PORT}`,
      `localhost.:${PORT}`,
      `127.0.0.1:${PORT}`,
      `127.1:${PORT}`,
      `127.0.0.2:${PORT}`,
      `[::1]:${PORT}`,
      `[0:0:0:0:0:0:0:1]:${PORT}`,
      `[::ffff:127.0.0.1]:${PORT}`,
    ]) {
      expect({
        host,
        loopback: answersFor(host, '127.0.0.1', PORT, none),
      }).toEqual({
        host,
        loopback: true,
      });
      expect({
        host,
        network: answersFor(
          host,
          '192.168.1.20',
          PORT,
          allowedAuthorities(SPELLINGS(PORT)),
        ),
      }).toEqual({ host, network: false });
      expect(
        answersFor(host.replace(`:${PORT}`, ':1'), '127.0.0.1', PORT, none),
      ).toBe(false);
    }
    // The unspecified address is never an authority, from any peer: the
    // list drops it, and a Host naming it answers nothing even when a list
    // (built by hand, past that filter) holds it.
    expect(allowedAuthorities(['0.0.0.0', `[::]:${PORT}`])).toEqual([]);
    const unfiltered = [
      parseAuthority('0.0.0.0'),
      parseAuthority('[::]'),
    ].filter((entry) => entry !== undefined);
    expect(unfiltered).toHaveLength(2);
    for (const host of [`0.0.0.0:${PORT}`, `[::]:${PORT}`]) {
      expect(answersFor(host, '127.0.0.1', PORT, unfiltered)).toBe(false);
    }
    for (const host of [`0.0.0.0:${PORT}`, `[::]:${PORT}`]) {
      expect(
        answersFor(host, '127.0.0.1', PORT, allowedAuthorities([host])),
      ).toBe(false);
    }
  });

  it('an entry the URL host parser cannot read, or that carries more than an authority, matches nothing', () => {
    for (const entry of [
      'a b',
      'user@realhost.example',
      'realhost.example/x',
      'realhost.example:',
      'realhost.example:99999',
    ]) {
      expect({ entry, read: allowedAuthorities([entry]) }).toEqual({
        entry,
        read: [],
      });
    }
    expect(
      answersFor(
        'REALHOST.example.:80',
        '192.168.1.20',
        PORT,
        allowedAuthorities(['realhost.example:80']),
      ),
    ).toBe(true);
  });
});
