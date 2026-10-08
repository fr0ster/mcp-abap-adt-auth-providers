/**
 * The shipped browsers (spec §6d, §6a0): `systemBrowser()`, `chromeBrowser()`,
 * `edgeBrowser()`, `firefoxBrowser()` implement `IBrowser` through the
 * package's own launchers on every platform (no `open` package), each
 * started with an argument array and no shell: `xdg-open` / the browser's executables on
 * Linux, `open` (`-a <app>`) on macOS, and on Windows `rundll32` or
 * PowerShell's `Start-Process` (the URL only in the environment), both by
 * absolute path under `%SystemRoot%\System32`. Only an `http(s)` URL is
 * launched, as its serialisation.
 *
 * `open` resolves once the browser was asked to open the URL — a hand-off
 * launcher (`xdg-open`, `open(1)`, `rundll32`, `Start-Process`) at its exit
 * `0`, a browser binary started directly at its `spawn` — and rejects when
 * it could not be, with an `AuthProviderFailure` (`unknown`,
 * `opening-browser`, an allowlisted code) — no URL, no `state`, no
 * launcher text.
 *
 * - `spawn` recorded (nothing starts): each platform and browser gets the
 *   exact URL as one argument, no `shell` option, never `exec`;
 * - settlement per launcher, through the mocked `child_process` boundary
 *   only: there is no `open` package to mock;
 * - for real (Linux): a fake `xdg-open` and `google-chrome` on `PATH`; a
 *   hostile URL reaches them as one argument and no MARKER file is created.
 */

import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import {
  AuthProviderFailure,
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type { IBrowser } from '@mcp-abap-adt/interfaces-auth';

type SpawnCall = { command: string; args: string[]; options: unknown };
const spawned: SpawnCall[] = [];
const realChildProcess =
  jest.requireActual<typeof import('node:child_process')>('node:child_process');
type FakeChild = InstanceType<typeof import('node:events').EventEmitter> & {
  unref(): void;
  kill(): boolean;
};
/**
 * How the recorded child goes: an error before it starts; or it starts
 * (`spawn`) and exits with a code; or it starts and keeps running
 * (`'running'`, kept in `running` for the test to end). Not recording, a
 * launcher runs for real as the fake program `real` names for it — never
 * the system's own (a launcher it does not name is refused, and the suite's
 * guard starts only registered paths).
 */
const fakeChild: {
  record: boolean;
  outcome: (index: number) => number | Error | 'running';
  real: Record<string, string>;
  running: FakeChild[];
  killed: number;
} = { record: true, outcome: () => 0, real: {}, running: [], killed: 0 };

jest.mock('node:child_process', () => ({
  ...jest.requireActual<Record<string, unknown>>('node:child_process'),
  spawn: (command: string, args: string[], options: unknown) => {
    if (!fakeChild.record) {
      const fake = fakeChild.real[command];
      if (fake === undefined) throw new Error(`no fake for ${command}`);
      // The options as given: a `shell` among them would reach the real spawn.
      return realChildProcess.spawn(
        fake,
        args,
        options as Parameters<typeof realChildProcess.spawn>[2],
      );
    }
    const index = spawned.length;
    spawned.push({ command, args, options });
    const { EventEmitter } =
      jest.requireActual<typeof import('node:events')>('node:events');
    const child = new EventEmitter() as FakeChild;
    child.unref = () => undefined;
    child.kill = () => {
      fakeChild.killed += 1;
      return true;
    };
    const outcome = fakeChild.outcome(index);
    setImmediate(() => {
      if (outcome instanceof Error) {
        child.emit('error', outcome);
        return;
      }
      child.emit('spawn');
      if (outcome === 'running') fakeChild.running.push(child);
      else setImmediate(() => child.emit('exit', outcome));
    });
    return child;
  },
  exec: () => {
    throw new Error('exec must never be called');
  },
  execSync: () => {
    throw new Error('execSync must never be called');
  },
}));

import { launchableUrl, URL_VARIABLE } from '../../auth/browserLaunch';
import {
  chromeBrowser,
  composeAuthorization,
  edgeBrowser,
  firefoxBrowser,
  loopback4,
  oauthCode,
  openInBrowser,
  systemBrowser,
} from '../../index';
import { getAvailablePort } from '../helpers/netHelpers';
import { allowExecutable } from '../helpers/noRealBrowser';

/** `${IFS}` as text: a shell's word separator, no space for the URL to encode. */
const IFS = ['$', '{IFS}'].join('');
const STATE = 'browser-state_abcdefghijklmnopqrstuvwxyz0123';
/**
 * A URL a shell would parse cleanly and run all three commands of; its
 * serialisation keeps them (no space to encode).
 */
const HOSTILE = `https://idp.example/authorize?a=$(touch${IFS}MARKER1)&b=\`touch${IFS}MARKER2\`;touch${IFS}MARKER3&state=${STATE}`;
const href = launchableUrl(HOSTILE) as string;
const realPlatform = process.platform;
/** The variables a test changes, restored key by key (`process.env` itself stays). */
const ENV_KEYS = ['PATH', 'DISPLAY', 'WAYLAND_DISPLAY', 'SystemRoot'] as const;
const savedEnv = Object.fromEntries(
  ENV_KEYS.map((key) => [key, process.env[key]]),
) as Record<(typeof ENV_KEYS)[number], string | undefined>;

function onPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', { value: platform });
}

const never = new AbortController().signal;

beforeEach(() => {
  fakeChild.record = true;
  fakeChild.outcome = () => 0;
  fakeChild.real = {};
  fakeChild.running = [];
  fakeChild.killed = 0;
  spawned.length = 0;
});
afterEach(() => {
  onPlatform(realPlatform);
  for (const key of ENV_KEYS) {
    const value = savedEnv[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

const factories = {
  systemBrowser,
  chromeBrowser,
  edgeBrowser,
  firefoxBrowser,
} as const;
type Name = keyof typeof factories;

/** Everything a rejection shows: no URL, no state, no launcher text. */
function rendered(error: unknown): string {
  const record = error as Record<string, unknown>;
  return [
    String(error),
    JSON.stringify(error),
    record.message,
    record.stack,
    JSON.stringify(record.cause ?? null),
    JSON.stringify(Object.getOwnPropertyNames(record).map((k) => record[k])),
  ].join('\n');
}

describe('each shipped browser is an IBrowser', () => {
  it.each(Object.keys(factories) as Name[])(
    '%s(): a frozen object whose only member is open',
    (name) => {
      const browser: IBrowser = factories[name]();
      expect(Object.keys(browser)).toEqual(['open']);
      expect(typeof browser.open).toBe('function');
      expect(Object.isFrozen(browser)).toBe(true);
    },
  );
});

describe('every platform: an argument array, no shell', () => {
  const ps = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  it.each<[NodeJS.Platform, Name, string, string[]]>([
    ['linux', 'systemBrowser', 'xdg-open', [href]],
    ['linux', 'chromeBrowser', 'google-chrome', [href]],
    ['linux', 'edgeBrowser', 'microsoft-edge', [href]],
    ['linux', 'firefoxBrowser', 'firefox', [href]],
    ['darwin', 'systemBrowser', 'open', [href]],
    ['darwin', 'chromeBrowser', 'open', ['-a', 'Google Chrome', href]],
    ['darwin', 'edgeBrowser', 'open', ['-a', 'Microsoft Edge', href]],
    ['darwin', 'firefoxBrowser', 'open', ['-a', 'Firefox', href]],
    [
      'win32',
      'systemBrowser',
      'C:\\Windows\\System32\\rundll32.exe',
      ['url.dll,FileProtocolHandler', href],
    ],
  ])('%s, %s: %s', async (platform, name, command, args) => {
    onPlatform(platform);
    delete process.env.SystemRoot;
    await expect(factories[name]().open(HOSTILE, never)).resolves.toBe(
      undefined,
    );
    expect(spawned).toHaveLength(1);
    const call = spawned[0] as SpawnCall;
    expect(call.command).toBe(command);
    expect(call.args).toEqual(args);
    expect(call.args.filter((arg) => arg.includes('idp.example'))).toEqual([
      href,
    ]);
    expect((call.options as { shell?: unknown }).shell).toBeUndefined();
  });

  it.each<[Name, string]>([
    ['chromeBrowser', 'chrome'],
    ['edgeBrowser', 'msedge'],
    ['firefoxBrowser', 'firefox'],
  ])(
    'win32, %s: PowerShell reads the URL from the environment, never its command line',
    async (name, program) => {
      onPlatform('win32');
      delete process.env.SystemRoot;
      await factories[name]().open(HOSTILE, never);
      expect(spawned).toHaveLength(1);
      const call = spawned[0] as SpawnCall;
      expect(call.command).toBe(ps);
      expect(call.args.join(' ')).not.toContain('idp.example');
      expect(call.args).toEqual([
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `Start-Process -FilePath '${program}' -ArgumentList $env:${URL_VARIABLE}`,
      ]);
      const options = call.options as {
        shell?: unknown;
        env?: Record<string, string>;
      };
      expect(options.shell).toBeUndefined();
      expect(options.env?.[URL_VARIABLE]).toBe(href);
    },
  );

  it('win32 launchers sit under SystemRoot', async () => {
    onPlatform('win32');
    process.env.SystemRoot = 'D:\\Win';
    await systemBrowser().open(HOSTILE, never);
    await chromeBrowser().open(HOSTILE, never);
    expect(spawned.map((call) => call.command)).toEqual([
      'D:\\Win\\System32\\rundll32.exe',
      'D:\\Win\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ]);
  });

  it('Linux: the next executable only when one cannot start; every one failing rejects', async () => {
    onPlatform('linux');
    const enoent = () => Object.assign(new Error('nope'), { code: 'ENOENT' });
    fakeChild.outcome = (index) => (index === 0 ? enoent() : 'running');
    await expect(chromeBrowser().open(HOSTILE, never)).resolves.toBe(undefined);
    expect(spawned.map((call) => call.command)).toEqual([
      'google-chrome',
      'chromium',
    ]);

    spawned.length = 0;
    fakeChild.outcome = enoent;
    const failed = await chromeBrowser()
      .open(HOSTILE, never)
      .catch((e: unknown) => e);
    expect(spawned.map((call) => call.command)).toEqual([
      'google-chrome',
      'chromium',
      'chromium-browser',
    ]);
    expect(isAuthProviderFailure(failed)).toBe(true);
  });

  // M2: `open` settles once the browser was asked (the IBrowser contract).
  it.each<[Name]>([['chromeBrowser'], ['edgeBrowser'], ['firefoxBrowser']])(
    'Linux, %s: a browser binary started directly resolves at its spawn and never waits for the browser to exit',
    async (name) => {
      onPlatform('linux');
      fakeChild.outcome = () => 'running';
      await expect(factories[name]().open(HOSTILE, never)).resolves.toBe(
        undefined,
      );
      expect(spawned).toHaveLength(1);
      expect(fakeChild.running).toHaveLength(1);
    },
  );

  it('Linux: a browser binary that started and later exits non-zero was still asked; no next candidate', async () => {
    onPlatform('linux');
    fakeChild.outcome = () => 1;
    await expect(chromeBrowser().open(HOSTILE, never)).resolves.toBe(undefined);
    expect(spawned.map((call) => call.command)).toEqual(['google-chrome']);
  });

  it.each<[NodeJS.Platform, Name]>([
    ['linux', 'systemBrowser'],
    ['darwin', 'systemBrowser'],
    ['darwin', 'chromeBrowser'],
    ['win32', 'systemBrowser'],
    ['win32', 'firefoxBrowser'],
  ])(
    '%s, %s: a hand-off launcher is awaited to its exit',
    async (platform, name) => {
      onPlatform(platform);
      fakeChild.outcome = () => 'running';
      let settled = false;
      const opened = factories[name]()
        .open(HOSTILE, never)
        .finally(() => {
          settled = true;
        });
      for (let i = 0; i < 20 && fakeChild.running.length === 0; i += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      await new Promise((resolve) => setImmediate(resolve));
      expect(fakeChild.running).toHaveLength(1);
      expect(settled).toBe(false);
      fakeChild.running[0]?.emit('exit', 0);
      await expect(opened).resolves.toBe(undefined);
    },
  );

  it('every launcher failing rejects in fixed words, keeping an allowlisted code — no URL, no state, no launcher text', async () => {
    onPlatform('linux');
    fakeChild.outcome = () =>
      Object.assign(new Error(`spawn SECRET-PATH ${HOSTILE}`), {
        code: 'ENOENT',
        spawnargs: [HOSTILE],
      });
    const failure = await firefoxBrowser()
      .open(HOSTILE, never)
      .catch((e: unknown) => e);
    expect(isAuthProviderFailure(failure)).toBe(true);
    expect(readFailure(failure, 'opening-browser')).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'opening-browser', code: 'ENOENT' },
    });
    const text = rendered(failure);
    expect(text).not.toContain('idp.example');
    expect(text).not.toContain(STATE);
    expect(text).not.toContain('SECRET-PATH');
  });

  it('a launcher exiting non-zero rejects too, with no code', async () => {
    onPlatform('linux');
    fakeChild.outcome = () => 3;
    const failure = await systemBrowser()
      .open(HOSTILE, never)
      .catch((e: unknown) => e);
    expect(readFailure(failure, 'opening-browser').facts).toEqual({
      operation: 'opening-browser',
    });
  });

  it.each(['javascript:alert(1)', 'file:///etc/passwd', 'not a url'])(
    'a URL that is not http(s) (%j) starts nothing and rejects',
    async (url) => {
      onPlatform('linux');
      const failure = await systemBrowser()
        .open(url, never)
        .catch((e: unknown) => e);
      expect(isAuthProviderFailure(failure)).toBe(true);
      expect(rendered(failure)).not.toContain(url);
      expect(spawned).toEqual([]);
    },
  );

  // Settlement per launcher, every platform (fix round 2).
  const HAND_OFF: [NodeJS.Platform, Name][] = [
    ['linux', 'systemBrowser'],
    ['darwin', 'systemBrowser'],
    ['darwin', 'chromeBrowser'],
    ['darwin', 'edgeBrowser'],
    ['darwin', 'firefoxBrowser'],
    ['win32', 'systemBrowser'],
    ['win32', 'chromeBrowser'],
    ['win32', 'edgeBrowser'],
    ['win32', 'firefoxBrowser'],
  ];

  it.each(HAND_OFF)(
    '%s, %s: a hand-off launcher exiting non-zero after its spawn rejects (no next launcher)',
    async (platform, name) => {
      onPlatform(platform);
      fakeChild.outcome = () => 1;
      const failure = await factories[name]()
        .open(HOSTILE, never)
        .catch((e: unknown) => e);
      expect(readFailure(failure, 'opening-browser').facts).toEqual({
        operation: 'opening-browser',
      });
      expect(spawned).toHaveLength(1);
    },
  );

  it.each(HAND_OFF)(
    '%s, %s: a hand-off launcher failing before its spawn rejects',
    async (platform, name) => {
      onPlatform(platform);
      fakeChild.outcome = () =>
        Object.assign(new Error('nope'), { code: 'ENOENT' });
      const failure = await factories[name]()
        .open(HOSTILE, never)
        .catch((e: unknown) => e);
      expect(readFailure(failure, 'opening-browser').facts).toEqual({
        operation: 'opening-browser',
        code: 'ENOENT',
      });
    },
  );

  it.each(HAND_OFF)(
    '%s, %s: an abort while the hand-off launcher runs rejects aborted; the child is not killed',
    async (platform, name) => {
      onPlatform(platform);
      fakeChild.outcome = () => 'running';
      const controller = new AbortController();
      const opened = factories[name]()
        .open(HOSTILE, controller.signal)
        .catch((e: unknown) => e);
      for (let i = 0; i < 20 && fakeChild.running.length === 0; i += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      controller.abort();
      expect(readFailure(await opened, 'browser-login').facts).toEqual({
        outcome: 'aborted',
      });
      expect(fakeChild.killed).toBe(0);
      // Its later exit changes nothing.
      fakeChild.running[0]?.emit('exit', 0);
    },
  );

  it.each<[Name]>([['chromeBrowser'], ['edgeBrowser'], ['firefoxBrowser']])(
    'Linux, %s: an abort while a browser binary is starting rejects aborted; nothing is killed',
    async (name) => {
      onPlatform('linux');
      const controller = new AbortController();
      fakeChild.outcome = () => {
        controller.abort();
        return 'running';
      };
      await expect(
        factories[name]().open(HOSTILE, controller.signal),
      ).rejects.toBeInstanceOf(AuthProviderFailure);
      expect(fakeChild.killed).toBe(0);
    },
  );

  it('an aborted signal starts nothing and rejects', async () => {
    onPlatform('linux');
    const controller = new AbortController();
    controller.abort();
    await expect(
      systemBrowser().open(HOSTILE, controller.signal),
    ).rejects.toBeInstanceOf(AuthProviderFailure);
    expect(spawned).toEqual([]);
  });

  it('a signal aborting during the launch rejects it and starts no further candidate', async () => {
    onPlatform('linux');
    const controller = new AbortController();
    fakeChild.outcome = () => {
      controller.abort();
      return Object.assign(new Error('nope'), { code: 'ENOENT' });
    };
    await expect(
      chromeBrowser().open(HOSTILE, controller.signal),
    ).rejects.toBeInstanceOf(AuthProviderFailure);
    expect(spawned.map((call) => call.command)).toEqual(['google-chrome']);
  });

  // The user's decision: no DISPLAY guessed — a display, a remote Chrome or
  // a console browser is the consumer's own IBrowser.
  it.each(Object.keys(factories) as Name[])(
    'Linux without a display, %s: process.env is left as it was',
    async (name) => {
      onPlatform('linux');
      delete process.env.DISPLAY;
      delete process.env.WAYLAND_DISPLAY;
      const before = { ...process.env };
      await factories[name]().open(HOSTILE, never);
      expect('DISPLAY' in process.env).toBe(false);
      expect('WAYLAND_DISPLAY' in process.env).toBe(false);
      expect({ ...process.env }).toEqual(before);
      const call = spawned[0] as SpawnCall;
      expect((call.options as { env?: unknown }).env).toBeUndefined();
    },
  );
});

describe('through openInBrowser: the failure in fixed words, the URL prompted once', () => {
  it.each([
    [
      'the launcher failing to start',
      () => {
        onPlatform('linux');
        fakeChild.outcome = () =>
          Object.assign(new Error(`SECRET-PATH ${HOSTILE}`), {
            code: 'ENOENT',
          });
      },
      'opening the browser failed (unknown error, ENOENT)',
    ],
    [
      'the hand-off launcher exiting non-zero',
      () => {
        onPlatform('linux');
        fakeChild.outcome = () => 2;
      },
      'opening the browser failed (unknown error)',
    ],
    [
      'every launcher failing',
      () => {
        onPlatform('linux');
        fakeChild.outcome = () => new Error(`SECRET-PATH ${HOSTILE}`);
      },
      'opening the browser failed (unknown error)',
    ],
  ] as const)('%s', async (_name, setUp, words) => {
    setUp();
    const written: string[] = [];
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      });
    try {
      const presented = openInBrowser({ browser: systemBrowser() }).present(
        HOSTILE,
        {
          signal: never,
          redirectUri: undefined,
          waitingOn: undefined,
          routeHint: undefined,
        },
      );
      const failure: unknown = await Promise.resolve(presented).then(
        () => undefined,
        (error: unknown) => error,
      );
      const fields = logFields(
        readFailure(failure, 'presenting-authorization-url'),
      );
      expect(fields).toEqual({ error: words, kind: 'unknown' });
      expect(JSON.stringify(fields)).not.toContain('SECRET-PATH');
      expect(written.join('').split(href).length - 1).toBe(1);
      expect(written.join('')).not.toContain('SECRET-PATH');
    } finally {
      stderr.mockRestore();
    }
  });
});

describe('no display is guessed: a launcher failing is the ordinary presentation failure', () => {
  it('Linux, no DISPLAY: the URL on stderr once, the login waits, process.env untouched; the signal ends it', async () => {
    onPlatform('linux');
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    const before = { ...process.env };
    fakeChild.outcome = () => 4;
    const written: string[] = [];
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      });
    try {
      const port = await getAvailablePort();
      const controller = new AbortController();
      const url = (redirectUri: string) =>
        `https://idp.example/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${STATE}`;
      let done = false;
      const login = composeAuthorization({
        presentation: openInBrowser({ browser: systemBrowser() }),
        transport: loopback4({ port }),
        protocol: oauthCode(),
        endpoint: '/callback',
      })
        .authorize({
          buildAuthorizationUrl: async (redirectUri) => url(redirectUri),
          signal: controller.signal,
        })
        .then(
          () => undefined,
          (error: unknown) => error,
        )
        .finally(() => {
          done = true;
        });
      const shown = url(`http://127.0.0.1:${port}/callback`);
      for (let i = 0; i < 200 && !written.join('').includes(shown); i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      expect(spawned.map((call) => call.command)).toEqual(['xdg-open']);
      expect(written.join('').split(shown).length - 1).toBe(1);
      expect(done).toBe(false);
      expect({ ...process.env }).toEqual(before);
      controller.abort();
      expect(readFailure(await login, 'browser-login').facts).toEqual({
        outcome: 'aborted',
        strategy: 'browser',
      });
    } finally {
      stderr.mockRestore();
    }
  });
});

// Runs on Linux, where the launchers are found on PATH; skipped elsewhere.
const onLinux = realPlatform === 'linux' ? it : it.skip;

describe('for real: a hostile URL runs nothing', () => {
  onLinux.each<Name>(['systemBrowser', 'chromeBrowser'])(
    '%s reaches its launcher as one argument; no MARKER is created',
    async (name) => {
      fakeChild.record = false;
      const unregister: (() => void)[] = [];
      const dir = mkdtempSync(join(tmpdir(), 'browser-'));
      const out = join(dir, 'argv.json');
      for (const program of ['xdg-open', 'google-chrome']) {
        const path = join(dir, program);
        writeFileSync(
          path,
          `#!${process.execPath}\nrequire("fs").writeFileSync(${JSON.stringify(out)}, JSON.stringify(process.argv.slice(2)))\n`,
        );
        chmodSync(path, 0o755);
        fakeChild.real[program] = path;
        unregister.push(allowExecutable(path));
      }
      const markers = () =>
        readdirSync(process.cwd()).filter((f) => f.startsWith('MARKER'));
      try {
        await factories[name]().open(HOSTILE, never);
        // Until the fake wrote its argv (a shell would background it at the
        // `&`), then let anything a shell would have started finish.
        for (let i = 0; i < 100 && !existsSync(out); i += 1) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        await new Promise((resolve) => setTimeout(resolve, 300));
        // First: nothing ran (with a shell, `$(…)`, the backticks and the
        // `;` would have created these).
        expect(markers()).toEqual([]);
        expect(JSON.parse(readFileSync(out, 'utf8'))).toEqual([href]);
      } finally {
        for (const marker of markers()) rmSync(marker, { force: true });
        for (const close of unregister) close();
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});
