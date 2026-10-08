/**
 * The shipped browsers (spec §6d, §6a0): `systemBrowser()`, `chromeBrowser()`,
 * `edgeBrowser()`, `firefoxBrowser()` implement `IBrowser` with today's
 * launch — the `open` package when it loads, else a launcher started with an
 * argument array and no shell: `xdg-open` / the browser's executables on
 * Linux, `open` (`-a <app>`) on macOS, and on Windows `rundll32` or
 * PowerShell's `Start-Process` (the URL only in the environment), both by
 * absolute path under `%SystemRoot%\System32`. Only an `http(s)` URL is
 * launched, as its serialisation.
 *
 * `open` resolves once the browser was asked to open the URL and rejects
 * when it could not be, with an `AuthProviderFailure` (`unknown`,
 * `opening-browser`, an allowlisted code) — no URL, no `state`, no
 * launcher text.
 *
 * - `spawn` recorded (nothing starts): each platform and browser gets the
 *   exact URL as one argument, no `shell` option, never `exec`;
 * - `open` mocked: each named browser reaches it under the per-platform
 *   names `open` ships;
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
import { delimiter, join } from 'node:path';
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
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type { IBrowser } from '@mcp-abap-adt/interfaces-auth';

type SpawnCall = { command: string; args: string[]; options: unknown };
const spawned: SpawnCall[] = [];
const realChildProcess =
  jest.requireActual<typeof import('node:child_process')>('node:child_process');
/** How the recorded child ends: `0`, another exit code, or an error. */
const fakeChild: {
  record: boolean;
  outcome: (index: number) => number | Error;
} = { record: true, outcome: () => 0 };

jest.mock('node:child_process', () => ({
  ...jest.requireActual<Record<string, unknown>>('node:child_process'),
  spawn: (command: string, args: string[], options: unknown) => {
    if (!fakeChild.record) {
      return realChildProcess.spawn(
        command,
        args,
        options as Parameters<typeof realChildProcess.spawn>[2],
      );
    }
    const index = spawned.length;
    spawned.push({ command, args, options });
    const { EventEmitter } =
      jest.requireActual<typeof import('node:events')>('node:events');
    const child = new EventEmitter() as InstanceType<typeof EventEmitter> & {
      unref(): void;
    };
    child.unref = () => undefined;
    const outcome = fakeChild.outcome(index);
    setImmediate(() =>
      outcome instanceof Error
        ? child.emit('error', outcome)
        : child.emit('exit', outcome),
    );
    return child;
  },
  exec: () => {
    throw new Error('exec must never be called');
  },
  execSync: () => {
    throw new Error('execSync must never be called');
  },
}));

type OpenFn = (url: string, options?: unknown) => Promise<unknown>;
const mockOpen: {
  default: OpenFn | undefined;
  apps: Record<string, string | string[]> | undefined;
} = { default: undefined, apps: undefined };
jest.mock('open', () => ({
  __esModule: true,
  get default() {
    return mockOpen.default;
  },
  get apps() {
    return mockOpen.apps;
  },
}));

import { launchableUrl, URL_VARIABLE } from '../../auth/browserLaunch';
import {
  chromeBrowser,
  edgeBrowser,
  firefoxBrowser,
  systemBrowser,
} from '../../index';

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
const savedEnv = { ...process.env };

function onPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', { value: platform });
}

const never = new AbortController().signal;

beforeEach(() => {
  mockOpen.default = undefined;
  mockOpen.apps = undefined;
  fakeChild.record = true;
  fakeChild.outcome = () => 0;
  spawned.length = 0;
});
afterEach(() => {
  onPlatform(realPlatform);
  process.env = { ...savedEnv };
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

describe('without the open package: an argument array, no shell', () => {
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

  it('Linux: the next executable when one cannot start or exits non-zero; resolved on the first that runs', async () => {
    onPlatform('linux');
    fakeChild.outcome = (index) =>
      index === 0 ? Object.assign(new Error('nope'), { code: 'ENOENT' }) : 1;
    // google-chrome errors, chromium exits 1, chromium-browser exits 1: all fail.
    const failed = await chromeBrowser()
      .open(HOSTILE, never)
      .catch((e: unknown) => e);
    expect(spawned.map((call) => call.command)).toEqual([
      'google-chrome',
      'chromium',
      'chromium-browser',
    ]);
    expect(isAuthProviderFailure(failed)).toBe(true);

    spawned.length = 0;
    fakeChild.outcome = (index) => (index < 2 ? 1 : 0);
    await expect(chromeBrowser().open(HOSTILE, never)).resolves.toBe(undefined);
    expect(spawned).toHaveLength(3);
  });

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
      mockOpen.default = jest.fn(async () => undefined);
      const failure = await systemBrowser()
        .open(url, never)
        .catch((e: unknown) => e);
      expect(isAuthProviderFailure(failure)).toBe(true);
      expect(rendered(failure)).not.toContain(url);
      expect(spawned).toEqual([]);
      expect(mockOpen.default).not.toHaveBeenCalled();
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
      return 1;
    };
    await expect(
      chromeBrowser().open(HOSTILE, controller.signal),
    ).rejects.toBeInstanceOf(AuthProviderFailure);
    expect(spawned.map((call) => call.command)).toEqual(['google-chrome']);
  });

  it('Linux without a display: DISPLAY=:0 for the launcher (as today)', async () => {
    onPlatform('linux');
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    await systemBrowser().open(HOSTILE, never);
    expect(process.env.DISPLAY).toBe(':0');
  });
});

describe('with the open package: today’s app names', () => {
  const apps = {
    chrome: ['chrome-name-a', 'chrome-name-b'],
    edge: ['edge-name-a'],
    firefox: 'firefox-name',
  };

  it.each<[Name, unknown]>([
    ['systemBrowser', undefined],
    ['chromeBrowser', { app: { name: apps.chrome } }],
    ['edgeBrowser', { app: { name: apps.edge } }],
    ['firefoxBrowser', { app: { name: apps.firefox } }],
  ])('%s: open(href, %j)', async (name, options) => {
    const open = jest.fn<OpenFn>(async () => undefined);
    mockOpen.default = open;
    mockOpen.apps = apps;
    await expect(factories[name]().open(HOSTILE, never)).resolves.toBe(
      undefined,
    );
    expect(open).toHaveBeenCalledTimes(1);
    expect(open.mock.calls[0]?.[0]).toBe(href);
    expect(open.mock.calls[0]?.[1]).toEqual(options);
    expect(spawned).toEqual([]);
  });

  it('without open’s apps a named browser goes by its own name', async () => {
    const open = jest.fn<OpenFn>(async () => undefined);
    mockOpen.default = open;
    await edgeBrowser().open(HOSTILE, never);
    expect(open.mock.calls[0]?.[1]).toEqual({ app: { name: 'msedge' } });
  });

  it('open rejecting rejects in fixed words, keeping an allowlisted code', async () => {
    mockOpen.default = async () => {
      throw Object.assign(new Error(`spawn SECRET-PATH ${HOSTILE}`), {
        code: 'ENOENT',
      });
    };
    const failure = await chromeBrowser()
      .open(HOSTILE, never)
      .catch((e: unknown) => e);
    expect(readFailure(failure, 'opening-browser')).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'opening-browser', code: 'ENOENT' },
    });
    const text = rendered(failure);
    expect(text).not.toContain('idp.example');
    expect(text).not.toContain('SECRET-PATH');
  });
});

// Runs on Linux, where the launchers are found on PATH; skipped elsewhere.
const onLinux = realPlatform === 'linux' ? it : it.skip;

describe('for real: a hostile URL runs nothing', () => {
  onLinux.each<Name>(['systemBrowser', 'chromeBrowser'])(
    '%s reaches its launcher as one argument; no MARKER is created',
    async (name) => {
      fakeChild.record = false;
      const dir = mkdtempSync(join(tmpdir(), 'browser-'));
      const out = join(dir, 'argv.json');
      for (const program of ['xdg-open', 'google-chrome']) {
        const path = join(dir, program);
        writeFileSync(
          path,
          `#!${process.execPath}\nrequire("fs").writeFileSync(${JSON.stringify(out)}, JSON.stringify(process.argv.slice(2)))\n`,
        );
        chmodSync(path, 0o755);
      }
      process.env.PATH = `${dir}${delimiter}${savedEnv.PATH ?? ''}`;
      const markers = () =>
        readdirSync(process.cwd()).filter((f) => f.startsWith('MARKER'));
      try {
        await factories[name]().open(HOSTILE, never);
        expect(existsSync(out)).toBe(true);
        // Let anything a shell would have started finish.
        await new Promise((resolve) => setTimeout(resolve, 300));
        expect(markers()).toEqual([]);
        expect(JSON.parse(readFileSync(out, 'utf8'))).toEqual([href]);
      } finally {
        for (const marker of markers()) rmSync(marker, { force: true });
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});
