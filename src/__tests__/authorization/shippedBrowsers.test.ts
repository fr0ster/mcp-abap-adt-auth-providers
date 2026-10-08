/**
 * The shipped browsers: six `IBrowser` factories, each ONE fixed
 * launch — no platform switch, no fallback chain, no platform check. The
 * consumer picks the one for its machine; run on another OS a launch simply
 * fails to start and rejects. Every launch is a program started with an
 * argument array, never a shell; only an `http(s)` URL is launched, as its
 * serialisation.
 *
 * | Factory | Program, arguments | Settles |
 * |---|---|---|
 * | `linuxDefaultBrowser()` | `xdg-open <url>` | exit `0` |
 * | `linuxBrowser(executable)` | `<executable> <url>` | its `spawn` |
 * | `macDefaultBrowser()` | `open <url>` | exit `0` |
 * | `macBrowser(app)` | `open -a <app> <url>` | exit `0` |
 * | `windowsDefaultBrowser()` | `System32\rundll32.exe url.dll,FileProtocolHandler <url>` | exit `0` |
 * | `windowsBrowser(program)` | `System32\…\powershell.exe … -Command <fixed text>`, program and URL in the environment | exit `0` |
 *
 * A hand-off launcher's non-zero exit or an error before its spawn rejects;
 * a browser binary resolves at its spawn and its exit is never awaited. The
 * rejection is an `AuthProviderFailure` (`unknown`, `opening-browser`, an
 * allowlisted code) — no URL, no `state`, no launcher text; an abort
 * rejects `aborted`; a started browser is never killed.
 *
 * Tested through the mocked `child_process` boundary only (recorded, or a
 * registered fake script for real).
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
 * launch runs for real as the fake program `real` names for its command —
 * never the system's own (a command it does not name is refused, and the
 * suite's guard starts only registered paths).
 */
const fakeChild: {
  record: boolean;
  outcome: (index: number) => number | Error | 'running';
  real: Record<string, string>;
  running: FakeChild[];
  killed: number;
  unrefs: number;
} = {
  record: true,
  outcome: () => 0,
  real: {},
  running: [],
  killed: 0,
  unrefs: 0,
};

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
    child.unref = () => {
      fakeChild.unrefs += 1;
    };
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

import {
  launchableUrl,
  PROGRAM_VARIABLE,
  URL_VARIABLE,
} from '../../auth/browserLaunch';
import {
  composeAuthorization,
  linuxBrowser,
  linuxDefaultBrowser,
  loopback4,
  macBrowser,
  macDefaultBrowser,
  oauthCode,
  openInBrowser,
  windowsBrowser,
  windowsDefaultBrowser,
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
const RUNDLL32 = 'C:\\Windows\\System32\\rundll32.exe';
const POWERSHELL =
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const START_PROCESS = `Start-Process -FilePath $env:${PROGRAM_VARIABLE} -ArgumentList $env:${URL_VARIABLE}`;
/** The variables a test changes, restored key by key (`process.env` itself stays). */
const ENV_KEYS = ['DISPLAY', 'WAYLAND_DISPLAY', 'SystemRoot'] as const;
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
  fakeChild.unrefs = 0;
  spawned.length = 0;
  delete process.env.SystemRoot;
});
afterEach(() => {
  onPlatform(realPlatform);
  for (const key of ENV_KEYS) {
    const value = savedEnv[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/** Every factory, built once per call, with a fixed argument where it takes one. */
const factories = {
  linuxDefaultBrowser: () => linuxDefaultBrowser(),
  linuxBrowser: () => linuxBrowser('google-chrome'),
  macDefaultBrowser: () => macDefaultBrowser(),
  macBrowser: () => macBrowser('Google Chrome'),
  windowsDefaultBrowser: () => windowsDefaultBrowser(),
  windowsBrowser: () => windowsBrowser('chrome'),
} as const;
type Name = keyof typeof factories;
const NAMES = Object.keys(factories) as Name[];
const HAND_OFF = NAMES.filter((name) => name !== 'linuxBrowser');

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

async function untilRunning(): Promise<void> {
  for (let i = 0; i < 20 && fakeChild.running.length === 0; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

describe('each factory is an IBrowser', () => {
  it.each(NAMES)('%s(): a frozen object whose only member is open', (name) => {
    const browser: IBrowser = factories[name]();
    expect(Object.keys(browser)).toEqual(['open']);
    expect(typeof browser.open).toBe('function');
    expect(Object.isFrozen(browser)).toBe(true);
  });
});

describe('one fixed launch each: an argument array, no shell', () => {
  it.each<[Name, string, string[]]>([
    ['linuxDefaultBrowser', 'xdg-open', [href]],
    ['linuxBrowser', 'google-chrome', [href]],
    ['macDefaultBrowser', 'open', [href]],
    ['macBrowser', 'open', ['-a', 'Google Chrome', href]],
    ['windowsDefaultBrowser', RUNDLL32, ['url.dll,FileProtocolHandler', href]],
  ])('%s: %s', async (name, command, args) => {
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
    const options = call.options as { shell?: unknown; env?: unknown };
    expect(options.shell).toBeUndefined();
    expect(options.env).toBeUndefined();
  });

  it('windowsBrowser: PowerShell with fixed command text; the program and the URL only in the environment', async () => {
    await windowsBrowser('chrome').open(HOSTILE, never);
    expect(spawned).toHaveLength(1);
    const call = spawned[0] as SpawnCall;
    expect(call.command).toBe(POWERSHELL);
    expect(call.args).toEqual([
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      START_PROCESS,
    ]);
    const options = call.options as {
      shell?: unknown;
      env?: Record<string, string>;
    };
    expect(options.shell).toBeUndefined();
    expect(options.env?.[URL_VARIABLE]).toBe(href);
    expect(options.env?.[PROGRAM_VARIABLE]).toBe('chrome');
  });

  it.each([
    `chrome'; Start-Process calc; '`,
    '$(Start-Process calc)',
    'chrome" -ArgumentList "x"; calc; "',
    '`calc`',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  ])(
    'windowsBrowser(%j): the program never appears in the command text',
    async (program) => {
      await windowsBrowser(program).open(HOSTILE, never);
      const call = spawned[0] as SpawnCall;
      expect(call.args).toEqual([
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        START_PROCESS,
      ]);
      expect(call.args.some((arg) => arg.includes(program))).toBe(false);
      expect(
        (call.options as { env?: Record<string, string> }).env?.[
          PROGRAM_VARIABLE
        ],
      ).toBe(program);
    },
  );

  it.each<[string, () => IBrowser, string, string[]]>([
    [
      'linuxBrowser, an absolute path with a space',
      () => linuxBrowser('/opt/my browser/bin/browser'),
      '/opt/my browser/bin/browser',
      [href],
    ],
    [
      'linuxBrowser, a name beginning with -',
      () => linuxBrowser('-x'),
      '-x',
      [href],
    ],
    [
      'macBrowser, an app name with quotes and a semicolon',
      () => macBrowser(`My "App"; rm -rf ~`),
      'open',
      ['-a', `My "App"; rm -rf ~`, href],
    ],
  ])('%s: the string as given', async (_name, make, command, args) => {
    await make().open(HOSTILE, never);
    const call = spawned[0] as SpawnCall;
    expect(call.command).toBe(command);
    expect(call.args).toEqual(args);
  });

  it('the Windows launches sit under SystemRoot (C:\\Windows without it)', async () => {
    process.env.SystemRoot = 'D:\\Win';
    await windowsDefaultBrowser().open(HOSTILE, never);
    await windowsBrowser('chrome').open(HOSTILE, never);
    expect(spawned.map((call) => call.command)).toEqual([
      'D:\\Win\\System32\\rundll32.exe',
      'D:\\Win\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ]);
  });

  it.each<NodeJS.Platform>(['linux', 'darwin', 'win32'])(
    'no platform check: on %s every factory makes its own launch, and none is cmd',
    async (platform) => {
      onPlatform(platform);
      for (const name of NAMES) await factories[name]().open(HOSTILE, never);
      expect(spawned.map((call) => call.command)).toEqual([
        'xdg-open',
        'google-chrome',
        'open',
        'open',
        RUNDLL32,
        POWERSHELL,
      ]);
      for (const call of spawned) {
        const last = call.command.split('\\').pop()?.toLowerCase();
        expect(last === 'cmd' || last === 'cmd.exe').toBe(false);
      }
    },
  );
});

describe('settlement: a hand-off launcher at its exit, a browser binary at its spawn', () => {
  it.each(HAND_OFF)(
    '%s: awaited to its exit 0 — pending while the launcher runs',
    async (name) => {
      fakeChild.outcome = () => 'running';
      let settled = false;
      const opened = factories[name]()
        .open(HOSTILE, never)
        .finally(() => {
          settled = true;
        });
      await untilRunning();
      await new Promise((resolve) => setImmediate(resolve));
      expect(fakeChild.running).toHaveLength(1);
      expect(settled).toBe(false);
      fakeChild.running[0]?.emit('exit', 0);
      await expect(opened).resolves.toBe(undefined);
    },
  );

  it.each(HAND_OFF)(
    '%s: a non-zero exit after its spawn rejects, with no code',
    async (name) => {
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

  it.each(NAMES)(
    '%s: an error before its spawn rejects in fixed words, keeping an allowlisted code — no URL, no state, no launcher text',
    async (name) => {
      fakeChild.outcome = () =>
        Object.assign(new Error(`spawn SECRET-PATH ${HOSTILE}`), {
          code: 'ENOENT',
          spawnargs: [HOSTILE],
        });
      const failure = await factories[name]()
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
      // One launch, no fallback chain.
      expect(spawned).toHaveLength(1);
    },
  );

  it('linuxBrowser: resolves at its spawn while the browser keeps running; its exit is never awaited', async () => {
    fakeChild.outcome = () => 'running';
    await expect(
      linuxBrowser('google-chrome').open(HOSTILE, never),
    ).resolves.toBe(undefined);
    expect(fakeChild.running).toHaveLength(1);
  });

  it('linuxBrowser: a browser that started and later exits non-zero was still asked', async () => {
    fakeChild.outcome = () => 1;
    await expect(linuxBrowser('firefox').open(HOSTILE, never)).resolves.toBe(
      undefined,
    );
    expect(spawned).toHaveLength(1);
  });

  it.each(HAND_OFF)(
    '%s: an abort while the launcher runs rejects aborted; the child is not killed',
    async (name) => {
      fakeChild.outcome = () => 'running';
      const controller = new AbortController();
      const opened = factories[name]()
        .open(HOSTILE, controller.signal)
        .catch((e: unknown) => e);
      await untilRunning();
      controller.abort();
      expect(readFailure(await opened, 'browser-login').facts).toEqual({
        outcome: 'aborted',
      });
      expect(fakeChild.killed).toBe(0);
      // Its later exit changes nothing.
      fakeChild.running[0]?.emit('exit', 0);
    },
  );

  it.each(HAND_OFF)(
    '%s: the launcher stays referenced while it runs; an abort unreferences it, never kills it',
    async (name) => {
      fakeChild.outcome = () => 'running';
      const controller = new AbortController();
      const opened = factories[name]().open(HOSTILE, controller.signal);
      const rejected =
        expect(opened).rejects.toBeInstanceOf(AuthProviderFailure);
      await untilRunning();
      expect(fakeChild.unrefs).toBe(0);
      controller.abort();
      await rejected;
      expect(fakeChild.unrefs).toBe(1);
      expect(fakeChild.killed).toBe(0);
    },
  );

  it('linuxBrowser: unreferenced once started', async () => {
    fakeChild.outcome = () => 'running';
    await linuxBrowser('google-chrome').open(HOSTILE, never);
    expect(fakeChild.unrefs).toBe(1);
  });

  it('linuxBrowser: an abort while the browser starts rejects aborted; nothing is killed', async () => {
    const controller = new AbortController();
    fakeChild.outcome = () => {
      controller.abort();
      return 'running';
    };
    await expect(
      linuxBrowser('google-chrome').open(HOSTILE, controller.signal),
    ).rejects.toBeInstanceOf(AuthProviderFailure);
    expect(fakeChild.killed).toBe(0);
  });

  it.each(NAMES)(
    '%s: no signal, or no real AbortSignal, starts nothing and rejects in fixed words',
    async (name) => {
      const notSignals: unknown[] = [
        undefined,
        { aborted: false, addEventListener() {}, removeEventListener() {} },
        Object.create(AbortSignal.prototype),
      ];
      for (const notSignal of notSignals) {
        const failure = await factories[name]()
          .open(HOSTILE, notSignal as AbortSignal)
          .catch((e: unknown) => e);
        expect(isAuthProviderFailure(failure)).toBe(true);
        expect(readFailure(failure, 'opening-browser').facts).toEqual({
          operation: 'opening-browser',
        });
      }
      expect(spawned).toEqual([]);
    },
  );

  it.each(NAMES)(
    '%s: an aborted signal starts nothing and rejects',
    async (name) => {
      const controller = new AbortController();
      controller.abort();
      await expect(
        factories[name]().open(HOSTILE, controller.signal),
      ).rejects.toBeInstanceOf(AuthProviderFailure);
      expect(spawned).toEqual([]);
    },
  );

  it.each(['javascript:alert(1)', 'file:///etc/passwd', 'not a url'])(
    'a URL that is not http(s) (%j) starts nothing and rejects',
    async (url) => {
      for (const name of NAMES) {
        const failure = await factories[name]()
          .open(url, never)
          .catch((e: unknown) => e);
        expect(isAuthProviderFailure(failure)).toBe(true);
        expect(rendered(failure)).not.toContain(url);
      }
      expect(spawned).toEqual([]);
    },
  );
});

describe('no environment is guessed or changed', () => {
  it.each(NAMES)(
    '%s without a display: process.env is left as it was',
    async (name) => {
      delete process.env.DISPLAY;
      delete process.env.WAYLAND_DISPLAY;
      const before = { ...process.env };
      await factories[name]().open(HOSTILE, never);
      expect('DISPLAY' in process.env).toBe(false);
      expect('WAYLAND_DISPLAY' in process.env).toBe(false);
      expect({ ...process.env }).toEqual(before);
    },
  );

  it('a launcher failing is the ordinary presentation failure: the URL on stderr once, the login waits; the signal ends it', async () => {
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
        presentation: openInBrowser({ browser: linuxDefaultBrowser() }),
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

describe('through openInBrowser: the failure in fixed words, the URL prompted once', () => {
  it.each([
    [
      'the launcher failing to start',
      (): Error =>
        Object.assign(new Error(`SECRET-PATH ${HOSTILE}`), { code: 'ENOENT' }),
      'opening the browser failed (unknown error, ENOENT)',
    ],
    [
      'the hand-off launcher exiting non-zero',
      (): number => 2,
      'opening the browser failed (unknown error)',
    ],
  ] as const)('%s', async (_name, outcome, words) => {
    fakeChild.outcome = outcome;
    const written: string[] = [];
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      });
    try {
      const presented = openInBrowser({
        browser: linuxDefaultBrowser(),
      }).present(HOSTILE, {
        signal: never,
        redirectUri: undefined,
        waitingOn: undefined,
        routeHint: undefined,
      });
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

// Runs on Linux, where a fake script can stand in; skipped elsewhere.
const onLinux = realPlatform === 'linux' ? it : it.skip;

describe('for real: a hostile URL runs nothing', () => {
  onLinux.each<'linuxDefaultBrowser' | 'linuxBrowser'>([
    'linuxDefaultBrowser',
    'linuxBrowser',
  ])(
    '%s reaches its program as one argument; no MARKER is created',
    async (name) => {
      fakeChild.record = false;
      const unregister: (() => void)[] = [];
      const dir = mkdtempSync(join(tmpdir(), 'browser-'));
      const out = join(dir, 'argv.json');
      const fakeBrowser = join(dir, 'fake-browser');
      for (const [command, path] of [
        ['xdg-open', join(dir, 'xdg-open')],
        [fakeBrowser, fakeBrowser],
      ] as const) {
        writeFileSync(
          path,
          `#!${process.execPath}\nrequire("fs").writeFileSync(${JSON.stringify(out)}, JSON.stringify(process.argv.slice(2)))\n`,
        );
        chmodSync(path, 0o755);
        fakeChild.real[command] = path;
        unregister.push(allowExecutable(path));
      }
      const browser =
        name === 'linuxDefaultBrowser'
          ? linuxDefaultBrowser()
          : linuxBrowser(fakeBrowser);
      const markers = () =>
        readdirSync(process.cwd()).filter((f) => f.startsWith('MARKER'));
      try {
        await browser.open(HOSTILE, never);
        // Until the fake wrote its argv, then let anything a shell would
        // have started finish.
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
