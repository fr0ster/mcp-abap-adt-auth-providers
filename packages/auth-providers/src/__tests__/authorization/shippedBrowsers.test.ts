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

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
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
import { afterEach, beforeEach, describe, it, mock } from 'node:test';

import childProcess = require('node:child_process');

import {
  AuthProviderFailure,
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type { IBrowser } from '@mcp-abap-adt/interfaces-auth';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
  thrown,
} from '../helpers/expectations';

type SpawnCall = { command: string; args: string[]; options: unknown };
const spawned: SpawnCall[] = [];
// The spawn the guard wrapped, kept before this file's mock replaces it.
const realChildProcess = { spawn: childProcess.spawn };
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

// node:child_process's spawn (and exec) replaced on the module object for the
// whole file: browserLaunch reads `child_process.spawn` at each call.
mock.method(
  childProcess,
  'spawn',
  (command: string, args: string[], options: unknown) => {
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
);
mock.method(childProcess, 'exec', () => {
  throw new Error('exec must never be called');
});
mock.method(childProcess, 'execSync', () => {
  throw new Error('execSync must never be called');
});

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
  for (const [caseIndex, caseRow] of NAMES.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s(): a frozen object whose only member is open',
        caseRow,
        caseIndex,
      ),
      () => {
        const browser: IBrowser = factories[name]();
        assert.deepEqual(Object.keys(browser), ['open']);
        assert.equal(typeof browser.open, 'function');
        assert.equal(Object.isFrozen(browser), true);
      },
    );
  }
});

describe('one fixed launch each: an argument array, no shell', () => {
  for (const [caseIndex, caseRow] of cases<[Name, string, string[]]>([
    ['linuxDefaultBrowser', 'xdg-open', [href]],
    ['linuxBrowser', 'google-chrome', [href]],
    ['macDefaultBrowser', 'open', [href]],
    ['macBrowser', 'open', ['-a', 'Google Chrome', href]],
    ['windowsDefaultBrowser', RUNDLL32, ['url.dll,FileProtocolHandler', href]],
  ]).entries()) {
    const [name, command, args] = caseRow;
    it(caseTitle('%s: %s', caseRow, caseIndex), async () => {
      assert.equal(await factories[name]().open(HOSTILE, never), undefined);
      assert.equal(spawned.length, 1);
      const call = spawned[0] as SpawnCall;
      assert.equal(call.command, command);
      assert.deepEqual(call.args, args);
      assert.deepEqual(
        call.args.filter((arg) => arg.includes('idp.example')),
        [href],
      );
      const options = call.options as { shell?: unknown; env?: unknown };
      assert.equal(options.shell, undefined);
      assert.equal(options.env, undefined);
    });
  }

  it('windowsBrowser: PowerShell with fixed command text; the program and the URL only in the environment', async () => {
    await windowsBrowser('chrome').open(HOSTILE, never);
    assert.equal(spawned.length, 1);
    const call = spawned[0] as SpawnCall;
    assert.equal(call.command, POWERSHELL);
    assert.deepEqual(call.args, [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      START_PROCESS,
    ]);
    const options = call.options as {
      shell?: unknown;
      env?: Record<string, string>;
    };
    assert.equal(options.shell, undefined);
    assert.equal(options.env?.[URL_VARIABLE], href);
    assert.equal(options.env?.[PROGRAM_VARIABLE], 'chrome');
  });

  for (const [caseIndex, caseRow] of [
    `chrome'; Start-Process calc; '`,
    '$(Start-Process calc)',
    'chrome" -ArgumentList "x"; calc; "',
    '`calc`',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  ].entries()) {
    const program = caseRow;
    it(
      caseTitle(
        'windowsBrowser(%j): the program never appears in the command text',
        caseRow,
        caseIndex,
      ),
      async () => {
        await windowsBrowser(program).open(HOSTILE, never);
        const call = spawned[0] as SpawnCall;
        assert.deepEqual(call.args, [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          START_PROCESS,
        ]);
        assert.equal(
          call.args.some((arg) => arg.includes(program)),
          false,
        );
        assert.equal(
          (call.options as { env?: Record<string, string> }).env?.[
            PROGRAM_VARIABLE
          ],
          program,
        );
      },
    );
  }

  for (const [caseIndex, caseRow] of cases([
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
  ]).entries()) {
    const [_name, make, command, args] = caseRow;
    it(caseTitle('%s: the string as given', caseRow, caseIndex), async () => {
      await make().open(HOSTILE, never);
      const call = spawned[0] as SpawnCall;
      assert.equal(call.command, command);
      assert.deepEqual(call.args, args);
    });
  }

  it('the Windows launches sit under SystemRoot (C:\\Windows without it)', async () => {
    process.env.SystemRoot = 'D:\\Win';
    await windowsDefaultBrowser().open(HOSTILE, never);
    await windowsBrowser('chrome').open(HOSTILE, never);
    assert.deepEqual(
      spawned.map((call) => call.command),
      [
        'D:\\Win\\System32\\rundll32.exe',
        'D:\\Win\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ],
    );
  });

  const platforms: NodeJS.Platform[] = ['linux', 'darwin', 'win32'];
  for (const [caseIndex, caseRow] of platforms.entries()) {
    const platform = caseRow;
    it(
      caseTitle(
        'no platform check: on %s every factory makes its own launch, and none is cmd',
        caseRow,
        caseIndex,
      ),
      async () => {
        onPlatform(platform);
        for (const name of NAMES) await factories[name]().open(HOSTILE, never);
        assert.deepEqual(
          spawned.map((call) => call.command),
          ['xdg-open', 'google-chrome', 'open', 'open', RUNDLL32, POWERSHELL],
        );
        for (const call of spawned) {
          const last = call.command.split('\\').pop()?.toLowerCase();
          assert.equal(last === 'cmd' || last === 'cmd.exe', false);
        }
      },
    );
  }
});

describe('settlement: a hand-off launcher at its exit, a browser binary at its spawn', () => {
  for (const [caseIndex, caseRow] of HAND_OFF.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s: awaited to its exit 0 — pending while the launcher runs',
        caseRow,
        caseIndex,
      ),
      async () => {
        fakeChild.outcome = () => 'running';
        let settled = false;
        const opened = factories[name]()
          .open(HOSTILE, never)
          .finally(() => {
            settled = true;
          });
        await untilRunning();
        await new Promise((resolve) => setImmediate(resolve));
        assert.equal(fakeChild.running.length, 1);
        assert.equal(settled, false);
        fakeChild.running[0]?.emit('exit', 0);
        assert.equal(await opened, undefined);
      },
    );
  }

  for (const [caseIndex, caseRow] of HAND_OFF.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s: a non-zero exit after its spawn rejects, with no code',
        caseRow,
        caseIndex,
      ),
      async () => {
        fakeChild.outcome = () => 1;
        const failure = await factories[name]()
          .open(HOSTILE, never)
          .catch((e: unknown) => e);
        assert.deepEqual(readFailure(failure, 'opening-browser').facts, {
          operation: 'opening-browser',
        });
        assert.equal(spawned.length, 1);
      },
    );
  }

  for (const [caseIndex, caseRow] of NAMES.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s: an error before its spawn rejects in fixed words, keeping an allowlisted code — no URL, no state, no launcher text',
        caseRow,
        caseIndex,
      ),
      async () => {
        fakeChild.outcome = () =>
          Object.assign(new Error(`spawn SECRET-PATH ${HOSTILE}`), {
            code: 'ENOENT',
            spawnargs: [HOSTILE],
          });
        const failure = await factories[name]()
          .open(HOSTILE, never)
          .catch((e: unknown) => e);
        assert.equal(isAuthProviderFailure(failure), true);
        matchObject(readFailure(failure, 'opening-browser'), {
          kind: 'unknown',
          facts: { operation: 'opening-browser', code: 'ENOENT' },
        });
        const text = rendered(failure);
        notContains(text, 'idp.example');
        notContains(text, STATE);
        notContains(text, 'SECRET-PATH');
        // One launch, no fallback chain.
        assert.equal(spawned.length, 1);
      },
    );
  }

  it('linuxBrowser: resolves at its spawn while the browser keeps running; its exit is never awaited', async () => {
    fakeChild.outcome = () => 'running';
    assert.equal(
      await linuxBrowser('google-chrome').open(HOSTILE, never),
      undefined,
    );
    assert.equal(fakeChild.running.length, 1);
  });

  it('linuxBrowser: a browser that started and later exits non-zero was still asked', async () => {
    fakeChild.outcome = () => 1;
    assert.equal(await linuxBrowser('firefox').open(HOSTILE, never), undefined);
    assert.equal(spawned.length, 1);
  });

  for (const [caseIndex, caseRow] of HAND_OFF.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s: an abort while the launcher runs rejects aborted; the child is not killed',
        caseRow,
        caseIndex,
      ),
      async () => {
        fakeChild.outcome = () => 'running';
        const controller = new AbortController();
        const opened = factories[name]()
          .open(HOSTILE, controller.signal)
          .catch((e: unknown) => e);
        await untilRunning();
        controller.abort();
        assert.deepEqual(readFailure(await opened, 'browser-login').facts, {
          outcome: 'aborted',
        });
        assert.equal(fakeChild.killed, 0);
        // Its later exit changes nothing.
        fakeChild.running[0]?.emit('exit', 0);
      },
    );
  }

  for (const [caseIndex, caseRow] of HAND_OFF.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s: the launcher stays referenced while it runs; an abort unreferences it, never kills it',
        caseRow,
        caseIndex,
      ),
      async () => {
        fakeChild.outcome = () => 'running';
        const controller = new AbortController();
        const opened = factories[name]().open(HOSTILE, controller.signal);
        const rejected = assert.rejects(opened, thrown(AuthProviderFailure));
        await untilRunning();
        assert.equal(fakeChild.unrefs, 0);
        controller.abort();
        await rejected;
        assert.equal(fakeChild.unrefs, 1);
        assert.equal(fakeChild.killed, 0);
      },
    );
  }

  it('linuxBrowser: unreferenced once started', async () => {
    fakeChild.outcome = () => 'running';
    await linuxBrowser('google-chrome').open(HOSTILE, never);
    assert.equal(fakeChild.unrefs, 1);
  });

  it('linuxBrowser: an abort while the browser starts rejects aborted; nothing is killed', async () => {
    const controller = new AbortController();
    fakeChild.outcome = () => {
      controller.abort();
      return 'running';
    };
    await assert.rejects(
      linuxBrowser('google-chrome').open(HOSTILE, controller.signal),
      thrown(AuthProviderFailure),
    );
    assert.equal(fakeChild.killed, 0);
  });

  for (const [caseIndex, caseRow] of NAMES.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s: an aborted signal starts nothing and rejects',
        caseRow,
        caseIndex,
      ),
      async () => {
        const controller = new AbortController();
        controller.abort();
        await assert.rejects(
          factories[name]().open(HOSTILE, controller.signal),
          thrown(AuthProviderFailure),
        );
        assert.deepEqual(spawned, []);
      },
    );
  }

  for (const [caseIndex, caseRow] of [
    'javascript:alert(1)',
    'file:///etc/passwd',
    'not a url',
  ].entries()) {
    const url = caseRow;
    it(
      caseTitle(
        'a URL that is not http(s) (%j) starts nothing and rejects',
        caseRow,
        caseIndex,
      ),
      async () => {
        for (const name of NAMES) {
          const failure = await factories[name]()
            .open(url, never)
            .catch((e: unknown) => e);
          assert.equal(isAuthProviderFailure(failure), true);
          notContains(rendered(failure), url);
        }
        assert.deepEqual(spawned, []);
      },
    );
  }
});

describe('no environment is guessed or changed', () => {
  for (const [caseIndex, caseRow] of NAMES.entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s without a display: process.env is left as it was',
        caseRow,
        caseIndex,
      ),
      async () => {
        delete process.env.DISPLAY;
        delete process.env.WAYLAND_DISPLAY;
        const before = { ...process.env };
        await factories[name]().open(HOSTILE, never);
        assert.equal('DISPLAY' in process.env, false);
        assert.equal('WAYLAND_DISPLAY' in process.env, false);
        assert.deepEqual({ ...process.env }, before);
      },
    );
  }

  it('a launcher failing is the ordinary presentation failure: the URL on stderr once, the login waits; the signal ends it', async () => {
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    const before = { ...process.env };
    fakeChild.outcome = () => 4;
    const written: string[] = [];
    const stderr = mock.method(process.stderr, 'write', (chunk: unknown) => {
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
      assert.deepEqual(
        spawned.map((call) => call.command),
        ['xdg-open'],
      );
      assert.equal(written.join('').split(shown).length - 1, 1);
      assert.equal(done, false);
      assert.deepEqual({ ...process.env }, before);
      controller.abort();
      assert.deepEqual(readFailure(await login, 'browser-login').facts, {
        outcome: 'aborted',
        strategy: 'browser',
      });
    } finally {
      stderr.mock.restore();
    }
  });
});

describe('through openInBrowser: the failure in fixed words, the URL prompted once', () => {
  for (const [caseIndex, caseRow] of (
    [
      [
        'the launcher failing to start',
        (): Error =>
          Object.assign(new Error(`SECRET-PATH ${HOSTILE}`), {
            code: 'ENOENT',
          }),
        'opening the browser failed (unknown error, ENOENT)',
      ],
      [
        'the hand-off launcher exiting non-zero',
        (): number => 2,
        'opening the browser failed (unknown error)',
      ],
    ] as const
  ).entries()) {
    const [_name, outcome, words] = caseRow;
    it(caseTitle('%s', caseRow, caseIndex), async () => {
      fakeChild.outcome = outcome;
      const written: string[] = [];
      const stderr = mock.method(process.stderr, 'write', (chunk: unknown) => {
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
        assert.deepEqual(fields, { error: words, kind: 'unknown' });
        notContains(JSON.stringify(fields), 'SECRET-PATH');
        assert.equal(written.join('').split(href).length - 1, 1);
        notContains(written.join(''), 'SECRET-PATH');
      } finally {
        stderr.mock.restore();
      }
    });
  }
});

// Runs on Linux, where a fake script can stand in; skipped elsewhere.
const onLinux = realPlatform === 'linux' ? it : it.skip;

describe('for real: a hostile URL runs nothing', () => {
  const linuxFactories: Name[] = ['linuxDefaultBrowser', 'linuxBrowser'];
  for (const [caseIndex, name] of linuxFactories.entries()) {
    onLinux(
      caseTitle(
        '%s reaches its program as one argument; no MARKER is created',
        name,
        caseIndex,
      ),
      async () => {
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
          assert.deepEqual(markers(), []);
          assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), [href]);
        } finally {
          for (const marker of markers()) rmSync(marker, { force: true });
          for (const close of unregister) close();
          rmSync(dir, { recursive: true, force: true });
        }
      },
    );
  }
});
