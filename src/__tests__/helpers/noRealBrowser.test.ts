/**
 * The setup guard (`noRealBrowser.ts`): deny by default. In a test, every
 * `child_process` entry point refuses unless the program is node itself
 * (`process.execPath`) or an exact path a test registered as its fake —
 * and refuses any shell. Every refused program here is a path that does not
 * exist, so even a broken guard starts nothing.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it, jest } from '@jest/globals';

// The core module object itself: the one the guard wraps.
import childProcess = require('node:child_process');

const REFUSED = 'a test tried to start a program it did not register';
const nowhere = (name: string) => join('/nonexistent-launcher-dir', name);

/** Loaded only after the first case: the import itself would install it. */
const guard = () =>
  jest.requireActual('./noRealBrowser') as {
    allowExecutable: (path: string) => () => void;
  };

describe('no real program in a test', () => {
  // First, before this file loads the module: jest's setupFiles installed it.
  it('the guard is installed for every test file (jest setupFiles)', () => {
    expect(
      (childProcess as unknown as Record<symbol, unknown>)[
        Symbol.for('mcp-abap-adt.noRealBrowser')
      ],
    ).toBe(true);
    expect(() => childProcess.spawn(nowhere('xdg-open'), ['u'])).toThrow(
      REFUSED,
    );
  });

  it.each([
    // `open`'s fallback names, WSL paths and the .exe forms: no name list —
    // anything not registered is refused.
    nowhere('microsoft-edge-dev'),
    '/mnt/nonexistent-c/Program Files/Google/Chrome/Application/chrome.exe',
    '/mnt/nonexistent-c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    nowhere('firefox.exe'),
    nowhere('pwsh.exe'),
    'pwsh.exe-nonexistent',
    nowhere('osascript'),
    // A program under the temporary directory is no longer allowed by place.
    join(tmpdir(), 'nonexistent-browser-dir', 'xdg-open'),
  ])('spawn(%s) is refused', (program) => {
    expect(() => childProcess.spawn(program, ['https://x.invalid/'])).toThrow(
      REFUSED,
    );
  });

  it.each([
    [
      'spawnSync',
      () => childProcess.spawnSync(nowhere('xdg-open'), ['https://x.invalid/']),
    ],
    [
      'execFile',
      () => childProcess.execFile(nowhere('xdg-open'), ['https://x.invalid/']),
    ],
    [
      'execFileSync',
      () =>
        childProcess.execFileSync(nowhere('xdg-open'), ['https://x.invalid/']),
    ],
    ['exec', () => childProcess.exec(`${nowhere('xdg-open')} https://x/`)],
    ['execSync', () => childProcess.execSync(`${nowhere('xdg-open')} x`)],
    ['fork', () => childProcess.fork(nowhere('module.js'))],
  ])('%s is guarded', (_name, call) => {
    expect(call).toThrow(REFUSED);
  });

  it.each([
    [
      'a whole command string with shell: true',
      () =>
        childProcess.spawn(`${nowhere('xdg-open')} https://x.invalid/`, {
          shell: true,
        }),
    ],
    [
      'node itself with shell: true',
      () =>
        childProcess.spawn(process.execPath, ['-e', '0'], {
          shell: true,
        }),
    ],
    [
      'sh -c',
      () => childProcess.spawn('/bin/sh', ['-c', `${nowhere('xdg-open')} x`]),
    ],
    [
      'env …',
      () => childProcess.spawn('/usr/bin/env', [nowhere('xdg-open'), 'x']),
    ],
    [
      'execFile with shell: true',
      () => childProcess.execFile(nowhere('xdg-open'), ['x'], { shell: true }),
    ],
  ])('%s is refused', (_name, call) => {
    expect(call).toThrow(REFUSED);
  });

  it('the interactive opt-in no longer lifts it', () => {
    const saved = process.env.MCP_ABAP_ADT_INTERACTIVE;
    process.env.MCP_ABAP_ADT_INTERACTIVE = '1';
    try {
      expect(() => childProcess.spawn(nowhere('xdg-open'), [])).toThrow(
        REFUSED,
      );
    } finally {
      if (saved === undefined) delete process.env.MCP_ABAP_ADT_INTERACTIVE;
      else process.env.MCP_ABAP_ADT_INTERACTIVE = saved;
    }
  });

  it('a registered exact path is allowed, its neighbour is not; unregistering closes it', () => {
    const fake = join(tmpdir(), 'nonexistent-registered-dir', 'fake-launcher');
    const unregister = guard().allowExecutable(fake);
    try {
      // Allowed: the real spawn reports ENOENT asynchronously, no throw.
      const child = childProcess.spawn(fake, [], { stdio: 'ignore' });
      child.on('error', () => undefined);
      expect(() =>
        childProcess.spawn(`${fake}-neighbour`, [], { stdio: 'ignore' }),
      ).toThrow(REFUSED);
    } finally {
      unregister();
    }
    expect(() => childProcess.spawn(fake, [])).toThrow(REFUSED);
  });

  // `promisify(execFile)` goes through `util.promisify.custom`, which
  // must be kept (SncSystem destructures `{ stdout }`) and guarded too.
  // Node itself runs a JS fixture: the same on every platform (no shebang).
  it('promisify(execFile) of node with a fixture resolves { stdout, stderr }', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'guard-promisify-'));
    const fixture = join(dir, 'fixture.js');
    writeFileSync(
      fixture,
      "process.stdout.write('out\\n'); process.stderr.write('err\\n');\n",
    );
    try {
      const result = await promisify(childProcess.execFile)(process.execPath, [
        fixture,
      ]);
      expect(result).toEqual({ stdout: 'out\n', stderr: 'err\n' });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.each([
    ['execFile', () => promisify(childProcess.execFile)(nowhere('x'), [])],
    ['exec', () => promisify(childProcess.exec)(`${nowhere('x')} y`)],
  ])(
    'promisify(%s) of an unregistered program is refused',
    async (_n, call) => {
      let thrown: unknown;
      try {
        await call();
      } catch (error) {
        thrown = error;
      }
      expect(String(thrown)).toContain(REFUSED);
    },
  );

  it('jest.requireActual sees the guard too', () => {
    const actual =
      jest.requireActual<typeof import('node:child_process')>(
        'node:child_process',
      );
    expect(() => actual.spawn(nowhere('xdg-open'), [])).toThrow(REFUSED);
  });
});
