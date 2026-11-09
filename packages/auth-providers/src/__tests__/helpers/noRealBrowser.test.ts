/**
 * The child-process guard (`noRealBrowser.ts`): deny by default. In a test,
 * every `child_process` entry point refuses unless the program is node
 * itself (`process.execPath`) or an exact path a test registered as its
 * fake — and refuses any shell. Every refused program here is a path that
 * does not exist, so even a broken guard starts nothing.
 *
 * That the runner installs it in every file's process before the file loads
 * is proved by `runner/guardPreload.test.ts`, over fixture files that never
 * load it themselves.
 */

import assert from 'node:assert/strict';
// Another way in to the same module object: a namespace import.
import * as childProcessNamespace from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';
import { allowExecutable } from './noRealBrowser';

// The core module object itself: the one the guard wraps.
import childProcess = require('node:child_process');

const REFUSED = 'a test tried to start a program it did not register';
const nowhere = (name: string) => join('/nonexistent-launcher-dir', name);

/** The guard's refusal. */
const refused = (error: unknown): boolean =>
  error instanceof Error && error.message.includes(REFUSED);

describe('no real program in a test', () => {
  it('the guard is installed on the module object', () => {
    assert.equal(
      Reflect.get(childProcess, Symbol.for('mcp-abap-adt.noRealBrowser')),
      true,
    );
    assert.throws(
      () => childProcess.spawn(nowhere('xdg-open'), ['u']),
      refused,
    );
  });

  for (const program of [
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
  ]) {
    it(`spawn(${program}) is refused`, () => {
      assert.throws(
        () => childProcess.spawn(program, ['https://x.invalid/']),
        refused,
      );
    });
  }

  const entryPoints: [string, () => unknown][] = [
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
  ];
  for (const [name, call] of entryPoints) {
    it(`${name} is guarded`, () => {
      assert.throws(call, refused);
    });
  }

  const shells: [string, () => unknown][] = [
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
  ];
  for (const [name, call] of shells) {
    it(`${name} is refused`, () => {
      assert.throws(call, refused);
    });
  }

  it('the interactive opt-in no longer lifts it', () => {
    const saved = process.env.MCP_ABAP_ADT_INTERACTIVE;
    process.env.MCP_ABAP_ADT_INTERACTIVE = '1';
    try {
      assert.throws(() => childProcess.spawn(nowhere('xdg-open'), []), refused);
    } finally {
      if (saved === undefined) delete process.env.MCP_ABAP_ADT_INTERACTIVE;
      else process.env.MCP_ABAP_ADT_INTERACTIVE = saved;
    }
  });

  it('a registered exact path is allowed, its neighbour is not; unregistering closes it', () => {
    const fake = join(tmpdir(), 'nonexistent-registered-dir', 'fake-launcher');
    const unregister = allowExecutable(fake);
    try {
      // Allowed: the real spawn reports ENOENT asynchronously, no throw.
      const child = childProcess.spawn(fake, [], { stdio: 'ignore' });
      child.on('error', () => undefined);
      assert.throws(
        () => childProcess.spawn(`${fake}-neighbour`, [], { stdio: 'ignore' }),
        refused,
      );
    } finally {
      unregister();
    }
    assert.throws(() => childProcess.spawn(fake, []), refused);
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
      assert.deepEqual(result, { stdout: 'out\n', stderr: 'err\n' });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  const promisified: [string, () => Promise<unknown>][] = [
    ['execFile', () => promisify(childProcess.execFile)(nowhere('x'), [])],
    ['exec', () => promisify(childProcess.exec)(`${nowhere('x')} y`)],
  ];
  for (const [name, call] of promisified) {
    it(`promisify(${name}) of an unregistered program is refused`, async () => {
      let thrown: unknown;
      try {
        await call();
      } catch (error) {
        thrown = error;
      }
      assert.ok(String(thrown).includes(REFUSED), String(thrown));
    });
  }

  // Was "jest.requireActual sees the guard too": with no module registry of
  // a runner in between, the other import of the module object is the case.
  it('a namespace import of node:child_process sees the guard too', () => {
    assert.throws(
      () => childProcessNamespace.spawn(nowhere('xdg-open'), []),
      refused,
    );
  });
});
