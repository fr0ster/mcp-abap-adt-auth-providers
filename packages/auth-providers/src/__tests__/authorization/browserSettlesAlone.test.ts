/**
 * A shipped browser's `open()` awaited on its own — nothing else holding the
 * event loop, as in a consumer's script — settles as documented: a hand-off
 * launcher (`linuxDefaultBrowser`) keeps its child referenced until it exits,
 * so the process waits for the exit and the promise resolves; a browser
 * binary (`linuxBrowser`) is unreferenced once it has started, so the process
 * does not wait for the browser to close.
 *
 * Run under plain node in a child process, against fake programs written
 * here before the child starts. Jest's guard does not reach that child (it
 * allows `process.execPath`), so the child's `PATH` holds only the fake
 * directory and `linuxBrowser` is given the fake by absolute path: no system
 * program can be found, whatever factory is run. Linux and macOS only: the
 * fakes are `#!` scripts.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { PACKAGE_ROOT } from '../helpers/packagePaths';

import { compiledSources } from '../helpers/plainNode';

const root = PACKAGE_ROOT;
const onPosix = process.platform === 'win32' ? describe.skip : describe;

const dir = mkdtempSync(join(tmpdir(), 'browser-alone-'));
after(() => rmSync(dir, { recursive: true, force: true }));

/** A `#!node` script at `name` in `dir` that runs `body`. */
function fake(name: string, body: string): string {
  const path = join(dir, name);
  writeFileSync(path, `#!${process.execPath}\n${body}\n`);
  chmodSync(path, 0o755);
  return path;
}

/** Runs `open()` alone in a plain node child; what it printed, how it ended. */
function openAlone(factory: string): { stdout: string; status: number | null } {
  const browsers = join(
    compiledSources(),
    'authorization',
    'presentation',
    'browsers.js',
  );
  const script = `
const b = require(${JSON.stringify(browsers)});
b.${factory}.open('https://idp.example/authorize?state=s', new AbortController().signal)
  .then(() => process.stdout.write('resolved'), () => process.stdout.write('rejected'));
`;
  const run = spawnSync(process.execPath, ['-e', script], {
    cwd: root,
    env: {
      ...process.env,
      NODE_PATH: join(root, 'node_modules'),
      // Only the fake directory: no system program can ever be found, so a
      // launcher the fakes do not cover fails to start (ENOENT).
      PATH: dir,
    },
    encoding: 'utf8',
    // The test's own bound: a regression fails instead of hanging.
    timeout: 20_000,
    killSignal: 'SIGKILL',
  });
  return { stdout: run.stdout, status: run.status };
}

onPosix('a shipped browser awaited alone', () => {
  it('linuxDefaultBrowser: the process waits for the launcher to exit, and open() resolves', () => {
    fake('xdg-open', 'setTimeout(() => process.exit(0), 300);');
    assert.deepEqual(openAlone('linuxDefaultBrowser()'), {
      stdout: 'resolved',
      status: 0,
    });
  });

  it('linuxBrowser: open() resolves at the start, and the process does not wait for the browser', async () => {
    const done = join(dir, 'browser-closed');
    const browser = fake(
      'fake-browser',
      `setTimeout(() => require('fs').writeFileSync(${JSON.stringify(done)}, ''), 3000);`,
    );
    assert.deepEqual(openAlone(`linuxBrowser(${JSON.stringify(browser)})`), {
      stdout: 'resolved',
      status: 0,
    });
    // The child exited while the browser still ran.
    assert.equal(existsSync(done), false);
    // Nothing left running: wait for the fake browser to end.
    for (let i = 0; i < 100 && !existsSync(done); i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(existsSync(done), true);
  });
});
