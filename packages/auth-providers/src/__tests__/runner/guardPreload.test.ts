/**
 * The child-process guard is in every test file's process: the runner
 * starts each with `--require` of the compiled guard, before any test module
 * loads. The fixtures below never load the guard themselves, yet each finds
 * it installed and is refused a program it did not register. Every refused
 * program is a path that does not exist, so even a missing guard starts
 * nothing.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, it } from 'node:test';

// .test-build/__tests__/runner → the package.
const RUNNER = join(__dirname, '..', '..', '..', 'tools', 'run-tests.mjs');

/** A fixture file that does not import the guard. */
const FIXTURE = `const { appendFileSync } = require('node:fs');
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
require('node:test').it('the guard is installed before this file loads', () => {
  assert.equal(childProcess[Symbol.for('mcp-abap-adt.noRealBrowser')], true);
  assert.throws(
    () => childProcess.spawn('/nonexistent-launcher-dir/xdg-open', ['https://x.invalid/']),
    (error) => error instanceof Error &&
      error.message.includes('a test tried to start a program it did not register'),
  );
  appendFileSync(process.env.GUARD_RECORD, process.pid + '\\n');
});
`;

let cwd = '';

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'guard-preload-'));
});
afterEach(() => {
  rmSync(cwd, { recursive: true, force: true });
});

it('every file the runner starts has the guard before its first line', () => {
  mkdirSync(join(cwd, '.test-build', 'deep'), { recursive: true });
  writeFileSync(join(cwd, '.test-build', 'a.test.js'), FIXTURE);
  writeFileSync(join(cwd, '.test-build', 'deep', 'b.test.js'), FIXTURE);
  const record = join(cwd, 'record.txt');
  // A nested `node --test` must not take itself for this runner's child.
  const { NODE_TEST_CONTEXT: _child, ...env } = process.env;
  const result = spawnSync(process.execPath, [RUNNER], {
    cwd,
    encoding: 'utf8',
    env: { ...env, GUARD_RECORD: record },
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const pids = readFileSync(record, 'utf8')
    .split('\n')
    .filter((line) => line !== '');
  assert.equal(pids.length, 2);
  assert.equal(new Set(pids).size, 2);
});
