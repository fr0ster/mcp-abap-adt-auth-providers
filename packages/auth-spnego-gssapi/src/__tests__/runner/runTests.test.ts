/**
 * The test runner (`tools/run-tests.mjs`): what it runs and when it fails.
 * Each case runs the runner in a temporary directory of its own, over
 * fixture files written into that directory's `.test-build/`, so what the
 * runner did is read from its exit status and from files the fixtures wrote.
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
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { nodeTestArguments } from '../../../tools/node-test-arguments.mjs';

// .test-build/__tests__/runner → the package.
const RUNNER = join(__dirname, '..', '..', '..', 'tools', 'run-tests.mjs');

/** A fixture that passes, and one that fails. */
const PASSES = "require('node:test').it('passes', () => {});\n";
const FAILS =
  "require('node:test').it('fails', () => { throw new Error('fixture fails'); });\n";

/** Records this file's pid (and its name) in the file `$RUN_TESTS_RECORD`. */
const recording = (name: string) =>
  `const { appendFileSync } = require('node:fs');
require('node:test').it('${name} records', () => {
  appendFileSync(process.env.RUN_TESTS_RECORD, '${name} ' + process.pid + '\\n');
});
`;

let cwd = '';
let record = '';

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'run-tests-'));
  record = join(cwd, 'record.txt');
});
afterEach(() => {
  rmSync(cwd, { recursive: true, force: true });
});

/** Writes `.test-build/<path>` in the case's directory. */
function fixture(path: string, source: string): void {
  const file = join(cwd, '.test-build', path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, source);
}

/** Runs the runner in the case's directory; its status and its output. */
function run(...args: string[]): { status: number | null; output: string } {
  // A test process carries NODE_TEST_CONTEXT: a nested `node --test` would
  // take itself for a child of this runner and report to it.
  const { NODE_TEST_CONTEXT: _child, ...env } = process.env;
  const result = spawnSync(process.execPath, [RUNNER, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...env, RUN_TESTS_RECORD: record },
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

/** The lines the fixtures recorded: `<name> <pid>`. */
function recorded(): string[][] {
  return readFileSync(record, 'utf8')
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => line.split(' '));
}

describe('run-tests', () => {
  it('fails when .test-build/ does not exist', () => {
    const { status, output } = run();
    assert.equal(status, 1);
    assert.ok(output.includes('.test-build/ does not exist'), output);
  });

  it('fails when the test build produced no test', () => {
    mkdirSync(join(cwd, '.test-build'));
    const { status, output } = run();
    assert.equal(status, 1);
    assert.ok(output.includes('the test build produced none'), output);
  });

  it('runs every *.test.js under .test-build/ when no path is named', () => {
    fixture('a.test.js', recording('a'));
    fixture('deep/b.test.js', recording('b'));
    fixture('helper.js', 'throw new Error("not a test: never run");\n');
    const { status, output } = run();
    assert.equal(status, 0, output);
    assert.deepEqual(
      recorded()
        .map(([name]) => name)
        .sort(),
      ['a', 'b'],
    );
  });

  it('fails when any file fails', () => {
    fixture('a.test.js', PASSES);
    fixture('b.test.js', FAILS);
    assert.equal(run().status, 1);
  });

  it('a named file runs alone', () => {
    fixture('a.test.js', recording('a'));
    fixture('b.test.js', FAILS);
    const { status, output } = run('.test-build/a.test.js');
    assert.equal(status, 0, output);
    assert.deepEqual(
      recorded().map(([name]) => name),
      ['a'],
    );
  });

  it('a named file that does not exist fails', () => {
    fixture('a.test.js', PASSES);
    const { status, output } = run('.test-build/missing.test.js');
    assert.equal(status, 1);
    assert.ok(output.includes('missing.test.js does not exist'), output);
  });

  it('a named directory under .test-build/ runs alone', () => {
    fixture('stand/a.test.js', recording('a'));
    fixture('stand/deep/b.test.js', recording('b'));
    fixture('c.test.js', FAILS);
    const { status, output } = run('.test-build/stand');
    assert.equal(status, 0, output);
    assert.deepEqual(
      recorded()
        .map(([name]) => name)
        .sort(),
      ['a', 'b'],
    );
  });

  it('a named directory without a test, or that does not exist, fails', () => {
    fixture('a.test.js', PASSES);
    mkdirSync(join(cwd, '.test-build', 'empty'));
    const empty = run('.test-build/empty');
    assert.equal(empty.status, 1);
    assert.ok(empty.output.includes('produced none'), empty.output);
    const missing = run('.test-build/missing');
    assert.equal(missing.status, 1);
    assert.ok(missing.output.includes('does not exist'), missing.output);
  });

  it('--env NAME=VALUE reaches the test, the value whole', () => {
    fixture(
      'env.test.js',
      `require('node:test').it('sees the variable', () => {
  require('node:assert/strict').equal(process.env.RUN_TESTS_PROBE, 'a=b c');
});
`,
    );
    assert.equal(run().status, 1, 'without --env the fixture fails');
    const { status, output } = run('--env', 'RUN_TESTS_PROBE=a=b c');
    assert.equal(status, 0, output);
  });

  it('--env without NAME=VALUE is refused', () => {
    fixture('a.test.js', PASSES);
    for (const pair of ['RUN_TESTS_PROBE', '=value']) {
      const { status, output } = run('--env', pair);
      assert.equal(status, 2, pair);
      assert.ok(output.includes('--env takes NAME=VALUE'), output);
    }
  });

  it('every file runs in a process of its own, with module mocks available', () => {
    const source = `const { appendFileSync } = require('node:fs');
const { it, mock } = require('node:test');
it('records', () => {
  require('node:assert/strict').equal(typeof mock.module, 'function');
  appendFileSync(process.env.RUN_TESTS_RECORD, 'f ' + process.pid + '\\n');
});
`;
    fixture('a.test.js', source);
    fixture('b.test.js', source);
    fixture('c.test.js', source);
    const { status, output } = run();
    assert.equal(status, 0, output);
    const pids = recorded().map(([, pid]) => pid);
    assert.equal(pids.length, 3);
    assert.equal(new Set(pids).size, 3);
  });
});

describe('the arguments the runner gives node', () => {
  const args = nodeTestArguments({
    options: ['--test-name-pattern', 'x'],
    files: ['a.test.js', 'b.test.js'],
  });

  it('module mocks on, one file at a time; the options, then the files', () => {
    assert.deepEqual(args, [
      '--experimental-test-module-mocks',
      '--test',
      '--test-concurrency=1',
      '--test-name-pattern',
      'x',
      'a.test.js',
      'b.test.js',
    ]);
  });

  it('no timeout: no --test-timeout', () => {
    for (const arg of args) {
      assert.equal(arg.startsWith('--test-timeout'), false, arg);
    }
  });

  it('the runner starts node with exactly these arguments, in one spawn', () => {
    // The source without its layout: the formatter may wrap the call.
    const source = [...readFileSync(RUNNER, 'utf8')]
      .filter((c) => c !== ' ' && c !== '\n' && c !== '\r')
      .join('');
    assert.ok(
      source.includes('spawnSync(process.execPath,nodeTestArguments({'),
      'run-tests.mjs spawns node with nodeTestArguments(…)',
    );
    assert.equal(source.split('spawnSync(').length, 2, 'one spawn');
  });
});
