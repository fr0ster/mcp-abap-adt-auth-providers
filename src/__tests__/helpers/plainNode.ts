/**
 * Runs a scenario under plain node, in a child process, with an
 * unhandled-rejection recorder: what Jest's own handlers would hide (an
 * unhandled rejection, a promise left behind by a race) shows up there.
 *
 * The package's sources are compiled once per test file into a temporary
 * directory (`tsc -p tsconfig.build.json`, no declarations); a scenario is
 * plain CommonJS that receives `lib` (the compiled `index.js`), `errors`
 * (auth-errors) and `load`
 * (a compiled module by its path under `src`), and reports a JSON value
 * through `report(value)`. The child exits on its own; nothing is timed.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = join(__dirname, '..', '..', '..');

let compiled: string | undefined;

/** Compiles `src` once for this test file; the directory is removed at exit. */
export function compiledSources(): string {
  if (compiled) return compiled;
  const out = mkdtempSync(join(tmpdir(), 'auth-providers-plain-'));
  const tsc = spawnSync(
    process.execPath,
    [
      join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
      '-p',
      join(root, 'tsconfig.build.json'),
      '--outDir',
      out,
      '--composite',
      'false',
      '--declaration',
      'false',
      '--declarationMap',
      'false',
      '--incremental',
      'false',
    ],
    { cwd: root, encoding: 'utf8' },
  );
  if (tsc.status !== 0) {
    throw new Error(`tsc failed: ${tsc.stdout}${tsc.stderr}`);
  }
  process.once('exit', () => rmSync(out, { recursive: true, force: true }));
  compiled = out;
  return out;
}

export interface PlainNodeRun<T> {
  /** What the scenario reported. */
  readonly result: T;
  /** Every unhandled rejection the child saw, by constructor name. */
  readonly unhandled: readonly string[];
  readonly status: number | null;
  readonly stderr: string;
}

/**
 * Runs `body` — the text of an async function body with `lib`, `errors`
 * (auth-errors), `load` and `report` in scope — in a child node process. After the body settles, the
 * child lets two macrotask turns pass so that a rejection left unhandled is
 * reported, then prints what it recorded.
 */
export function runPlainNode<T>(body: string): PlainNodeRun<T> {
  const out = compiledSources();
  const dir = mkdtempSync(join(tmpdir(), 'auth-providers-scenario-'));
  const script = join(dir, 'scenario.js');
  writeFileSync(
    script,
    `'use strict';
const unhandled = [];
process.on('unhandledRejection', (reason) => {
  let name = typeof reason;
  try { name = (reason && reason.constructor && reason.constructor.name) || name; } catch {}
  unhandled.push(name);
});
const path = require('node:path');
const lib = require(${JSON.stringify(join(out, 'index.js'))});
const errors = require('@mcp-abap-adt/auth-errors');
const load = (relative) => require(path.join(${JSON.stringify(out)}, relative));
let reported;
const report = (value) => { reported = value; };
const turn = () => new Promise((resolve) => setImmediate(resolve));
(async () => {
${body}
})().then(
  async () => {
    await turn();
    await turn();
    process.stdout.write(JSON.stringify({ result: reported, unhandled }));
    process.exit(0);
  },
  async (error) => {
    await turn();
    process.stdout.write(JSON.stringify({ result: { scenarioFailed: String(error && error.stack || error) }, unhandled }));
    process.exit(0);
  },
);
`,
  );
  try {
    const run = spawnSync(process.execPath, [script], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, NODE_PATH: join(root, 'node_modules') },
    });
    const parsed = JSON.parse(run.stdout || 'null') as {
      result: T;
      unhandled: string[];
    } | null;
    return {
      result: parsed?.result as T,
      unhandled: parsed?.unhandled ?? ['<no report>'],
      status: run.status,
      stderr: run.stderr,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
