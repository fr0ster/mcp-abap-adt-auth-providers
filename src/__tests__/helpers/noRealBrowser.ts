/**
 * Jest setup (`setupFiles`): no test starts a program it did not register —
 * above all no real browser or URL launcher.
 *
 * Deny by default. Every `child_process` entry point (`spawn`, `spawnSync`,
 * `execFile`, `execFileSync`, `exec`, `execSync`, `fork`) throws unless:
 *
 * - the program is node itself (`process.execPath`) — the suites that run a
 *   plain-node scenario, `tsc`, the shape check or the README generator;
 * - or it is an exact path a test registered with `allowExecutable(path)`
 *   (its own fake script: a fake `xdg-open`, a stand-in for `reg.exe`);
 *
 * and in either case no shell is asked for (`shell` in the options).
 * `exec` / `execSync` (a whole command line for a shell) and `fork` are
 * always refused: no suite uses them. There is no opt-in that lifts it: the
 * interactive cases show the URL instead of opening a browser.
 *
 * Not covered: a plain-node child scenario (`plainNode.ts`) runs outside
 * Jest's setup; those scenarios inject their own `IBrowser` only.
 */

import { resolve } from 'node:path';
import { promisify } from 'node:util';

// The core module object itself (not an import wrapper): every importer,
// the `open` package and `jest.requireActual` included, reads it.
import childProcess = require('node:child_process');

const GUARDED = Symbol.for('mcp-abap-adt.noRealBrowser');
const ALLOWED = Symbol.for('mcp-abap-adt.noRealBrowser.allowed');
const target = childProcess as unknown as Record<string | symbol, unknown>;

/** The registered paths, shared by every load of this module in a worker. */
function allowed(): Set<string> {
  let set = target[ALLOWED] as Set<string> | undefined;
  if (set === undefined) {
    set = new Set();
    target[ALLOWED] = set;
  }
  return set;
}

/**
 * Lets a test start `path` — exactly that file, an absolute path — until the
 * returned function is called.
 */
export function allowExecutable(path: string): () => void {
  const exact = resolve(path);
  allowed().add(exact);
  return () => {
    allowed().delete(exact);
  };
}

/** The options object of a call (`args` may be left out), if any. */
function optionsOf(args: readonly unknown[]): unknown {
  for (const value of args.slice(1)) {
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      return value;
    }
  }
  return undefined;
}

/** Whether a `spawn` / `execFile`-shaped call may run. */
function permitted(args: readonly unknown[]): boolean {
  const program = args[0];
  if (typeof program !== 'string' || program === '') return false;
  const options = optionsOf(args) as { shell?: unknown } | undefined;
  if (options?.shell !== undefined && options.shell !== false) return false;
  if (program === process.execPath) return true;
  // Exact, absolute: a bare name is a PATH lookup, never registered.
  return program === resolve(program) && allowed().has(program);
}

function refusal(program: unknown): Error {
  return new Error(
    `a test tried to start a program it did not register (${String(program)}): mock the spawn boundary, inject an IBrowser or allowExecutable(path)`,
  );
}

if (target[GUARDED] !== true) {
  const wrap = (
    name: string,
    check: (args: readonly unknown[]) => boolean,
  ): void => {
    const real = target[name] as ((...args: unknown[]) => unknown) &
      Record<symbol, unknown>;
    const guarded = function (this: unknown, ...args: unknown[]): unknown {
      if (!check(args)) throw refusal(args[0]);
      return real.apply(this, args);
    } as ((...args: unknown[]) => unknown) & Record<symbol, unknown>;
    // `util.promisify` uses this (execFile / exec resolve `{ stdout,
    // stderr }`); it closes over the real function, so it is guarded too.
    const custom = real[promisify.custom];
    if (typeof custom === 'function') {
      guarded[promisify.custom] = function (
        this: unknown,
        ...args: unknown[]
      ): unknown {
        if (!check(args)) return Promise.reject(refusal(args[0]));
        return (custom as (...a: unknown[]) => unknown).apply(this, args);
      };
    }
    try {
      Object.defineProperty(childProcess, name, {
        value: guarded,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } catch {
      target[name] = guarded;
    }
  };
  for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) {
    wrap(name, permitted);
  }
  for (const name of ['exec', 'execSync', 'fork']) {
    wrap(name, () => false);
  }
  target[GUARDED] = true;
}
