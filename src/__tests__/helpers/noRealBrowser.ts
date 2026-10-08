/**
 * Jest setup (`setupFiles`): no test starts a real browser or URL launcher.
 *
 * A test that reaches a shipped `IBrowser` without mocking the spawn
 * boundary would hand the authorization URL to the machine's own
 * `xdg-open`, `open`, a browser binary, `rundll32` or PowerShell — a real
 * browser tab, a real request. So `child_process.spawn` / `execFile` refuse
 * any launcher of that name, wherever it is found (the `open` package's
 * bundled `xdg-open` included), unless it is an absolute path inside the
 * temporary directory (a test's own fake script) — or a person asked for
 * the interactive cases (`interactive_login: true` or
 * `MCP_ABAP_ADT_INTERACTIVE=1`).
 */

import { existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join, resolve, sep } from 'node:path';
import * as yaml from 'js-yaml';
import { interactiveLoginEnabled, type TestConfig } from './configHelpers';

// The core module object itself (not an import wrapper): every importer,
// the `open` package and `jest.requireActual` included, reads spawn from it.
import childProcess = require('node:child_process');

/** Every program a browser launch may start, lower-cased. */
export const LAUNCHERS: ReadonlySet<string> = new Set([
  'xdg-open',
  'open',
  'gio',
  'sensible-browser',
  'x-www-browser',
  'www-browser',
  'wslview',
  'google-chrome',
  'google-chrome-stable',
  'chrome',
  'chromium',
  'chromium-browser',
  'microsoft-edge',
  'microsoft-edge-stable',
  'msedge',
  'firefox',
  'firefox-esr',
  'rundll32',
  'rundll32.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'cmd',
  'cmd.exe',
]);

/** A launcher name, outside the temporary directory: refused. */
export function refusedLauncher(command: unknown): boolean {
  if (typeof command !== 'string') return false;
  // Windows paths too: the last segment after either separator.
  const name = basename(command.split('\\').join('/')).toLowerCase();
  if (!LAUNCHERS.has(name)) return false;
  const temporary = resolve(tmpdir()) + sep;
  return !(isAbsolute(command) && resolve(command).startsWith(temporary));
}

/**
 * Whether a person asked for the interactive cases — read quietly (no
 * console line in every test file): `tests/test-config.yaml`, when present.
 */
function interactive(): boolean {
  let config: TestConfig = {};
  try {
    const path = join(__dirname, '..', '..', '..', 'tests', 'test-config.yaml');
    if (existsSync(path)) {
      config = (yaml.load(readFileSync(path, 'utf8')) as TestConfig) ?? {};
    }
  } catch {
    config = {};
  }
  return interactiveLoginEnabled({ env: process.env, config });
}

const GUARDED = Symbol.for('mcp-abap-adt.noRealBrowser');
const target = childProcess as unknown as Record<string | symbol, unknown>;

if (target[GUARDED] !== true && !interactive()) {
  for (const name of ['spawn', 'execFile'] as const) {
    const real = target[name] as (...args: unknown[]) => unknown;
    const guarded = function (this: unknown, ...args: unknown[]): unknown {
      if (refusedLauncher(args[0])) {
        throw new Error(
          `a test tried to start a real browser launcher (${String(args[0])}): mock the spawn boundary or inject an IBrowser`,
        );
      }
      return real.apply(this, args);
    };
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
  }
  target[GUARDED] = true;
}
