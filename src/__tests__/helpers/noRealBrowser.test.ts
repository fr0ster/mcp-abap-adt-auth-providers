/**
 * The setup guard (`noRealBrowser.ts`): no test starts a real browser
 * launcher. Each refused command is a path that does not exist, so even a
 * broken guard starts nothing (`ENOENT`).
 */

import childProcess = require('node:child_process');

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, jest } from '@jest/globals';

const nowhere = join('/nonexistent-launcher-dir', 'xdg-open');

/** Loaded only after the first case: the import itself would install it. */
const refusedLauncher = (command: string): boolean =>
  (
    jest.requireActual('./noRealBrowser') as {
      refusedLauncher: (command: string) => boolean;
    }
  ).refusedLauncher(command);

describe('no real browser launcher in a test', () => {
  // First, before this file loads the module: jest's setupFiles installed it.
  it('the guard is installed for every test file (jest setupFiles)', () => {
    expect(
      (childProcess as unknown as Record<symbol, unknown>)[
        Symbol.for('mcp-abap-adt.noRealBrowser')
      ],
    ).toBe(true);
    expect(() => childProcess.spawn(nowhere, ['https://x.invalid/'])).toThrow(
      'a test tried to start a real browser launcher',
    );
  });

  it.each([
    'xdg-open',
    'open',
    'google-chrome',
    'firefox',
    nowhere,
    'C:\\Windows\\System32\\rundll32.exe',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  ])('%s is refused', (command) => {
    expect(refusedLauncher(command)).toBe(true);
  });

  it.each([process.execPath, 'node', join(tmpdir(), 'browser-x', 'xdg-open')])(
    '%s is allowed',
    (command) => {
      expect(refusedLauncher(command)).toBe(false);
    },
  );

  it('spawn and execFile throw for a launcher, before anything starts', () => {
    expect(() => childProcess.spawn(nowhere, ['https://x.invalid/'])).toThrow(
      'a test tried to start a real browser launcher',
    );
    expect(() =>
      childProcess.execFile(nowhere, ['https://x.invalid/']),
    ).toThrow('a test tried to start a real browser launcher');
  });

  it('requireActual sees the guard too', () => {
    const actual =
      jest.requireActual<typeof import('node:child_process')>(
        'node:child_process',
      );
    expect(() => actual.spawn(nowhere, [])).toThrow(
      'a test tried to start a real browser launcher',
    );
  });
});
