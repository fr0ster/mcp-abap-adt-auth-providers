/**
 * Source tests for the interactive login (plan Task 23; spec §6a):
 * - none of `CallbackScopeError`, `AuthorizationRefusedError`,
 *   `BrowserAuthError`, `DeviceCodePresentationError` is constructed in
 *   `src` — every end of a login is an `AuthProviderFailure`; the classes
 *   stay, unconstructed, for the refusal ladder until Task 27. The one
 *   exception is K6 (the callback port validation), Task 26's row;
 * - no timer bounds a login: `runCallbackScope`'s module reads no
 *   `timeoutMs` (the 4.x field, Decision D6) and calls no `setTimeout`, and
 *   no strategy module calls one either.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from '@jest/globals';

const SRC = join(__dirname, '..', '..');

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (name === '__tests__') return [];
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith('.ts') ? [path] : [];
  });
}

/** Every `new <Class>(` in `src`, as `file:line`. */
function constructions(className: string): string[] {
  const needle = `new ${className}(`;
  return sourceFiles(SRC).flatMap((file) =>
    readFileSync(file, 'utf8')
      .split('\n')
      .flatMap((line, i) =>
        line.includes(needle) ? [`${relative(SRC, file)}:${i + 1}`] : [],
      ),
  );
}

describe('the four interactive classes are constructed nowhere in src', () => {
  it.each([
    'AuthorizationRefusedError',
    'BrowserAuthError',
    'DeviceCodePresentationError',
  ])('%s', (className) => {
    expect(constructions(className)).toEqual([]);
  });

  it('CallbackScopeError — only K6, the port validation (Task 26)', () => {
    const sites = constructions('CallbackScopeError');
    expect(sites).toHaveLength(1);
    expect(sites[0]).toMatch(/^auth[/\\]callbackServer\.ts:/);
    const file = readFileSync(join(SRC, 'auth', 'callbackServer.ts'), 'utf8');
    const line = file.split('\n')[Number(sites[0]?.split(':')[1]) - 1];
    expect(line).toContain('new CallbackScopeError(');
    expect(file).toContain('Invalid callback server port:');
  });
});

describe('no timer bounds a login', () => {
  it('runCallbackScope reads no timeoutMs and calls no setTimeout', () => {
    const file = readFileSync(join(SRC, 'auth', 'callbackServer.ts'), 'utf8');
    expect(file).not.toContain('timeoutMs');
    expect(file).not.toContain('setTimeout');
    expect(file).not.toContain('setInterval');
  });

  it.each(
    sourceFiles(join(SRC, 'strategies')).map((file) => relative(SRC, file)),
  )('%s calls no setTimeout', (file) => {
    const text = readFileSync(join(SRC, file), 'utf8');
    expect(text).not.toContain('setTimeout');
    expect(text).not.toContain('setInterval');
  });

  it('no package default bound is left anywhere in src', () => {
    for (const file of sourceFiles(SRC)) {
      const text = readFileSync(file, 'utf8');
      expect([
        relative(SRC, file),
        text.includes('DEFAULT_LOGIN_TIMEOUT_MS'),
      ]).toEqual([relative(SRC, file), false]);
      expect([relative(SRC, file), text.includes('300_000')]).toEqual([
        relative(SRC, file),
        false,
      ]);
    }
  });
});
