/**
 * Source tests for the interactive login:
 * - none of `CallbackScopeError`, `AuthorizationRefusedError`,
 *   `BrowserAuthError`, `DeviceCodePresentationError` is constructed in
 *   `src` — every end of a login is an `AuthProviderFailure`; the classes
 *   themselves are deleted (the callback port validation
 *   became `configuration`);
 * - no timer bounds a login: no module of the composer, its parts or the
 *   named compositions calls `setTimeout`, and no `timeoutMs`
 *   is left anywhere in `src` — interfaces-auth 6.0.0 has no such field, so
 *   the `Number.POSITIVE_INFINITY` placeholder went with it.
 */

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it } from 'node:test';
import { caseTitle, notContains } from '../helpers/expectations';
import { SRC } from '../helpers/packagePaths';

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
  // The port validation, the last CallbackScopeError, is a
  // `configuration` failure now.
  for (const [caseIndex, caseRow] of [
    'AuthorizationRefusedError',
    'BrowserAuthError',
    'CallbackScopeError',
    'DeviceCodePresentationError',
  ].entries()) {
    const className = caseRow;
    it(caseTitle('%s', caseRow, caseIndex), () => {
      assert.deepEqual(constructions(className), []);
    });
  }
});

describe('no timer bounds a login', () => {
  for (const [caseIndex, caseRow] of [
    ...sourceFiles(join(SRC, 'strategies')),
    ...sourceFiles(join(SRC, 'authorization')),
  ]
    .map((file) => relative(SRC, file))
    .entries()) {
    const file = caseRow;
    it(caseTitle('%s calls no setTimeout', caseRow, caseIndex), () => {
      const text = readFileSync(join(SRC, file), 'utf8');
      notContains(text, 'setTimeout');
      notContains(text, 'setInterval');
    });
  }

  it('no timeoutMs and no "no bound" placeholder anywhere in src', () => {
    for (const file of sourceFiles(SRC)) {
      const text = readFileSync(file, 'utf8');
      const name = relative(SRC, file);
      assert.deepEqual([name, text.includes('timeoutMs')], [name, false]);
      assert.deepEqual(
        [name, text.includes('POSITIVE_INFINITY')],
        [name, false],
      );
    }
  });

  it('no package default bound is left anywhere in src', () => {
    for (const file of sourceFiles(SRC)) {
      const text = readFileSync(file, 'utf8');
      assert.deepEqual(
        [relative(SRC, file), text.includes('DEFAULT_LOGIN_TIMEOUT_MS')],
        [relative(SRC, file), false],
      );
      assert.deepEqual(
        [relative(SRC, file), text.includes('300_000')],
        [relative(SRC, file), false],
      );
    }
  });
});
