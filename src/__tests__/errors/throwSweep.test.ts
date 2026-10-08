/**
 * The sweep of `src`: no `new Error(` and no construction of
 * any of this package's error classes — the thirteen of the old ladder and the two of
 * `callbackScopeError.ts`, and SNC's `SncLibraryNotFoundError` — is left.
 * Every throw is an `AuthProviderFailure` of its row's kind, built at its
 * site, or the rethrow of one; and no refusal is built from free words
 * (`oops(`, whose last caller is gone).
 *
 * The classes themselves are deleted (`transitionCoverage.test.ts`).
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

/** Every line of `src` holding `needle`, as `file:line`. */
function linesWith(needle: string): string[] {
  return sourceFiles(SRC).flatMap((file) =>
    readFileSync(file, 'utf8')
      .split('\n')
      .flatMap((line, i) =>
        line.includes(needle) ? [`${relative(SRC, file)}:${i + 1}`] : [],
      ),
  );
}

const CLASSES = [
  'DeviceCodePresentationError',
  'AssertionValidationError',
  'CertificateMaterialError',
  'ClientAuthenticationResultError',
  'ClientAuthenticationError',
  'BasicClientIdError',
  'BrowserAuthError',
  'RefreshError',
  'ValidationError',
  'ServiceKeyError',
  'SessionDataError',
  'TokenProviderError',
  'TokenEndpointError',
  'CallbackScopeError',
  'AuthorizationRefusedError',
  'SncLibraryNotFoundError',
];

describe('nothing in src throws an unminted error', () => {
  it('no new Error(', () => {
    expect(linesWith('new Error(')).toEqual([]);
  });

  it.each(CLASSES)('%s is constructed nowhere', (className) => {
    expect(linesWith(`new ${className}(`)).toEqual([]);
  });

  it('no refusal of free words: no oops(', () => {
    expect(linesWith('oops(')).toEqual([]);
  });
});
