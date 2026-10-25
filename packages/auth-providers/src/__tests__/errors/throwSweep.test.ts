/**
 * The sweep of `src`: no `new Error(` and no construction of any of this
 * package's error classes — the thirteen of the old ladder and the two of
 * `callbackScopeError.ts`, and SNC's `SncLibraryNotFoundError` — is left. Every
 * throw is an `AuthProviderFailure` of its row's kind, built at its site, or
 * the rethrow of one; and no refusal is built from free words (`oops(`, whose
 * last caller is gone).
 *
 * The classes, the 5.x transition pieces and their modules are deleted from
 * `src`: the second and third blocks keep it so.
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

describe('no transition piece is left in src', () => {
  it.each([
    'contractTransition',
    'toLegacyRefusal',
    'toLegacyOutcome',
    'legacyBridge',
    'isUnmintedRung',
    'errorFor(',
    'refusalFrom',
    'refusalWords',
    'loggedError(',
    'asContract',
    'contractShape',
    'TokenResultWithDisposition',
    'SignalledAuthorizationRequest',
    'TOKEN_PROVIDER_ERROR_CODES',
    'ASSERTION_ERROR_CODES',
    'TokenProviderError',
    'ValidationError',
    'CallbackScopeError',
    'AuthorizationRefusedError',
    'DeviceCodePresentationError',
    'CertificateMaterialError',
    'ClientAuthenticationError',
    'ClientAuthenticationResultError',
    'BasicClientIdError',
    'AssertionValidationError',
    'RefreshError',
    'BrowserAuthError',
    'ServiceKeyError',
    'SessionDataError',
    'TokenEndpointError',
    'SncLibraryNotFoundError',
    'tokenEndpointError',
  ])('%s is named nowhere in src', (needle) => {
    const found = sourceFiles(SRC)
      .filter((file) => readFileSync(file, 'utf8').includes(needle))
      .map((file) => relative(SRC, file));
    expect(found).toEqual([]);
  });

  it('the deleted modules are gone', () => {
    const names = new Set(sourceFiles(SRC).map((file) => relative(SRC, file)));
    for (const gone of [
      'auth/contractTransition.ts',
      'auth/contractShape.ts',
      'auth/refusal.ts',
      'auth/callbackScopeError.ts',
      'errors/TokenProviderErrors.ts',
      'errors/AssertionValidationError.ts',
      'errors/CertificateMaterialError.ts',
      'errors/ClientAuthenticationError.ts',
      'errors/TokenEndpointError.ts',
    ]) {
      expect([gone, names.has(gone)]).toEqual([gone, false]);
    }
    expect(names.size).toBeGreaterThan(10);
  });
});
