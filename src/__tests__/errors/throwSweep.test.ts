/**
 * The sweep of `src` (plan Task 26): no `new Error(` and no construction of
 * any of this package's error classes — A.1's thirteen and the two of
 * `callbackScopeError.ts` — is left. Every throw is an `AuthProviderFailure`
 * of its row's kind, built at its site, or the rethrow of one.
 *
 * TRANSITION: `src/snc` is Task 25's (E20, E21 and the locator's
 * `SncLibraryNotFoundError`), excluded here until that task removes the
 * exclusion. The classes themselves stay exported until Task 27.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { describe, expect, it } from '@jest/globals';

const SRC = join(__dirname, '..', '..');
const EXCLUDED = [`snc${sep}`];

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (name === '__tests__') return [];
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith('.ts') ? [path] : [];
  });
}

/** Every line of `src` (Task 25's excluded) holding `needle`, as `file:line`. */
function linesWith(needle: string): string[] {
  return sourceFiles(SRC)
    .filter(
      (file) => !EXCLUDED.some((dir) => relative(SRC, file).startsWith(dir)),
    )
    .flatMap((file) =>
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
];

describe('nothing in src throws an unminted error', () => {
  it('no new Error(', () => {
    expect(linesWith('new Error(')).toEqual([]);
  });

  it.each(CLASSES)('%s is constructed nowhere', (className) => {
    expect(linesWith(`new ${className}(`)).toEqual([]);
  });
});
