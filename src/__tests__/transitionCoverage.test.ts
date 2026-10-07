/**
 * R6 (plan Task 27): the transition tests of Decision D6 are deleted with the
 * pieces they kept green — `legacyLadder.test.ts`, `legacyBridge.test.ts`,
 * `contractTransition.test.ts`, `contractTransition.typecheck.ts` — and with
 * them the tests of the deleted classes and helpers (`refusalWords.test.ts`,
 * `AssertionValidationError.test.ts`, the class cases of `refusal.test.ts`,
 * `refusalRows.test.ts`, `thrownMessages.test.ts`, `producerRows.test.ts`,
 * `tokenProviderFailures.test.ts`, and the 4.x `timeoutMs` cases of
 * `callbackServer.test.ts` and `noLoginTimeout.test.ts`).
 *
 * Each deleted case is mapped to the test that covers its behaviour now — an
 * Appendix A row test of the kind the case produced, or the test of what
 * replaced the piece — named by a title that must appear, as written, in a
 * file under `src/__tests__`. A missing counterpart fails this suite.
 *
 * A12 (`ServiceKeyError` / `SessionDataError`) had no producer and has no
 * kind (spec §6): its counterpart is the case proving a look-alike lends
 * nothing.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { testFiles, testTitles } from './helpers/testTitles';

const TESTS = __dirname;

/**
 * Deleted case → [file under src/__tests__, the exact title of the test that
 * covers it now]. A title is matched whole against the literal titles of the
 * file's `it(…)` / `it.each(…)(…)` calls, never as a substring of its text,
 * so a describe, a comment or a fragment does not count.
 */
const COVERAGE: ReadonlyArray<readonly [string, string, string]> = [
  [
    'ladder: DeviceCodePresentationError → device-code-not-shown (A2)',
    'strategies/interactiveLoginRows.test.ts',
    'K17 / A2: a presenter that throws → device-code-not-shown; H3 logs logFields only',
  ],
  [
    'ladder: CertificateMaterialError incomplete (A4)',
    'auth/certificateMaterial.test.ts',
    'throws a client-certificate failure for incomplete material, with its words (A4)',
  ],
  [
    'ladder: CertificateMaterialError unusable (A4)',
    'auth/certificateMaterial.test.ts',
    'throws a client-certificate failure for unusable material, nothing of it in the refusal (A4)',
  ],
  [
    'ladder: CertificateMaterialError expired (A4)',
    'auth/certificateMaterial.test.ts',
    'throws a client-certificate failure, read by classify into the same words (A4)',
  ],
  [
    'ladder: ClientAuthenticationResultError → result-unsendable (A5)',
    'errors/producerRows.test.ts',
    'A5: a strategy result that cannot be sent (a line break in a header)',
  ],
  [
    'ladder: ClientAuthenticationError → signing-key-unusable (A6)',
    'errors/producerRows.test.ts',
    'A6: privateKeyJwt with %s',
  ],
  [
    'ladder: BasicClientIdError → basic-client-id-colon (A7)',
    'errors/producerRows.test.ts',
    'A7: raw clientSecretBasic with a client id containing a colon',
  ],
  [
    'ladder: BrowserAuthError from an IdP refusal → identity-provider-refused (A8)',
    'strategies/interactiveLoginRows.test.ts',
    'K10 / A8 (%s): the IdP refuses with a registered code → identity-provider-refused',
  ],
  [
    'ladder: any other BrowserAuthError → failed (A9)',
    'strategies/interactiveLoginRows.test.ts',
    'with a status and a registered error, verbatim, and A9’s new hint',
  ],
  [
    'ladder: RefreshError → credential-refused refresh-token (A10)',
    'providers/tokenProviderFailures.test.ts',
    'A10: %s → credential-refused refresh-token',
  ],
  [
    'ladder: TokenEndpointError → request-failed (A14)',
    'auth/tokenSiteRows.test.ts',
    '$name: request-failed refused, not the reduced AxiosError',
  ],
  [
    'ladder: TokenProviderError → unknown with the operation (A13)',
    'providers/tokenProviderFailures.test.ts',
    'A13 / L11: %s: unknown, wrapped',
  ],
  [
    'ladder: AssertionValidationError → saml-assertion (A3)',
    'errors/producerRows.test.ts',
    'A3: a shipped validator throws a minted saml-assertion failure with its rule',
  ],
  [
    'ladder: ValidationError → configuration required-fields-missing (A11)',
    'errors/configurationRows.test.ts',
    'E1: ClientCredentialsProvider names each missing field',
  ],
  [
    'ladder: ServiceKeyError / SessionDataError keep 5.4.2 words (A12, no producer)',
    'providers/tokenProviderFailures.test.ts',
    'A12: ServiceKeyError / SessionDataError look-alikes are unknown, wrapped (no producer, no kind)',
  ],
  [
    'ladder: anything else reaches classify (A16)',
    'auth/refusalRows.test.ts',
    'A16: a foreign value → unknown with its allowlisted facts, verbatim',
  ],
  [
    'bridge: a ladder class thrown by a body keeps its kind through the four moments',
    'auth/AuthProviderBase.test.ts',
    'a body that throws → unknown with the moment its operation names',
  ],
  [
    "bridge: anything else still reaches guard's classify",
    'auth/AuthProviderBase.test.ts',
    'a foreign throw by the body names the grant read once',
  ],
  [
    'toLegacyRefusal / toLegacyOutcome: the same minted object reaches the caller',
    'auth/relayMatrix.test.ts',
    'returned refusal → that refusal',
  ],
  [
    'C1: a minted error is not a 4.x refusal (typecheck)',
    'exports.test.ts',
    'does not export %s',
  ],
  [
    'refusalWords: a hostile value → fixed words, no throw',
    'auth/thrownMessages.test.ts',
    'a value whose every read throws is "unknown error", not an exception',
  ],
  ['refusalWords: no longer exported', 'exports.test.ts', 'does not export %s'],
  [
    'AssertionValidationError carries its check',
    'validation/samlRules.test.ts',
    'names 56 rules, each with a check of the allowlist',
  ],
  [
    'a mutated AuthorizationRefusedError code never reaches the refusal',
    'strategies/interactiveLoginRows.test.ts',
    'K10: an unregistered code → no oauthError, its own words',
  ],
  [
    'TokenEndpointError keeps only allowlisted facts; loggedError reads its status',
    'auth/tokenSiteRows.test.ts',
    '$name: request-failed refused, status and registered code; `<operation> failed (HTTP <n>, <oauth>)`',
  ],
  [
    'a reduced AxiosError reads like a TokenEndpointError',
    'auth/tokenSiteRows.test.ts',
    '$name: an allowlisted system code is the `code` fact',
  ],
  [
    'callbackServer: accepts whatever the 4.x bound field carries',
    'strategies/interactiveSources.test.ts',
    'no timeoutMs and no "no bound" placeholder anywhere in src',
  ],
  [
    'noLoginTimeout: a scope given timeoutMs 1 stays open until aborted',
    'strategies/interactiveSources.test.ts',
    'no timeoutMs and no "no bound" placeholder anywhere in src',
  ],
  [
    'TokenResultWithDisposition: what onTokens receives',
    'providers/tokenProviderFailures.test.ts',
    '§6c.1: a renewal returns the result with the held refresh token, and no disposition',
  ],
];

describe('R6: every deleted transition case has a counterpart test that exists', () => {
  const files = new Map(
    testFiles(TESTS).map((path) => [
      relative(TESTS, path),
      readFileSync(path, 'utf8'),
    ]),
  );

  it('the title reader collects test titles, not describes or fragments', () => {
    const titles = testTitles(
      "describe('outer', () => {\n  it('one', () => {});\n  it.each([[1, (2)]])(\n    'two %s',\n    () => {},\n  );\n});",
    );
    expect(titles.has('one')).toBe(true);
    expect(titles.has('two %s')).toBe(true);
    expect(titles.has('outer')).toBe(false);
    expect(titles.has('on')).toBe(false);
  });

  it.each(COVERAGE)('%s → %s', (_deleted, file, title) => {
    expect(file).not.toBe('transitionCoverage.test.ts');
    const text = files.get(file);
    expect([file, text !== undefined]).toEqual([file, true]);
    const titles = testTitles(text ?? '');
    expect([file, title, titles.has(title)]).toEqual([file, title, true]);
  });

  it('the deleted transition test files are gone', () => {
    for (const gone of [
      'auth/legacyLadder.test.ts',
      'auth/legacyBridge.test.ts',
      'auth/contractTransition.test.ts',
      'auth/contractTransition.typecheck.ts',
      'auth/refusalWords.test.ts',
      'errors/AssertionValidationError.test.ts',
    ]) {
      expect([gone, files.has(gone)]).toEqual([gone, false]);
    }
  });
});

describe('Decision D6: no transition piece is left in src', () => {
  const SRC = join(__dirname, '..');
  const sources = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      if (name === '__tests__') return [];
      if (statSync(path).isDirectory()) return sources(path);
      return name.endsWith('.ts') ? [path] : [];
    });
  const text = sources(SRC).map((path) => [
    relative(SRC, path),
    readFileSync(path, 'utf8'),
  ]);

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
  ])('%s', (needle) => {
    const found = text
      .filter(([, source]) => source?.includes(needle))
      .map(([name]) => name);
    expect(found).toEqual([]);
  });

  it('the deleted modules are gone', () => {
    const names = new Set(text.map(([name]) => name));
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
