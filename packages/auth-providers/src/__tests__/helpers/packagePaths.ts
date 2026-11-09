/**
 * Where a test finds the package's files. A test runs from its source
 * (`src/__tests__/…`, under Jest) or from its compiled copy
 * (`.test-build/__tests__/…`, under node:test); this file sits at the same
 * depth in both, so the package root is three directories up either way,
 * and the sources and fixtures are always read from `src/`, never from the
 * compiled copy.
 */

import { join } from 'node:path';

/** The package directory: `packages/auth-providers`. */
export const PACKAGE_ROOT = join(__dirname, '..', '..', '..');
/** The TypeScript sources. */
export const SRC = join(PACKAGE_ROOT, 'src');
/** The test sources. */
export const TESTS = join(SRC, '__tests__');
/** The certificate fixtures. */
export const CERTIFICATES = join(TESTS, 'fixtures', 'certificates');
