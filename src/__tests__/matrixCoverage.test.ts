/**
 * Every row of the diagnostic compatibility matrix
 * that belongs to this package has a test named by its row id, or is listed
 * as removed with its reason. The I rows belong to connection, the J rows to
 * the broker and the CLI.
 *
 * A row is named when a test's full name holds the row id as a whole token
 * (`` is not found in ``): the literal title of an `it(…)` /
 * `it.each(…)(…)` / `test(…)` call, or of a `describe(…)` block around tests
 * (Jest's full name begins with it), read by plain scanning. While the spec is in the tree
 * its Appendix A row ids must equal this list, so a row added there fails
 * here until it is listed; once the spec is deleted (before the release,
 * CLAUDE.md "Plans and specs") the list below stands alone.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import {
  describeTitles,
  namesRow,
  testFiles,
  testTitles,
} from './helpers/testTitles';

const SERIES: ReadonlyArray<readonly [string, number]> = [
  ['A', 19],
  ['B', 15],
  ['K', 17],
  ['D', 8],
  ['E', 28],
  ['F', 8],
  ['G', 10],
  ['H', 10],
];

const ROWS: readonly string[] = SERIES.flatMap(([prefix, count]) =>
  Array.from({ length: count }, (_, i) => `${prefix}${i + 1}`),
);

/** Rows with no behaviour left to test, each with the reason. */
const REMOVED: ReadonlyMap<string, string> = new Map([
  [
    'A12',
    'ServiceKeyError / SessionDataError had no producer in this package and were deleted with the classes (spec §6, Task 27)',
  ],
  [
    'A19',
    'refusalWords is deleted; a consumer calls classify(error, operation) (L10, Task 27)',
  ],
  [
    'H9',
    'the words inside TokenEndpointError went with the class; D2 carries them (Task 21)',
  ],
  [
    'K7',
    'the timeoutMs option and its invalid-value error are gone (spec §6a, L14, Task 23)',
  ],
  [
    'K9',
    'no built-in login timeout; an abort is K4 with the ignored-callback count (spec §6a, L14, Task 23)',
  ],
]);

const OUT_OF_PACKAGE = ['I', 'J'];

const TESTS = __dirname;
const SPEC = join(
  __dirname,
  '..',
  '..',
  'docs',
  'superpowers',
  'specs',
  '2026-10-05-error-contract-design.md',
);

/**
 * Every literal test and describe title under `src/__tests__`, with its file;
 * a file without a test contributes nothing.
 */
function allTitles(): Array<readonly [string, string]> {
  return testFiles(TESTS)
    .filter((path) => !path.endsWith('matrixCoverage.test.ts'))
    .flatMap((path) => {
      const source = readFileSync(path, 'utf8');
      const tests = testTitles(source);
      if (tests.size === 0) return [];
      return [...tests, ...describeTitles(source)].map(
        (title) => [relative(TESTS, path), title] as const,
      );
    });
}

/**
 * The row ids of Appendix A's tables: a line starting `| <id> |` between the
 * appendix heading and the next one, read by plain scanning.
 */
function specRows(text: string): string[] {
  const start = text.indexOf('## Appendix A');
  const end = text.indexOf('## Appendix B');
  const rows: string[] = [];
  for (const line of text.slice(start, end).split('\n')) {
    if (!line.startsWith('| ')) continue;
    const cell = line.slice(2, line.indexOf(' |', 2));
    const prefix = cell[0] ?? '';
    const number = cell.slice(1);
    if (
      prefix >= 'A' &&
      prefix <= 'Z' &&
      number.length > 0 &&
      [...number].every((c) => c >= '0' && c <= '9')
    ) {
      rows.push(cell);
    }
  }
  return rows;
}

describe('the diagnostic compatibility matrix: one named test per row', () => {
  const titles = allTitles();

  it('the row reader finds whole ids only', () => {
    expect(namesRow('A1: words', 'A1')).toBe(true);
    expect(namesRow('K17 / A2: x', 'A2')).toBe(true);
    expect(namesRow('A10: x', 'A1')).toBe(false);
    expect(namesRow('XA1 x', 'A1')).toBe(false);
    expect(namesRow('E1x', 'E1')).toBe(false);
  });

  it('a template-literal title is read too', () => {
    const dollar = '$';
    const title = `G5: ${dollar}{name} paths`;
    const found = testTitles(`it(\`${title}\`, () => {});`);
    expect([...found]).toEqual([title]);
  });

  const SPEC_PRESENT = existsSync(SPEC);
  (SPEC_PRESENT ? it : it.skip)(
    'the list equals the spec’s Appendix A rows of this package (skipped once the spec is deleted)',
    () => {
      const rows = specRows(readFileSync(SPEC, 'utf8')).filter(
        (id) => !OUT_OF_PACKAGE.includes(id[0] ?? ''),
      );
      expect(rows).toEqual([...ROWS]);
    },
  );

  it.each(ROWS.filter((id) => !REMOVED.has(id)))(
    '%s has a test named by its id',
    (id) => {
      const named = titles.filter(([, title]) => namesRow(title, id));
      expect([id, named.length > 0]).toEqual([id, true]);
    },
  );

  it.each([...REMOVED])('%s is removed: %s', (id, reason) => {
    expect(ROWS).toContain(id);
    expect(reason.length).toBeGreaterThan(20);
  });
});
