/**
 * The README's refusal tables are rendered: from auth-errors' `render` and
 * the interfaces-auth allowlists, by `helpers/refusalTables.ts`. The
 * committed README must equal the rendered tables. Run with
 * `WRITE_README_TABLES=1` (`npm run docs:tables`), this test writes them
 * first and then asserts as always; CI cannot write.
 */

import assert from 'node:assert/strict';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { tableWriteMode, withRegions } from '@mcp-abap-adt/auth-errors/tables';
import { cases, caseTitle, contains, thrown } from './helpers/expectations';
import { PACKAGE_ROOT } from './helpers/packagePaths';
import { refusalTableRegions } from './helpers/refusalTables';

const README = join(PACKAGE_ROOT, 'README.md');

/**
 * Writes the rendered tables into `file` when `env` asks for write mode and
 * the file differs; answers the text the file must hold. Write mode is
 * decided before anything is read or written.
 */
function writeWhenAsked(
  file: string,
  env: Readonly<Record<string, string | undefined>>,
): string {
  const write = tableWriteMode(env);
  const current = readFileSync(file, 'utf8');
  const expected = withRegions(current, refusalTableRegions());
  if (write && expected !== current) writeFileSync(file, expected);
  return expected;
}

describe('README refusal tables', () => {
  it('the README tables equal the rendered ones (regenerate: npm run docs:tables)', () => {
    const expected = writeWhenAsked(README, process.env);
    assert.equal(readFileSync(README, 'utf8'), expected);
  });

  it('renders the six tables', () => {
    assert.deepEqual(
      refusalTableRegions().map((region) => [region.open, region.close]),
      [
        'rejected',
        'refusals',
        'saml',
        'saml-candidates',
        'configuration',
        'spnego',
      ].map((name) => [
        `<!-- generated:refusal-table ${name} -->`,
        `<!-- /generated:refusal-table ${name} -->`,
      ]),
    );
  });

  for (const [caseIndex, caseRow] of cases([
    [
      'rejected',
      'the credential was accepted, but the user is not authorized (403)',
    ],
    ['refusals', '| the client certificate has expired |'],
    ['configuration', '| staticCodeStrategy requires a payload |'],
  ]).entries()) {
    const [_table, words] = caseRow;
    it(
      caseTitle(
        'a hand-edited row of the %s table differs from the rendered one',
        caseRow,
        caseIndex,
      ),
      () => {
        const readme = readFileSync(README, 'utf8');
        contains(readme, words);
        const edited = readme.replace(words, `${words}x`);
        assert.notEqual(edited, readme);
        assert.equal(withRegions(edited, refusalTableRegions()), readme);
      },
    );
  }

  describe('write mode, on a temporary copy', () => {
    let dir: string;
    let file: string;
    let current: string;
    let stale: string;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), 'refusal-tables-'));
      file = join(dir, 'README.md');
      current = readFileSync(README, 'utf8');
      const words = '| the client certificate has expired |';
      stale = current.replace(words, `${words}x`);
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('rewrites a stale copy, touching only the regions', () => {
      writeFileSync(file, stale);
      writeWhenAsked(file, { WRITE_README_TABLES: '1' });
      assert.equal(readFileSync(file, 'utf8'), current);
    });

    it('leaves a current copy alone: same bytes, same mtime', () => {
      writeFileSync(file, current);
      const past = new Date(Date.now() - 60_000);
      utimesSync(file, past, past);
      const before = statSync(file).mtimeMs;
      writeWhenAsked(file, { WRITE_README_TABLES: '1' });
      assert.equal(readFileSync(file, 'utf8'), current);
      assert.equal(statSync(file).mtimeMs, before);
    });

    it('writes nothing without WRITE_README_TABLES', () => {
      writeFileSync(file, stale);
      assert.equal(writeWhenAsked(file, {}), current);
      assert.equal(readFileSync(file, 'utf8'), stale);
    });

    it('refuses to write under CI, before touching the file', () => {
      writeFileSync(file, stale);
      assert.throws(
        () => writeWhenAsked(file, { WRITE_README_TABLES: '1', CI: 'true' }),
        thrown(),
      );
      assert.equal(readFileSync(file, 'utf8'), stale);
    });

    it('refuses any other value of WRITE_README_TABLES', () => {
      writeFileSync(file, stale);
      assert.throws(
        () => writeWhenAsked(file, { WRITE_README_TABLES: 'yes' }),
        thrown(),
      );
      assert.equal(readFileSync(file, 'utf8'), stale);
    });
  });
});
