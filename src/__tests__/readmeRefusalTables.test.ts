/**
 * The README's refusal tables are rendered: from auth-errors' `render` and
 * the interfaces-auth allowlists, by `helpers/refusalTables.ts`. The
 * committed README must equal the rendered tables. Run with
 * `WRITE_README_TABLES=1` (`npm run docs:tables`), this test writes them
 * first and then asserts as always; CI cannot write.
 */
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
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { tableWriteMode, withRegions } from '@mcp-abap-adt/auth-errors/tables';
import { refusalTableRegions } from './helpers/refusalTables';

const README = join(__dirname, '..', '..', 'README.md');

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
    expect(readFileSync(README, 'utf8')).toBe(expected);
  });

  it('renders the five tables', () => {
    expect(
      refusalTableRegions().map((region) => [region.open, region.close]),
    ).toStrictEqual(
      ['rejected', 'refusals', 'saml', 'saml-candidates', 'configuration'].map(
        (name) => [
          `<!-- generated:refusal-table ${name} -->`,
          `<!-- /generated:refusal-table ${name} -->`,
        ],
      ),
    );
  });

  it.each([
    [
      'rejected',
      'the credential was accepted, but the user is not authorized (403)',
    ],
    ['refusals', '| the client certificate has expired |'],
    ['configuration', '| staticCodeStrategy requires a payload |'],
  ])(
    'a hand-edited row of the %s table differs from the rendered one',
    (_table, words) => {
      const readme = readFileSync(README, 'utf8');
      expect(readme).toContain(words);
      const edited = readme.replace(words, `${words}x`);
      expect(edited).not.toBe(readme);
      expect(withRegions(edited, refusalTableRegions())).toBe(readme);
    },
  );

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
      expect(readFileSync(file, 'utf8')).toBe(current);
    });

    it('leaves a current copy alone: same bytes, same mtime', () => {
      writeFileSync(file, current);
      const past = new Date(Date.now() - 60_000);
      utimesSync(file, past, past);
      const before = statSync(file).mtimeMs;
      writeWhenAsked(file, { WRITE_README_TABLES: '1' });
      expect(readFileSync(file, 'utf8')).toBe(current);
      expect(statSync(file).mtimeMs).toBe(before);
    });

    it('writes nothing without WRITE_README_TABLES', () => {
      writeFileSync(file, stale);
      expect(writeWhenAsked(file, {})).toBe(current);
      expect(readFileSync(file, 'utf8')).toBe(stale);
    });

    it('refuses to write under CI, before touching the file', () => {
      writeFileSync(file, stale);
      expect(() =>
        writeWhenAsked(file, { WRITE_README_TABLES: '1', CI: 'true' }),
      ).toThrow();
      expect(readFileSync(file, 'utf8')).toBe(stale);
    });

    it('refuses any other value of WRITE_README_TABLES', () => {
      writeFileSync(file, stale);
      expect(() =>
        writeWhenAsked(file, { WRITE_README_TABLES: 'yes' }),
      ).toThrow();
      expect(readFileSync(file, 'utf8')).toBe(stale);
    });
  });
});
