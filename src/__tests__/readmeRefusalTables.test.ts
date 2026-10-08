/**
 * The README's refusal tables are generated: from auth-errors'
 * `render` and the interfaces-auth allowlists, by
 * `scripts/generate-refusal-tables.mjs`. The committed README must equal
 * what the script generates; `npm run docs:tables` rewrites it.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';

const root = join(__dirname, '..', '..');
const script = join(root, 'scripts', 'generate-refusal-tables.mjs');

const check = (readme?: string) =>
  spawnSync(
    process.execPath,
    [script, '--check', ...(readme ? ['--readme', readme] : [])],
    { cwd: root, encoding: 'utf8' },
  );

describe('README refusal tables', () => {
  it('the committed README equals the generated tables', () => {
    const run = check();
    expect(run.stderr).toBe('');
    expect(run.status).toBe(0);
  });

  it.each([
    [
      'rejected',
      'the credential was accepted, but the user is not authorized (403)',
    ],
    ['refusals', '| the client certificate has expired |'],
    ['configuration', '| staticCodeStrategy requires a payload |'],
  ])('a hand-edited row of the %s table fails the check', (_table, words) => {
    const dir = mkdtempSync(join(tmpdir(), 'refusal-tables-'));
    try {
      const copy = join(dir, 'README.md');
      const readme = readFileSync(join(root, 'README.md'), 'utf8');
      expect(readme).toContain(words);
      writeFileSync(copy, readme.replace(words, `${words}x`));
      const run = check(copy);
      expect(run.status).toBe(1);
      expect(run.stderr).toContain('npm run docs:tables');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
