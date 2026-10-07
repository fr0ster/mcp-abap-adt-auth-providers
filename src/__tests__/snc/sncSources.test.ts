/**
 * The user's rules, as source checks:
 * - no regular expression runs over untrusted input in `src/snc` — the
 *   registry output, a file head, an environment value, the SDK's error text
 *   are read by plain code;
 * - no built-in timeout: no timer and no `timeout` option anywhere in `src`
 *   but the server's device-poll interval (`src/auth/attempt.ts`).
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

function linesWith(files: string[], needles: readonly string[]): string[] {
  return files.flatMap((file) =>
    readFileSync(file, 'utf8')
      .split('\n')
      .flatMap((line, i) =>
        needles.some((needle) => line.includes(needle))
          ? [`${relative(SRC, file)}:${i + 1}: ${line.trim()}`]
          : [],
      ),
  );
}

/** `file:N: text` → `file: text`. */
function withoutLineNumber(entry: string): string {
  const first = entry.indexOf(':');
  const second = entry.indexOf(':', first + 1);
  return `${entry.slice(0, first)}:${entry.slice(second + 1)}`;
}

describe('src/snc reads untrusted text without regular expressions', () => {
  it('no RegExp, no regex literal method', () => {
    expect(
      linesWith(sourceFiles(join(SRC, 'snc')), [
        'RegExp',
        '.test(',
        '.exec(',
        '.match(',
        '.matchAll(',
        '.search(',
        'replace(/',
        'replaceAll(/',
        'split(/',
      ]),
    ).toEqual([]);
  });
});

describe('src/snc has no timer and no timeout of its own', () => {
  it('no timeout option (shorthand included), timers module or timer call', () => {
    expect(
      linesWith(sourceFiles(join(SRC, 'snc')), [
        '{ timeout',
        'timeout }',
        'timeout,',
        'timeout:',
        'timers/promises',
        "'timers'",
        'AbortSignal.timeout(',
        'setTimeout',
        'setInterval',
        'setImmediate',
      ]),
    ).toEqual([]);
  });
});

describe('no package timer', () => {
  it('setTimeout only for the server’s poll interval; no setInterval', () => {
    // Pinned by file and text, not line number: an edit above it moves the
    // line, but a second timer anywhere — or this one elsewhere — still fails.
    const found = linesWith(sourceFiles(SRC), ['setTimeout(', 'setInterval(']);
    expect(found.map(withoutLineNumber)).toEqual([
      'auth/attempt.ts: const timer = setTimeout(() => {',
    ]);
    // The one timer is intervalWait's, the server's poll interval.
    const source = readFileSync(join(SRC, 'auth', 'attempt.ts'), 'utf8');
    const wait = source.indexOf('export function intervalWait(');
    const timer = source.indexOf('const timer = setTimeout(');
    expect(wait).toBeGreaterThan(-1);
    expect(timer).toBeGreaterThan(wait);
    expect(source.indexOf('export function', wait + 1)).toBe(-1);
  });
  it('no timeout option', () => {
    expect(linesWith(sourceFiles(SRC), ['timeout:', 'REG_TIMEOUT_MS'])).toEqual(
      [],
    );
  });
});
