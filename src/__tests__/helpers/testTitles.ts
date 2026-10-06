/**
 * The literal titles of our own test files, read by plain scanning (no
 * regular expression): the string literal — single, double or backtick
 * quoted — that opens the argument list of `it(` / `test(`, or of the call
 * after `it.each(…)` / `test.each(…)`. A `describe` title is not a test and
 * is never collected. A template literal's `${…}` parts are kept as written.
 */
import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

export function testFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return testFiles(path);
    return name.endsWith('.ts') ? [path] : [];
  });
}

/** A character that continues an identifier or a member access. */
function isIdentifierPart(c: string): boolean {
  return (
    (c >= 'a' && c <= 'z') ||
    (c >= 'A' && c <= 'Z') ||
    (c >= '0' && c <= '9') ||
    c === '_' ||
    c === '$' ||
    c === '.'
  );
}

/** Characters that may sit between `it` / `it.each(…)` and the title's `(`. */
const SPACE = new Set([' ', '\n', '\t', '\r']);

function openersOf(source: string, word: string, openers: number[]): void {
  const call = `${word}(`;
  let at = source.indexOf(call);
  while (at !== -1) {
    if (at === 0 || !isIdentifierPart(source[at - 1] ?? '')) {
      openers.push(at + call.length);
    }
    at = source.indexOf(call, at + 1);
  }
  const each = `${word}.each(`;
  at = source.indexOf(each);
  while (at !== -1) {
    if (at === 0 || !isIdentifierPart(source[at - 1] ?? '')) {
      // Skip the table: the matching parenthesis, then the call's `(`.
      let depth = 0;
      let i = at + `${word}.each`.length;
      for (; i < source.length; i += 1) {
        const c = source[i];
        if (c === '(') depth += 1;
        else if (c === ')') {
          depth -= 1;
          if (depth === 0) break;
        }
      }
      let j = i + 1;
      while (SPACE.has(source[j] ?? '')) j += 1;
      if (source[j] === '(') openers.push(j + 1);
    }
    at = source.indexOf(each, at + 1);
  }
}

export function testTitles(source: string): Set<string> {
  return titlesOf(source, ['it', 'test']);
}

/**
 * The titles of a file's `describe(…)` / `describe.each(…)(…)` blocks: a
 * test's full name, as Jest reports it, begins with them.
 */
export function describeTitles(source: string): Set<string> {
  return titlesOf(source, ['describe']);
}

function titlesOf(source: string, words: readonly string[]): Set<string> {
  const titles = new Set<string>();
  const openers: number[] = [];
  for (const word of words) openersOf(source, word, openers);
  for (const start of openers) {
    let i = start;
    while (SPACE.has(source[i] ?? '')) i += 1;
    const quote = source[i];
    if (quote !== "'" && quote !== '"' && quote !== '`') continue;
    let title = '';
    for (i += 1; i < source.length && source[i] !== quote; i += 1) {
      if (source[i] === '\\') {
        i += 1;
      }
      title += source[i];
    }
    titles.add(title);
  }
  return titles;
}

function isIdChar(c: string): boolean {
  return (
    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
  );
}

/**
 * Whether `title` names the row `id` as a whole token: `A1` is not found in
 * `A10` or in `XA1`.
 */
export function namesRow(title: string, id: string): boolean {
  let at = title.indexOf(id);
  while (at !== -1) {
    const before = at === 0 ? '' : (title[at - 1] ?? '');
    const after = title[at + id.length] ?? '';
    if (!isIdChar(before) && !isIdChar(after)) return true;
    at = title.indexOf(id, at + 1);
  }
  return false;
}
