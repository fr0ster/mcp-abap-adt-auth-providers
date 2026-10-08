/**
 * No log call in `src` takes a URL, an endpoint or another free value.
 *
 * A source scan, so a new line cannot slip one in: every call of a logger
 * method (`.debug(`, `.info(`, `.warn(`, `.error(`, `logger[level](`), every
 * prompt (`announce(`) and every `stderr.write(` is found, its argument text
 * cut out by balanced parentheses, string literals dropped (a template's
 * `${…}` kept) and the identifiers left checked against a list of names a
 * free value travels under. A prompt may show a URL only as `promptableUrl`
 * admitted it — an identifier starting `shown`. Plain code over this
 * package's own source; no regular expression.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from '@jest/globals';

const SRC = join(__dirname, '..', '..');

/** Names a URL, an endpoint or a consumer's or server's free text goes by. */
const FREE_NAMES = [
  'url',
  'uri',
  'endpoint',
  'href',
  'issuer',
  'clientid',
  'username',
  'redirect',
  'scope',
  'audience',
  'message',
  'stack',
  'cause',
];

const CALL_OPENERS = [
  '.debug(',
  '.info(',
  '.warn(',
  '.error(',
  'logger[level](',
  'announce(',
  'stderr.write(',
];

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      return name === '__tests__' ? [] : sourceFiles(path);
    }
    return name.endsWith('.ts') ? [path] : [];
  });
}

const isIdentifierChar = (c: string) =>
  (c >= 'a' && c <= 'z') ||
  (c >= 'A' && c <= 'Z') ||
  (c >= '0' && c <= '9') ||
  c === '_' ||
  c === '$';

/**
 * The code of a call's arguments starting at `open` (the index of its `(`):
 * string literals blanked, a template's `${…}` kept, up to the matching `)`.
 */
function argumentCode(text: string, open: number): string {
  let depth = 0;
  let out = '';
  let i = open;
  const templates: number[] = [];
  while (i < text.length) {
    const c = text[i] ?? '';
    if (c === "'" || c === '"') {
      i += 1;
      while (i < text.length && text[i] !== c) {
        if (text[i] === '\\') i += 1;
        i += 1;
      }
      out += ' ';
      i += 1;
      continue;
    }
    if (c === '`' || (c === '}' && templates.at(-1) === depth)) {
      if (c === '}') templates.pop();
      // Inside a template literal: skip to its end or the next `${`.
      i += 1;
      while (i < text.length && text[i] !== '`') {
        if (text[i] === '\\') {
          i += 2;
          continue;
        }
        if (text[i] === '$' && text[i + 1] === '{') {
          templates.push(depth);
          i += 1;
          break;
        }
        i += 1;
      }
      out += ' ';
      i += 1;
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }
    if (c === '(' || c === '{' || c === '[') depth += 1;
    if (c === ')' || c === '}' || c === ']') {
      depth -= 1;
      if (depth === 0 && c === ')') return out;
    }
    out += c;
    i += 1;
  }
  return out;
}

/** The index of the `)` closing the `(` at `open` (no strings expected). */
function closingParen(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === '(') depth += 1;
    if (text[i] === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return text.length;
}

function identifiers(code: string): string[] {
  const found: string[] = [];
  let current = '';
  for (const c of `${code} `) {
    if (isIdentifierChar(c)) {
      current += c;
    } else if (current !== '') {
      found.push(current);
      current = '';
    }
  }
  return found;
}

/** A free name among a call's identifiers, else undefined. */
function freeNameIn(code: string): string | undefined {
  return identifiers(code).find((name) => {
    const lower = name.toLowerCase();
    if (lower.startsWith('shown')) return false;
    return FREE_NAMES.some((free) => lower.includes(free));
  });
}

interface LogCall {
  readonly where: string;
  readonly code: string;
}

function logCalls(file: string): LogCall[] {
  const text = readFileSync(file, 'utf8');
  const calls: LogCall[] = [];
  for (const opener of CALL_OPENERS) {
    let at = text.indexOf(opener);
    while (at !== -1) {
      const open = at + opener.length - 1;
      const line = text.slice(0, at).split('\n').length;
      // `announce(` inside `announcer(` or a declaration is not a call.
      const before = text[at - 1] ?? '';
      const isWord = opener === 'announce(' && isIdentifierChar(before);
      const declared =
        opener === 'announce(' &&
        text.slice(Math.max(0, at - 9), at) === 'function ';
      if (!isWord && !declared) {
        calls.push({
          where: `${relative(SRC, file)}:${line}`,
          code: argumentCode(text, open),
        });
      }
      at = text.indexOf(opener, at + 1);
    }
  }
  return calls;
}

describe('log calls in src', () => {
  const calls = sourceFiles(SRC).flatMap(logCalls);

  it('finds the log calls (the scan is not empty)', () => {
    expect(calls.length).toBeGreaterThan(60);
  });

  it('no log call takes a URL, an endpoint or another free value', () => {
    const offending = calls
      .map((call) => ({ ...call, name: freeNameIn(call.code) }))
      .filter((call) => call.name !== undefined)
      .map((call) => `${call.where}: ${call.name}`);
    expect(offending).toEqual([]);
  });

  it('every announcer is bound to a name before a prompt goes through it', () => {
    // `announcer(logger)(text)` would hide the prompt from the scan above.
    const unbound = sourceFiles(SRC).flatMap((file) => {
      const text = readFileSync(file, 'utf8');
      const found: string[] = [];
      let at = text.indexOf('announcer(');
      while (at !== -1) {
        const close = closingParen(text, at + 'announcer'.length);
        if (text[close + 1] === '(') {
          found.push(
            `${relative(SRC, file)}:${text.slice(0, at).split('\n').length}`,
          );
        }
        at = text.indexOf('announcer(', at + 1);
      }
      return found;
    });
    expect(unbound).toEqual([]);
  });

  it('the scan catches a free value (the check is load-bearing)', () => {
    // A template's `${` written apart, so the samples are plain strings.
    const open$ = '$' + '{';
    const sample = `logger?.info(\`Exchanging code: ${open$}prepared?.config.url ?? tokenUrl}\`, { tokenEndpoint });`;
    expect(freeNameIn(argumentCode(sample, sample.indexOf('(')))).toBe('url');
    const words = "logger?.info('[OIDC] Fetching the url', { wait });";
    expect(freeNameIn(argumentCode(words, words.indexOf('(')))).toBeUndefined();
    const shown = `announce(\`   ${open$}shownUrl}\`);`;
    expect(freeNameIn(argumentCode(shown, shown.indexOf('(')))).toBeUndefined();
    const raw = `announce(\`   ${open$}authorizationUrl}\`);`;
    expect(freeNameIn(argumentCode(raw, raw.indexOf('(')))).toBe(
      'authorizationUrl',
    );
  });
});
