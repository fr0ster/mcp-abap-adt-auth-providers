/**
 * The assertions `node:assert/strict` has no single call for, as the moved
 * tests asserted them under Jest: a partial match of an object, membership
 * of a string or an array, a thrown value's message, a case title. Each
 * fails with an `AssertionError`, so it works under any runner.
 */

import assert from 'node:assert/strict';
import { format, isDeepStrictEqual } from 'node:util';

/** A non-null object, not an array: a value whose keys are matched. */
function isRecord(value: unknown): value is Record<PropertyKey, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Whether `actual` matches `expected` as Jest's `toMatchObject` does: an
 * object matches when every key `expected` names matches, recursively; an
 * array when it has the same length and every element matches; anything
 * else when it is deeply and strictly equal.
 */
function matches(actual: unknown, expected: unknown): boolean {
  if (expected instanceof Placeholder) return expected.accepts(actual);
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((item, index) => matches(actual[index], item))
    );
  }
  if (
    isRecord(expected) &&
    Object.getPrototypeOf(expected) === Object.prototype
  ) {
    if (!isRecord(actual)) return false;
    return Reflect.ownKeys(expected).every(
      (key) => key in actual && matches(actual[key], expected[key]),
    );
  }
  return isDeepStrictEqual(actual, expected);
}

/** `actual` holds every field `expected` names, recursively (Jest's `toMatchObject`). */
export function matchObject(
  actual: unknown,
  expected: unknown,
  message?: string,
): void {
  if (!matches(actual, expected)) {
    assert.fail(
      message ??
        `expected ${format('%o', actual)} to match ${format('%o', expected)}`,
    );
  }
}

/**
 * `actual` is an object that does not hold every field `expected` names.
 * As Jest's `not.toMatchObject`, a value that is no object fails: nothing
 * absent passes a negative assertion.
 */
export function notMatchObject(
  actual: unknown,
  expected: unknown,
  message?: string,
): void {
  if (typeof actual !== 'object' || actual === null) {
    assert.fail(
      message ?? `expected an object not to match, got ${format('%o', actual)}`,
    );
  }
  if (matches(actual, expected)) {
    assert.fail(
      message ??
        `expected ${format('%o', actual)} not to match ${format('%o', expected)}`,
    );
  }
}

/** A string holds the fragment, or an array the item (`===`, as Jest's `toContain`). */
export function contains(
  haystack: unknown,
  needle: unknown,
  message?: string,
): void {
  if (typeof haystack !== 'string' && !Array.isArray(haystack)) {
    assert.fail(
      message ??
        `expected a string or an array to contain ${format('%o', needle)}, got ${format('%o', haystack)}`,
    );
  }
  const found =
    typeof haystack === 'string'
      ? typeof needle === 'string' && haystack.includes(needle)
      : haystack.includes(needle);
  if (!found) {
    assert.fail(
      message ??
        `expected ${format('%o', haystack)} to contain ${format('%o', needle)}`,
    );
  }
}

/** A string does not hold the fragment, nor an array the item. */
export function notContains(
  haystack: unknown,
  needle: unknown,
  message?: string,
): void {
  if (typeof haystack !== 'string' && !Array.isArray(haystack)) {
    assert.fail(
      message ??
        `expected a string or an array not to contain ${format('%o', needle)}, got ${format('%o', haystack)}`,
    );
  }
  const found =
    typeof haystack === 'string'
      ? typeof needle === 'string' && haystack.includes(needle)
      : haystack.includes(needle);
  if (found) {
    assert.fail(
      message ??
        `expected ${format('%o', haystack)} not to contain ${format('%o', needle)}`,
    );
  }
}

/** An array holds an item deeply and strictly equal to `item` (Jest's `toContainEqual`). */
export function containsEqual(
  haystack: readonly unknown[],
  item: unknown,
): void {
  if (!haystack.some((entry) => isDeepStrictEqual(entry, item))) {
    assert.fail(
      `expected ${format('%o', haystack)} to contain ${format('%o', item)}`,
    );
  }
}

/** `value` has the property `path` (dotted, as Jest's `toHaveProperty`). */
export function hasProperty(value: unknown, path: string): boolean {
  let current: unknown = value;
  for (const key of path.split('.')) {
    if (current === null || current === undefined) return false;
    if (!(key in Object(current))) return false;
    current = Reflect.get(Object(current), key);
  }
  return true;
}

/**
 * `value` is there (neither `undefined` nor `null`) and has no property
 * `path`: Jest's `not.toHaveProperty`, which failed on a missing value
 * rather than pass it.
 */
export function lacksProperty(
  value: unknown,
  path: string,
  message?: string,
): void {
  assert.ok(
    value !== undefined && value !== null,
    message ?? `expected a value without ${path}, got ${format('%o', value)}`,
  );
  assert.equal(hasProperty(value, path), false, message ?? `has ${path}`);
}

/** What a thrown value must be, as Jest's `toThrow(expected)` read it. */
export type ThrownExpectation =
  | string
  | RegExp
  | Error
  | (abstract new (
      ...args: never[]
    ) => unknown);

/**
 * A validator for `assert.throws` / `assert.rejects`: a string is a fragment
 * of the thrown Error's message, a RegExp is tested on it, an error is its
 * message exactly — each only when what was thrown is an Error; a class is
 * what it is an instance of; nothing expected accepts any throw.
 */
export function thrown(
  expected?: ThrownExpectation,
): (error: unknown) => boolean {
  return (error) => {
    if (expected === undefined) return true;
    if (typeof expected === 'function') {
      assert.ok(
        error instanceof expected,
        `expected an instance of ${expected.name}, got ${format('%o', error)}`,
      );
      return true;
    }
    // A message is expected: only an Error carries one. A primitive whose
    // text matches is no match (a rejection with a bare string passes no
    // message check).
    assert.ok(
      error instanceof Error,
      `expected an Error, got ${format('%o', error)}`,
    );
    const { message } = error;
    if (typeof expected === 'string') {
      contains(message, expected);
      return true;
    }
    if (expected instanceof RegExp) {
      assert.match(message, expected);
      return true;
    }
    assert.equal(message, expected.message);
    return true;
  };
}

/**
 * The title of one case of a table, as Jest's `.each` printed it: `%s`,
 * `%d`, `%i`, `%f`, `%j`, `%o`, `%p` take the row's values in order (a row
 * that is not an array is the one value), `%#` is the index, and `$key` a
 * field of an object row.
 */
export function caseTitle(
  template: string,
  row: unknown,
  index: number,
): string {
  const values: readonly unknown[] = Array.isArray(row) ? row : [row];
  let out = '';
  let next = 0;
  for (let i = 0; i < template.length; i += 1) {
    const char = template[i];
    const spec = template[i + 1];
    if (char === '%' && spec !== undefined) {
      if (spec === '%') {
        out += '%';
        i += 1;
        continue;
      }
      if (spec === '#') {
        out += String(index);
        i += 1;
        continue;
      }
      if ('sdifjop'.includes(spec)) {
        const value = values[next];
        next += 1;
        out +=
          spec === 's' && typeof value === 'string'
            ? value
            : format(spec === 'p' || spec === 'j' ? '%o' : `%${spec}`, value);
        i += 1;
        continue;
      }
    }
    if (char === '$' && isRecord(row)) {
      let end = i + 1;
      while (end < template.length) {
        const c = template[end];
        if (
          c === undefined ||
          !(
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c === '_' ||
            c === '.'
          )
        ) {
          break;
        }
        end += 1;
      }
      const path = template.slice(i + 1, end);
      if (path !== '' && hasProperty(row, path)) {
        let value: unknown = row;
        for (const key of path.split('.'))
          value = Reflect.get(Object(value), key);
        out += typeof value === 'string' ? value : format('%o', value);
        i = end - 1;
        continue;
      }
    }
    out += char;
  }
  return out;
}

/** A string that matches `pattern` (Jest's `toMatch` with a RegExp); anything else fails. */
export function matchText(actual: unknown, pattern: RegExp): void {
  if (typeof actual !== 'string') {
    assert.fail(
      `expected a string matching ${pattern}, got ${format('%o', actual)}`,
    );
  }
  assert.match(actual, pattern);
}

/** A string that does not match `pattern`; anything else fails. */
export function notMatchText(actual: unknown, pattern: RegExp): void {
  if (typeof actual !== 'string') {
    assert.fail(
      `expected a string not matching ${pattern}, got ${format('%o', actual)}`,
    );
  }
  assert.doesNotMatch(actual, pattern);
}

/**
 * A table of cases, each row typed as the tuple it is written as (what
 * Jest's `.each` inferred), so a destructured row keeps each column's type.
 */
export function cases<T extends readonly unknown[] | [unknown]>(
  rows: readonly T[],
): readonly T[] {
  return rows;
}

/** A placeholder in an expected value that accepts what its check accepts. */
class Placeholder {
  constructor(
    readonly description: string,
    readonly accepts: (value: unknown) => boolean,
  ) {}
}

/** Any value of the type a constructor names, as Jest's `expect.any(Type)`. */
export function anyOf(
  type: abstract new (...args: never[]) => unknown,
): Placeholder {
  return new Placeholder(`any ${type.name}`, (value) => {
    if (type === String) return typeof value === 'string';
    if (type === Number) return typeof value === 'number';
    if (type === Boolean) return typeof value === 'boolean';
    if (type === Function) return typeof value === 'function';
    return value instanceof type;
  });
}

/** A string matching the pattern, as Jest's `expect.stringMatching`. */
export function stringMatching(pattern: RegExp): Placeholder {
  return new Placeholder(
    `a string matching ${pattern}`,
    (value) => typeof value === 'string' && pattern.test(value),
  );
}

/** An object holding the fields named, as Jest's `expect.objectContaining`. */
export function objectContaining(fields: object): Placeholder {
  return new Placeholder(
    `an object containing ${format('%o', fields)}`,
    (value) => matches(value, fields),
  );
}

/** Deep, strict equality where a placeholder accepts what its check accepts. */
function equalWith(actual: unknown, expected: unknown): boolean {
  if (expected instanceof Placeholder) return expected.accepts(actual);
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((item, index) => equalWith(actual[index], item))
    );
  }
  if (
    isRecord(expected) &&
    Object.getPrototypeOf(expected) === Object.prototype
  ) {
    if (
      !isRecord(actual) ||
      Object.getPrototypeOf(actual) !== Object.prototype
    ) {
      return false;
    }
    const keys = Reflect.ownKeys(expected);
    return (
      keys.length === Reflect.ownKeys(actual).length &&
      keys.every(
        (key) => key in actual && equalWith(actual[key], expected[key]),
      )
    );
  }
  return isDeepStrictEqual(actual, expected);
}

/** `actual` deeply and strictly equals `expected`, its placeholders accepting what they check. */
export function deepEqualWith(
  actual: unknown,
  expected: unknown,
  message?: string,
): void {
  if (!equalWith(actual, expected)) {
    assert.fail(
      message ??
        `expected ${format('%o', actual)} to equal ${format('%o', expected)}`,
    );
  }
}

/** A placeholder for a string holding the fragment, as Jest's `expect.stringContaining`. */
export function stringContaining(fragment: string): Placeholder {
  return new Placeholder(
    `a string containing ${format('%o', fragment)}`,
    (value) => typeof value === 'string' && value.includes(fragment),
  );
}

/**
 * Some call of the mock had these arguments, its placeholders accepting what
 * they check: Jest's `toHaveBeenCalledWith`.
 */
export function calledWith(
  fn: {
    readonly mock: {
      readonly calls: readonly { readonly arguments: readonly unknown[] }[];
    };
  },
  ...expected: unknown[]
): void {
  const calls = fn.mock.calls.map((call) => call.arguments);
  if (!calls.some((args) => equalWith(args, expected))) {
    assert.fail(
      `expected a call with ${format('%o', expected)}, got ${format('%o', calls)}`,
    );
  }
}
