/**
 * `renewal` is required in every token provider's configuration (rule 7): a missing or unusable one is refused at construction —
 * `configuration` `required-fields-missing`, `fields: ['renewal']` —
 * read as own data like every other required collaborator, through every
 * constructor and every static factory. Nothing is called, nothing sent.
 */

import { describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import axios from 'axios';
import {
  authorize,
  BUILDERS,
  presenter,
  throwingProxy as proxyThrowing,
  validator,
} from '../helpers/tokenProviderBuilders';

const SECRET = 'RENEWAL-OPTION-SECRET-7';
const throwingProxy = proxyThrowing(SECRET);

/** What `renewal` is given, as extra fields — or as an accessor. */
const UNUSABLE: ReadonlyArray<[string, () => object]> = [
  ['missing', () => ({})],
  ['undefined', () => ({ renewal: undefined })],
  ['null', () => ({ renewal: null })],
  ['a string', () => ({ renewal: 'refreshThenLogin' })],
  ['an object without next', () => ({ renewal: {} })],
  ['next not a function', () => ({ renewal: { next: 'refresh' } })],
  ['a throwing Proxy', () => ({ renewal: throwingProxy })],
  [
    'a next getter that throws',
    () => ({
      renewal: Object.defineProperty({}, 'next', {
        get() {
          throw new Error(SECRET);
        },
      }),
    }),
  ],
  [
    'an accessor on the options (never run)',
    () =>
      Object.defineProperty({}, 'renewal', {
        enumerable: true,
        get() {
          throw new Error(SECRET);
        },
      }),
  ],
];

describe('a missing or unusable renewal is refused at construction', () => {
  const cases = BUILDERS.flatMap(([builder, build]) =>
    UNUSABLE.map(([what, extra]) => [builder, what, build, extra] as const),
  );

  it.each(cases)('%s, renewal %s', (_builder, _what, build, extra) => {
    const post = jest.spyOn(axios, 'post');
    const request = jest.spyOn(axios, 'request');
    let thrown: unknown;
    try {
      build(extra());
    } catch (error) {
      thrown = error;
    }
    try {
      expect(isAuthProviderFailure(thrown)).toBe(true);
      const error = readFailure(thrown, 'unfamiliar-error');
      expect(error).toMatchObject({
        kind: 'configuration',
        facts: { case: 'required-fields-missing', fields: ['renewal'] },
        reason: 'required configuration is missing: renewal',
      });
      expect(JSON.stringify(error)).not.toContain(SECRET);
      expect(String(thrown)).not.toContain(SECRET);
      expect(authorize).not.toHaveBeenCalled();
      expect(presenter.present).not.toHaveBeenCalled();
      expect(validator.validate).not.toHaveBeenCalled();
      expect(post).not.toHaveBeenCalled();
      expect(request).not.toHaveBeenCalled();
    } finally {
      post.mockRestore();
      request.mockRestore();
    }
  });
});
