/**
 * A `persistence` that is given must be usable: an
 * object whose `report` is a function. Anything else — `null`, a non-object,
 * an object without a callable `report`, a Proxy or getter that throws — is
 * refused at construction, `configuration` `invalid-value`, `fields:
 * ['persistence']`, through every constructor and every static factory.
 * Absent (not given, or `undefined`) is the consumer's choice: nothing is
 * persisted, nothing refused.
 */

import { describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import axios from 'axios';
import { refreshThenLogin } from '../../renewal';
import {
  authorize,
  BUILDERS,
  own,
  presenter,
  throwingProxy,
  validator,
} from '../helpers/tokenProviderBuilders';

const SECRET = 'PERSISTENCE-OPTION-SECRET-3';

/** What `persistence` is given, as extra fields — or as an accessor. */
const UNUSABLE: ReadonlyArray<[string, () => object]> = [
  ['null', () => ({ persistence: null })],
  ['a string', () => ({ persistence: 'store' })],
  ['a number', () => ({ persistence: 42 })],
  ['a function', () => ({ persistence: () => undefined })],
  ['an object without report', () => ({ persistence: {} })],
  ['report not a function', () => ({ persistence: { report: 'write' } })],
  ['a throwing Proxy', () => ({ persistence: throwingProxy(SECRET) })],
  [
    'a report getter that throws',
    () => ({
      persistence: Object.defineProperty({}, 'report', {
        get() {
          throw new Error(SECRET);
        },
      }),
    }),
  ],
];

const withRenewal = (extra: object): object =>
  own({ renewal: refreshThenLogin() }, extra);

describe('a malformed persistence is refused at construction', () => {
  const cases = BUILDERS.flatMap(([builder, build]) =>
    UNUSABLE.map(([what, extra]) => [builder, what, build, extra] as const),
  );

  it.each(cases)('%s, persistence %s', (_builder, _what, build, extra) => {
    const post = jest.spyOn(axios, 'post');
    const request = jest.spyOn(axios, 'request');
    let thrown: unknown;
    try {
      build(withRenewal(extra()));
    } catch (error) {
      thrown = error;
    }
    try {
      expect(isAuthProviderFailure(thrown)).toBe(true);
      const error = readFailure(thrown, 'unfamiliar-error');
      expect(error).toMatchObject({
        kind: 'configuration',
        facts: { case: 'invalid-value', fields: ['persistence'] },
        reason: 'a configured value cannot be used: persistence',
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

describe('an absent persistence is a choice, not a fault', () => {
  const ABSENT: ReadonlyArray<[string, () => object]> = [
    ['not given', () => ({})],
    ['undefined', () => ({ persistence: undefined })],
    [
      'an accessor on the options (never run, read as absent)',
      () =>
        Object.defineProperty({}, 'persistence', {
          enumerable: true,
          get() {
            throw new Error(SECRET);
          },
        }),
    ],
    ['usable', () => ({ persistence: { report: () => undefined } })],
  ];
  const cases = BUILDERS.flatMap(([builder, build]) =>
    ABSENT.map(([what, extra]) => [builder, what, build, extra] as const),
  );

  it.each(cases)('%s, persistence %s: constructed', (_b, _w, build, extra) => {
    expect(() => build(withRenewal(extra()))).not.toThrow();
  });
});
