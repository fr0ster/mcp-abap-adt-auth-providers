/**
 * The expectations helper holds the moved tests' assertions, so a gap in it
 * weakens every test that uses it. Pinned here: what `thrown` accepts.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { thrown } from './expectations';

const WORDS = 'the code exchange returned no access_token';

describe('thrown', () => {
  it('a message expectation passes for an Error carrying it', async () => {
    await assert.rejects(Promise.reject(new Error(WORDS)), thrown(WORDS));
    await assert.rejects(
      Promise.reject(new Error(WORDS)),
      thrown(/no access_token$/),
    );
  });

  it('a primitive rejection whose text matches is no match', async () => {
    // Was: String(error) — a rejection with the bare string passed.
    for (const expected of [WORDS, /no access_token$/, new Error(WORDS)]) {
      await assert.rejects(
        assert.rejects(Promise.reject(WORDS), thrown(expected)),
        assert.AssertionError,
      );
    }
  });

  it('an Error with other words is no match', async () => {
    await assert.rejects(
      assert.rejects(Promise.reject(new Error('other')), thrown(WORDS)),
      assert.AssertionError,
    );
  });

  it('a class is what the value is an instance of; nothing expected accepts any rejection', async () => {
    await assert.rejects(
      Promise.reject(new RangeError('x')),
      thrown(RangeError),
    );
    await assert.rejects(Promise.reject('anything'), thrown());
  });
});
