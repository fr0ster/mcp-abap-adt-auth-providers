/**
 * once / resetMock / clearMock: one-time answers queue call after call, and
 * a reset or a clear leaves no stale one behind — also when it fails because
 * one was never taken (a test that failed early), so the next test's reset
 * does not fail on the same answer.
 */

import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import { thrown } from './expectations';
import { clearMock, once, resetMock } from './mockOnce';

describe('mockOnce', () => {
  it('one-time answers answer the next calls, in order', () => {
    const fn = mock.fn((): string => 'original');
    once(fn, () => 'first');
    once(fn, () => 'second');
    assert.deepEqual([fn(), fn(), fn()], ['first', 'second', 'original']);
  });

  it('a reset with an answer no call took fails, and leaves the mock clean', () => {
    const fn = mock.fn((): string => 'original');
    once(fn, () => 'stale');
    assert.throws(() => resetMock(fn), thrown('one-time answer'));
    // Clean: a second reset passes, and the next call answers as made.
    resetMock(fn);
    assert.equal(fn(), 'original');
    assert.equal(fn.mock.callCount(), 1);
  });

  it('a clear with an answer no call took fails, and keeps the implementation, without the stale answer', () => {
    const fn = mock.fn((): string => 'original');
    fn.mock.mockImplementation(() => 'kept');
    fn();
    once(fn, () => 'stale');
    assert.throws(() => clearMock(fn), thrown('one-time answer'));
    clearMock(fn);
    assert.deepEqual([fn(), fn()], ['kept', 'kept']);
  });
});
