/**
 * Jest's queue of one-time answers on a `node:test` mock. Jest's
 * `mockResolvedValueOnce(a)` then `(b)` answers the next call with `a` and
 * the one after with `b`; node's `mockImplementationOnce(impl)` targets the
 * next call by default, so two in a row would both target the same call.
 * `once` gives each one the call after the last one queued.
 */

import assert from 'node:assert/strict';
import type { Mock } from 'node:test';

/** The next call each mock has a one-time answer queued for, past its calls. */
const queued = new WeakMap<object, number>();

/** Answers one call with `impl`: the next call no earlier one-time answer took. */
export function once<F extends (...args: never[]) => unknown>(
  fn: Mock<F>,
  impl: F,
): void {
  const next = Math.max(fn.mock.callCount(), queued.get(fn) ?? 0);
  fn.mock.mockImplementationOnce(impl, next);
  queued.set(fn, next + 1);
}

/**
 * Forgets a mock's calls and its implementation: Jest's `mockReset`. The
 * mock answers as when it was made.
 *
 * node keeps a one-time answer no call took, keyed by its call number, past
 * `resetCalls()`, and nothing removes it: after the reset it would answer a
 * later call. Jest dropped it. So a reset with a one-time answer still
 * queued fails, naming the mock's state, instead of letting it answer.
 */
export function resetMock<F extends (...args: never[]) => unknown>(
  fn: Mock<F>,
): void {
  const pending = (queued.get(fn) ?? 0) - fn.mock.callCount();
  assert.ok(
    pending <= 0,
    `a reset with ${pending} one-time answer(s) no call took`,
  );
  fn.mock.resetCalls();
  fn.mock.restore();
  queued.delete(fn);
}

/**
 * Forgets a mock's calls, its implementation kept: Jest's `mockClear`. A
 * one-time answer still queued fails it, as in `resetMock`: node keys it by
 * call number, so after the calls are forgotten it would answer a later
 * call than the one it was queued for.
 */
export function clearMock<F extends (...args: never[]) => unknown>(
  fn: Mock<F>,
): void {
  const pending = (queued.get(fn) ?? 0) - fn.mock.callCount();
  assert.ok(
    pending <= 0,
    `a clear with ${pending} one-time answer(s) no call took`,
  );
  fn.mock.resetCalls();
  queued.delete(fn);
}
