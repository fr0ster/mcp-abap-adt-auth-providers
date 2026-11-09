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

/** An answer that does nothing: what a dropped one-time answer is replaced by. */
const nothing = (): undefined => undefined;

/**
 * Drops every one-time answer queued on `fn` that no call took, and answers
 * how many there were. node keeps such an answer keyed by its call number,
 * and nothing removes it: after `resetCalls()` it would answer a later call.
 * So each one is first replaced by an answer that does nothing (a one-time
 * answer for the same call number), and then taken by a call — the mock's
 * calls are forgotten right after, by the caller.
 */
function dropPending<F extends (...args: never[]) => unknown>(
  fn: Mock<F>,
): number {
  const from = fn.mock.callCount();
  const to = queued.get(fn) ?? 0;
  queued.delete(fn);
  for (let call = from; call < to; call += 1) {
    Reflect.apply(fn.mock.mockImplementationOnce, fn.mock, [nothing, call]);
  }
  for (let call = from; call < to; call += 1) Reflect.apply(fn, undefined, []);
  return Math.max(0, to - from);
}

/**
 * Forgets a mock's calls and its implementation: Jest's `mockReset`. The
 * mock answers as when it was made. A one-time answer no call took is
 * dropped first, then reported: the reset fails, naming how many, but the
 * mock is clean either way, so the next test's reset does not fail on it.
 */
export function resetMock<F extends (...args: never[]) => unknown>(
  fn: Mock<F>,
): void {
  const pending = dropPending(fn);
  fn.mock.resetCalls();
  fn.mock.restore();
  assert.equal(
    pending,
    0,
    `a reset with ${pending} one-time answer(s) no call took`,
  );
}

/**
 * Forgets a mock's calls, its implementation kept: Jest's `mockClear`. A
 * one-time answer no call took is dropped and reported, as in `resetMock`.
 */
export function clearMock<F extends (...args: never[]) => unknown>(
  fn: Mock<F>,
): void {
  const pending = dropPending(fn);
  fn.mock.resetCalls();
  assert.equal(
    pending,
    0,
    `a clear with ${pending} one-time answer(s) no call took`,
  );
}
