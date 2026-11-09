/**
 * Jest's fake clock on node:test's `mock.timers` (spec §9, decision 2).
 *
 * `setTimeout`, `setInterval` and `Date` are faked, the clock starting at
 * the real time, as Jest's modern timers did; `setImmediate`,
 * `process.nextTick` and microtasks stay real.
 *
 * node's `tick(ms)` is synchronous: a timer the code under test sets only
 * after a promise chain does not exist yet when `tick` runs, so it does not
 * fire. Jest's `advanceTimersByTimeAsync` let those chains run between
 * timers. The measured pattern (plan step 1, on Node 22, 24 and 26): one real
 * `setImmediate` turn before each `tick`. `advanceTimersByTimeAsync` applies
 * it to every millisecond, so a timer set at any point in the window fires at
 * its time, as under Jest.
 */

import { mock } from 'node:test';

/** One real macrotask turn: every promise chain already queued has settled. */
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

/** Jest's `useFakeTimers()`, with setImmediate, nextTick and microtasks real. */
export function useFakeTimers(): void {
  mock.timers.enable({
    apis: ['setTimeout', 'setInterval', 'Date'],
    now: Date.now(),
  });
}

/** Jest's `useRealTimers()`. */
export function useRealTimers(): void {
  mock.timers.reset();
}

/** Jest's `advanceTimersByTime`: synchronous, firing only the timers already set. */
export function advanceTimersByTime(ms: number): void {
  mock.timers.tick(ms);
}

/**
 * Jest's `advanceTimersByTimeAsync`: `ms` milliseconds, one at a time, each
 * after a real turn, and a turn after the last.
 */
export async function advanceTimersByTimeAsync(ms: number): Promise<void> {
  for (let elapsed = 0; elapsed < ms; elapsed += 1) {
    await turn();
    mock.timers.tick(1);
  }
  await turn();
}
