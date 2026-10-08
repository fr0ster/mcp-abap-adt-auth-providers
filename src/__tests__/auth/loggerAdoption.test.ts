/**
 * A logger is the consumer's own code: what its methods answer is adopted
 * like an await would adopt it. A rejecting
 * Promises/A+ thenable, a `then` that throws and a rejecting native promise
 * leave no `unhandledRejection`, change no outcome, and are never awaited.
 * Run under plain node in a child process with an unhandled-rejection
 * recorder (`logQuietly` and `announcer`).
 */

import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { runPlainNode } from '../helpers/plainNode';

const aplus = JSON.stringify(
  join(__dirname, '..', 'helpers', 'aplusPromise.ts'),
);

const SCENARIO = `
const { APlusPromise } = require(${aplus});
const { logQuietly } = load('auth/tokenRequest.js');
const { announcer } = load('auth/announce.js');
const answers = {
  aplus: () => APlusPromise.reject(new Error('async logger failed')),
  throwingThen: () => ({ then() { throw new Error('then threw'); } }),
  native: () => Promise.reject(new Error('async logger failed')),
};
const written = [];
const realWrite = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
const out = {};
for (const [name, answer] of Object.entries(answers)) {
  const logger = { info: () => answer(), debug: () => answer() };
  let logged = 'returned';
  try { logQuietly(() => logger.debug('line')); } catch { logged = 'threw'; }
  announcer(logger)('prompt ' + name);
  out[name] = { logged };
}
for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));
process.stderr.write = realWrite;
out.written = written;
out.thenCalls = APlusPromise.thenCalls;
report(out);
`;

describe('a logger whose methods answer a rejecting thenable', () => {
  it('raises no unhandledRejection and changes no outcome', () => {
    const run = runPlainNode<{
      aplus: { logged: string };
      throwingThen: { logged: string };
      native: { logged: string };
      written: string[];
      thenCalls: number;
    }>(SCENARIO, { boundMs: 60000 });
    expect(run.timedOut).toBe(false);
    expect(run.unhandled).toEqual([]);
    expect(run.result.aplus.logged).toBe('returned');
    expect(run.result.throwingThen.logged).toBe('returned');
    expect(run.result.native.logged).toBe('returned');
    // The Promises/A+ answer was followed, not left alone.
    expect(run.result.thenCalls).toBeGreaterThan(0);
    // The announced prompt reaches stderr once the logger's rejection arrives.
    for (const name of ['aplus', 'throwingThen', 'native']) {
      expect(run.result.written).toContain(`prompt ${name}\n`);
    }
  });
});
