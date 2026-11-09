/**
 * Watching `process.stdout` in a test. Under node:test a test file's process
 * reports to the runner over its own stdout, in frames of the V8 serializer
 * (each opens with its header, `0xFF 0x0F`, a four-byte length, then the
 * serialized message's own header): a test that replaced
 * `process.stdout.write` outright would swallow the report of a test — and
 * see it as a write. These frames go on to the real stream; anything else is
 * what the code under test wrote, handed to the test and never written.
 */

import { mock } from 'node:test';

/** Whether a chunk is one of node:test's report frames (measured on Node 22, 24, 26). */
function isRunnerFrame(chunk: unknown): boolean {
  return (
    chunk instanceof Uint8Array &&
    chunk.length >= 8 &&
    chunk[0] === 0xff &&
    chunk[1] === 0x0f &&
    chunk[6] === 0xff &&
    chunk[7] === 0x0f
  );
}

/**
 * Replaces `process.stdout.write` until `mock.restoreAll()` (or the returned
 * mock's restore): the runner's frames pass through, every other chunk goes
 * to `onWrite` as text and is not written.
 */
export function watchStdout(onWrite: (text: string) => void) {
  const stdout = process.stdout;
  const real = stdout.write;
  return mock.method(stdout, 'write', (...args: unknown[]): boolean => {
    const [chunk] = args;
    if (isRunnerFrame(chunk)) return Reflect.apply(real, stdout, args);
    onWrite(
      chunk instanceof Uint8Array
        ? Buffer.from(chunk).toString('utf8')
        : String(chunk),
    );
    return true;
  });
}
