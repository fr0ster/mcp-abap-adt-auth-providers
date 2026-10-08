/**
 * A stand-in for `node:readline` on a pretend terminal: each interface holds
 * one listener on `process.stdin` (an `end` listener — it does not put stdin
 * into flowing mode) from creation until it is closed, and its close can be
 * held open by a gate, as a slow release would. Lets a test count the
 * readers on stdin and defer a reader's release.
 */

import { EventEmitter } from 'node:events';

export interface FakeReader {
  /** Delivers one line, as a user pressing Enter. */
  type(line: string): void;
  /** Ends the input with no line, as a closed terminal (Ctrl+D) does. */
  end(): void;
  /** Whether `close()` has been called (the release may still be held). */
  readonly closeCalled: boolean;
  /** Whether the reader is closed — its listener gone from stdin. */
  readonly closed: boolean;
}

export interface FakeTerminal {
  /** What `jest.doMock('node:readline', …)` should return. */
  readonly module: { createInterface: () => unknown };
  /** Every reader created, in order. */
  readonly readers: FakeReader[];
  /** stdin's `end` listeners when each reader was created. */
  readonly listenersAtOpen: number[];
  /** While set, a reader's close waits for `releaseClose()`. */
  holdClose: boolean;
  /** Lets every held close complete. */
  releaseClose(): void;
  /** Restores `process.stdin.isTTY`. */
  restore(): void;
}

const noop = () => undefined;

export function fakeTerminal(): FakeTerminal {
  const tty = process.stdin.isTTY;
  Object.defineProperty(process.stdin, 'isTTY', {
    value: true,
    configurable: true,
  });
  const held: Array<() => void> = [];
  const terminal: FakeTerminal = {
    readers: [],
    listenersAtOpen: [],
    holdClose: false,
    releaseClose() {
      for (const done of held.splice(0)) done();
    },
    restore() {
      Object.defineProperty(process.stdin, 'isTTY', {
        value: tty,
        configurable: true,
      });
    },
    module: {
      createInterface: () => {
        terminal.listenersAtOpen.push(process.stdin.listenerCount('end'));
        const rl = new EventEmitter();
        const listener = noop.bind(null);
        process.stdin.on('end', listener);
        const lines: string[] = [];
        let wake: (() => void) | undefined;
        let closeCalled = false;
        let closed = false;
        const finish = () => {
          if (closed) return;
          closed = true;
          process.stdin.off('end', listener);
          wake?.();
          rl.emit('close');
        };
        const reader: FakeReader = {
          type(line) {
            lines.push(line);
            wake?.();
          },
          end() {
            close();
          },
          get closeCalled() {
            return closeCalled;
          },
          get closed() {
            return closed;
          },
        };
        terminal.readers.push(reader);
        function close(): void {
          if (closeCalled) return;
          closeCalled = true;
          wake?.();
          if (terminal.holdClose) held.push(finish);
          else finish();
        }
        return Object.assign(rl, {
          close,
          [Symbol.asyncIterator]() {
            return {
              next: async (): Promise<IteratorResult<string>> => {
                for (;;) {
                  const line = lines.shift();
                  if (line !== undefined) return { value: line, done: false };
                  if (closeCalled) return { value: undefined, done: true };
                  await new Promise<void>((resolve) => {
                    wake = resolve;
                  });
                }
              },
              return: async (): Promise<IteratorResult<string>> => ({
                value: undefined,
                done: true,
              }),
            };
          },
        });
      },
    },
  };
  return terminal;
}
