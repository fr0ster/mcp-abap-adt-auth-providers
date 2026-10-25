/**
 * A minimal Promises/A+ implementation, apart from the native `Promise`
 * (no subclass, its own prototype, its own job queue through
 * `queueMicrotask`): the shape of Bluebird, Q or any other promise library a
 * consumer's collaborator may answer with. A collaborator is the consumer's
 * own code, and its answer must work when awaited.
 *
 * `then` calls are counted on the instance's class, so a test can prove the
 * package actually followed the answer.
 */

type Settler = (value: unknown) => void;

type State =
  | { readonly kind: 'pending' }
  | { readonly kind: 'fulfilled'; readonly value: unknown }
  | { readonly kind: 'rejected'; readonly reason: unknown };

export class APlusPromise {
  /** Every `then` call on any instance. */
  static thenCalls = 0;

  #state: State = { kind: 'pending' };
  #queue: Array<() => void> = [];

  constructor(executor: (resolve: Settler, reject: Settler) => void) {
    let done = false;
    const resolve: Settler = (value) => {
      if (done) return;
      done = true;
      this.#resolveWith(value);
    };
    const reject: Settler = (reason) => {
      if (done) return;
      done = true;
      this.#settle({ kind: 'rejected', reason });
    };
    try {
      executor(resolve, reject);
    } catch (error) {
      reject(error);
    }
  }

  static resolve(value: unknown): APlusPromise {
    return new APlusPromise((resolve) => resolve(value));
  }

  static reject(reason: unknown): APlusPromise {
    return new APlusPromise((_resolve, reject) => reject(reason));
  }

  /** An answer that never settles. */
  static never(): APlusPromise {
    return new APlusPromise(() => undefined);
  }

  // biome-ignore lint/suspicious/noThenProperty: a promise library's then is the point
  then(onFulfilled?: unknown, onRejected?: unknown): APlusPromise {
    APlusPromise.thenCalls += 1;
    return new APlusPromise((resolve, reject) => {
      const run = () => {
        const state = this.#state;
        if (state.kind === 'pending') return;
        const handler = state.kind === 'fulfilled' ? onFulfilled : onRejected;
        if (typeof handler !== 'function') {
          if (state.kind === 'fulfilled') resolve(state.value);
          else reject(state.reason);
          return;
        }
        try {
          resolve(
            handler(state.kind === 'fulfilled' ? state.value : state.reason),
          );
        } catch (error) {
          reject(error);
        }
      };
      if (this.#state.kind === 'pending') this.#queue.push(() => run());
      else queueMicrotask(run);
    });
  }

  catch(onRejected?: unknown): APlusPromise {
    return this.then(undefined, onRejected);
  }

  #settle(state: State): void {
    if (this.#state.kind !== 'pending') return;
    this.#state = state;
    const queue = this.#queue;
    this.#queue = [];
    for (const job of queue) queueMicrotask(job);
  }

  /** The Promise Resolution Procedure (Promises/A+ §2.3). */
  #resolveWith(value: unknown): void {
    if (value === this) {
      this.#settle({
        kind: 'rejected',
        reason: new TypeError('a promise resolved with itself'),
      });
      return;
    }
    if (
      (typeof value === 'object' && value !== null) ||
      typeof value === 'function'
    ) {
      let then: unknown;
      try {
        then = (value as { then?: unknown }).then;
      } catch (error) {
        this.#settle({ kind: 'rejected', reason: error });
        return;
      }
      if (typeof then === 'function') {
        let called = false;
        try {
          then.call(
            value,
            (inner: unknown) => {
              if (called) return;
              called = true;
              this.#resolveWith(inner);
            },
            (reason: unknown) => {
              if (called) return;
              called = true;
              this.#settle({ kind: 'rejected', reason });
            },
          );
        } catch (error) {
          if (!called) {
            called = true;
            this.#settle({ kind: 'rejected', reason: error });
          }
        }
        return;
      }
    }
    this.#settle({ kind: 'fulfilled', value });
  }
}
