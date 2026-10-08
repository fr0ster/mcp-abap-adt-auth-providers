/**
 * Fake parts for the composer's tests: a transport whose arrivals the test
 * drives (it calls the judge itself and decides when `answer()` settles),
 * a transport wrapper whose release a test holds, and a recording
 * presentation.
 */

import type {
  AnswerJudge,
  AnswerTransportOptions,
  AnswerVerdict,
  AuthorizationAnswer,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationPresentation,
  InteractiveLoginStrategy,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import { type Deferred, deferred } from './attemptHarness';

/** One open of a scripted transport. */
export interface ScriptedOpen {
  readonly options: AnswerTransportOptions;
  /** The judge it was armed with, once armed. */
  judge: AnswerJudge<unknown> | undefined;
  /** What `answer()` returns. */
  readonly answer: Deferred<unknown>;
  /** Judges one arrival, as a transport would. */
  deliver(answer: AuthorizationAnswer): AnswerVerdict<unknown>;
  /** Resolves once this open has settled (released). */
  readonly released: Promise<void>;
}

export interface ScriptedTransport {
  readonly transport: IAnswerTransport;
  readonly opens: ScriptedOpen[];
  /** Resolves with the n-th open (1-based) once it is armed. */
  armed(n: number): Promise<ScriptedOpen>;
}

/**
 * A transport whose channel advertises `redirectUri`, whose `answer()` is
 * the test's to settle, and whose `open` settles at the signal (it holds
 * nothing) or when `use` settles.
 */
export function scriptedTransport(
  options: {
    readonly redirectUri?: string | undefined;
    readonly label?: InteractiveLoginStrategy;
    readonly events?: string[];
  } = {},
): ScriptedTransport {
  const opens: ScriptedOpen[] = [];
  const waiters: Array<{ n: number; resolve: (o: ScriptedOpen) => void }> =
    [];
  const notify = () => {
    for (const waiter of [...waiters]) {
      const open = opens[waiter.n - 1];
      if (open?.judge !== undefined) {
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.resolve(open);
      }
    }
  };
  const transport: IAnswerTransport = {
    label: options.label ?? 'consumer',
    async open<TReturn>(
      openOptions: AnswerTransportOptions,
      use: (channel: IAnswerChannel) => Promise<TReturn>,
    ): Promise<TReturn> {
      options.events?.push('open');
      const answer = deferred<unknown>();
      void answer.promise.catch(() => undefined);
      const released = deferred<void>();
      const open: ScriptedOpen = {
        options: openOptions,
        judge: undefined,
        answer,
        deliver(arrival) {
          if (open.judge === undefined) throw new Error('not armed');
          return open.judge(arrival) as AnswerVerdict<unknown>;
        },
        released: released.promise,
      };
      opens.push(open);
      const channel: IAnswerChannel = {
        redirectUri: options.redirectUri,
        arm(judge) {
          options.events?.push('arm');
          open.judge = judge;
          notify();
          return {
            answer: () => answer.promise as unknown as Promise<void>,
          };
        },
      };
      const signal = openOptions.signal;
      try {
        return await new Promise<TReturn>((resolve, reject) => {
          const onAbort = () => reject(new Error('scripted transport aborted'));
          if (signal.aborted) onAbort();
          signal.addEventListener('abort', onAbort, { once: true });
          use(channel).then(resolve, reject);
        });
      } finally {
        options.events?.push('released');
        released.resolve();
      }
    },
  };
  return {
    transport,
    opens,
    armed: (n) =>
      new Promise<ScriptedOpen>((resolve) => {
        waiters.push({ n, resolve });
        notify();
      }),
  };
}

/**
 * Wraps `inner` so that each `open` settles only once the test opens its
 * gate: the release a test holds (the drain's test hook). Counts opens.
 */
export function heldRelease(inner: IAnswerTransport): {
  readonly transport: IAnswerTransport;
  readonly gates: Deferred<void>[];
  readonly opened: () => number;
  /** Resolves once the n-th open's inner open has settled. */
  innerSettled(n: number): Promise<void>;
} {
  const gates: Deferred<void>[] = [];
  const settled: Deferred<void>[] = [];
  const at = (list: Deferred<void>[], n: number) => {
    while (list.length < n) list.push(deferred<void>());
    return list[n - 1] as Deferred<void>;
  };
  let opened = 0;
  const transport: IAnswerTransport = {
    label: inner.label,
    async open<TReturn>(
      openOptions: AnswerTransportOptions,
      use: (channel: IAnswerChannel) => Promise<TReturn>,
    ): Promise<TReturn> {
      opened += 1;
      const n = opened;
      const gate = at(gates, n);
      try {
        return await inner.open(openOptions, use);
      } finally {
        at(settled, n).resolve();
        await gate.promise;
      }
    },
  };
  return {
    transport,
    gates: new Proxy(gates, {
      get: (target, key) =>
        typeof key === 'string' && /^\d+$/.test(key)
          ? at(target, Number(key) + 1)
          : Reflect.get(target, key),
    }),
    opened: () => opened,
    innerSettled: (n) => at(settled, n).promise,
  };
}

/** A presentation that records each call; `run` decides what it answers. */
export function recordingPresentation(
  run: (url: string, context: PresentationContext) => unknown = () =>
    undefined,
  events?: string[],
): {
  readonly presentation: IAuthorizationPresentation;
  readonly calls: Array<{ url: string; context: PresentationContext }>;
} {
  const calls: Array<{ url: string; context: PresentationContext }> = [];
  return {
    presentation: {
      present(url, context) {
        events?.push('present');
        calls.push({ url, context });
        return run(url, context);
      },
    },
    calls,
  };
}
