/**
 * The mock browser every test injects (`IBrowser`): it records each
 * `open(url, signal)` and resolves — or rejects, when told to — and never
 * launches anything. No test outside `shippedBrowsers.test.ts` gets a
 * shipped browser (`linuxDefaultBrowser()` …); those are tested only there, at a
 * mocked spawn / `open` boundary with fake executables.
 *
 * `onOpen` plays the user's browser where a test needs one: it runs on each
 * open (visiting the callback, aborting, …) and its answer is awaited.
 */

import type { IBrowser } from '@mcp-abap-adt/interfaces-auth';

export interface BrowserCall {
  readonly url: string;
  readonly signal: AbortSignal;
}

export interface RecordingBrowser extends IBrowser {
  /** Every open, in order. */
  readonly calls: readonly BrowserCall[];
  /** From now on every open rejects with `error` (after `onOpen`, if any). */
  rejectWith(error: unknown): void;
  /** From now on every open resolves again. */
  resolve(): void;
}

export interface RecordingBrowserOptions {
  /** Runs on each open, awaited; a throw or rejection is the open's. */
  readonly onOpen?: ((url: string, signal: AbortSignal) => unknown) | undefined;
  /** Every open rejects with this from the start. */
  readonly rejectWith?: unknown;
}

export function recordingBrowser(
  options: RecordingBrowserOptions = {},
): RecordingBrowser {
  const calls: BrowserCall[] = [];
  let failure: { error: unknown } | undefined =
    'rejectWith' in options ? { error: options.rejectWith } : undefined;
  return {
    calls,
    rejectWith(error: unknown) {
      failure = { error };
    },
    resolve() {
      failure = undefined;
    },
    async open(url: string, signal: AbortSignal): Promise<void> {
      calls.push({ url, signal });
      await options.onOpen?.(url, signal);
      if (failure !== undefined) throw failure.error;
    },
  };
}
