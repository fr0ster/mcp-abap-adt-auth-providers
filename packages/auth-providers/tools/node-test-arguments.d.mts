/** The arguments `tools/run-tests.mjs` gives `node`, in order. */
export function nodeTestArguments(run: {
  readonly guard: string;
  readonly options: readonly string[];
  readonly files: readonly string[];
}): string[];
