// The arguments the runner gives node — one place, so a test pins them (see
// src/__tests__/runner/runTests.test.ts). Every file runs in a process of its own
// (`node --test`'s process isolation, the default), one file at a time, with no
// timeout: a file ends on its result. The guard is loaded first in every file's
// process, and every process may mock a module.
export function nodeTestArguments({ guard, options, files }) {
  return [
    '--experimental-test-module-mocks',
    '--require',
    guard,
    '--test',
    '--test-concurrency=1',
    ...options,
    ...files,
  ];
}
