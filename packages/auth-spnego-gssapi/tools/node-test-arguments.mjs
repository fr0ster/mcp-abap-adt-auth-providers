// The arguments the runner gives node — one place, so a test pins them (see
// src/__tests__/runner/runTests.test.ts). Every file runs in a process of its own
// (`node --test`'s process isolation, the default), one file at a time, with no
// timeout: a file ends on its result. Every process may mock a module, as in
// `@mcp-abap-adt/auth-providers`.
export function nodeTestArguments({ options, files }) {
  return [
    '--experimental-test-module-mocks',
    '--test',
    '--test-concurrency=1',
    ...options,
    ...files,
  ];
}
