# Plan: the tests run on node:test

Goal: `2026-11-09-node-test-goal.md`. Spec: `2026-11-09-node-test-spec.md`. One branch,
`refactor/node-test`, one PR (#88). Every step ends with its gate: `npm run build`,
`npm run test:check`, `npm run lint:check` and the full `npm test` of both packages, all
through npm scripts. A step that changes a rule proves it load-bearing (break it, see the
test go red, revert) and reports the mutation as Measured. A step pushes only after its
gate.

## Steps

1. **Measure before anything moves** (spec §2, §5, §6, §9). Scratch measurements, not
   committed, each reported Measured or refuted, on Node 22 (the lowest line CI runs),
   24 and 26:
   - a `mock.method` on the `axios` module object replaces what one `axios.post` site
     and the one `axios(…)` site call, in the compiled CommonJS;
   - a `mock.method` on `oidcToken`'s module object replaces what its importer calls;
   - one `devicePoll` case under `mock.timers` with `tick` proves what it proves under
     `advanceTimersByTimeAsync`;
   - a compiled test that needs no `--experimental-vm-modules` runs;
   - `node --test --require <file>` loads the file in every test file's process.

   Any measurement that fails stops the plan: it goes to the owner with its options.

2. **The runner and the build, in both packages** (spec §2). Each package gains a
   `tsconfig.test.json` (today's strict options, CommonJS, `noEmitOnError`, out to
   `.test-build/`, gitignored) and `tools/run-tests.mjs` after auth-errors'. The runner
   runs one process per file, one file at a time, has no timeout and no `forceExit`, fails
   on an empty run, and runs a named file or directory alone. It takes `--env NAME=VALUE`.
   The scripts `test:build` and `test:file` are added. While Jest still holds files, `npm test` runs both
   runners: node:test over the moved files and Jest over the rest. Jest's
   `testPathIgnorePatterns` in its config names the moved directories; a flag is never
   used, because a flag replaces the configured ignores. Tests: an empty run fails, a
   named missing file fails, `--env` reaches the test.

3. **The child-process guard as a preload** (spec §3). The runner starts every file's
   process with `--require` of the compiled guard. `allowExecutable` keeps its signature.
   Tests: a fixture file run through the runner tries a `spawn` of an unregistered program
   and is refused, and the guard's own `noRealBrowser` tests move. Mutation: the preload
   dropped from the runner turns the fixture red.

4. **auth-spnego-gssapi moves whole** (spec §4, §7). Its four files move, `gssapiTokenSource`'s
   module-registry reset among them. `run-suite.sh` runs the stand directory through
   `test:file`, and `.test-build/` is built inside the container from the git-tracked
   files. Jest leaves this package's manifest and its `jest.config.js`, and npm
   regenerates its lockfile. Gate, plus `npm run test:stand` with the Kerberos stand
   (local Docker).

5. **auth-providers: the files with neither a module mock nor a fake timer** (spec §4).
   They move directory by directory, one commit per directory. Spies become `mock.fn` /
   `mock.method` with their restore in the file's hooks. `.each` tables become loops, and
   `expect` becomes `node:assert/strict`. The rejection convention stays: the
   `assert.rejects` promise is made before the trigger. The `shapeCheck` test moves with
   its gate assertions, and `test:shape` and `docs:tables` run its compiled file.
   `docs:tables` stays refused under `CI`. The module-registry resets (`manualDrain`,
   `manualStrategiesAbort`, `sncRows`) become a fresh process or a fresh module through
   `require.cache`, per file. A test that proves nothing is fixed and listed for the PR.

6. **auth-providers: the module-mock files** (spec §5, decision 1). The 28 `jest.mock`
   calls become `mock.method` on the module object. For each mocked module (`axios`,
   `node:child_process`, `oidcToken`, `oidcDiscovery`, `tokenRefresher`,
   `saml2TokenExchange`), a pin test proves that the mock replaces what production calls.
   Mutation: production reads the module through a destructured import, and the pin goes
   red.

7. **auth-providers: the fake-timer files** (spec §6, decision 2). `attemptSignals`,
   `devicePoll` and `noLoginTimeout` move to `mock.timers`, one file per commit. Any case
   `tick` cannot express stops the step and goes to the owner with its options before it
   is changed.

8. **auth-providers: the live suites** (spec §7). `integration/stand`, `integration/xsuaa`
   and the rest of `integration/` move. `tests/stand/run.sh` and `tests/xsuaa/run.sh` run
   their directory through `test:file`, and keep their skip with a reason, their cleanup
   on failure and their exit status. The interactive gate stays. Gate, plus
   `npm run test:stand` (local Docker). `npm run test:xsuaa` touches a real BTP
   subaccount, so it runs only on the owner's go.

9. **Jest leaves** (spec §8). `npm test` runs node:test alone. `jest`, `ts-jest`,
   `jest-util`, `@jest/globals` and `@types/jest` leave the manifest, and
   `jest.config.js` is deleted. npm regenerates the lockfile. The lockfiles are checked
   for `"link": true` and for anything not from the registry. A sweep test refuses any
   Jest API or import in `src`. `npm run audit` passes on the root and both packages
   (Measured); an advisory left that does not come from the test runner goes to the owner.

10. **CI and the release gates** (spec §8). `ci.yml` keeps its steps on Node 22, 24 and 26.
    `release.yml` and `prepublishOnly` still run `npm run test:shape`, and the root
    `npm run check` passes. CI is green on the PR.

11. **Docs** (spec §8):
    - README and the package docs that name Jest.
    - A CHANGELOG entry per package: a patch, no published contract changes.
    - The new text of `CLAUDE.md`'s Build and Testing sections goes to the owner, and is
      applied only after the text is approved.

12. **Review and the end.**
    - Codex reviews the PR, and every finding goes to the owner.
    - Before the release, the goal, spec and plan are deleted. What they still owe goes
      into the PR description first.
    - Merge, tag and publish happen only on the owner's word. #87 rebases on master
      after this merge, and its CI must pass.
