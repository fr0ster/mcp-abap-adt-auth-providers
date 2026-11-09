# Spec: the tests run on node:test

The goal is `2026-11-09-node-test-goal.md`; it binds this spec. Every fact below is tagged
**Measured** (run here), **Code** (read in this repository or a named one) or **Inference**.
Decisions the owner has not yet taken are in §9, each with options and a recommendation.

## 1. Where the repository stands

- **Two packages, both on Jest 30 with ts-jest** (Code: `packages/*/jest.config.js`).
  `auth-providers`: 136 test files, `setupFiles` the child-process guard
  (`src/__tests__/helpers/noRealBrowser.ts`), `maxWorkers: 1`, `forceExit: true`, and
  `npm test` sets `NODE_OPTIONS=--experimental-vm-modules`. `auth-spnego-gssapi`: 4 files,
  no setup file. The tsconfig of both is `module: CommonJS`, `target: es2022`.
- **Today's run** (Measured, 2026-11-09, a fresh worktree without test configuration or
  stand variables): `auth-providers` 5504 passed, 55 skipped, 136 suites (8 skipped);
  `auth-spnego-gssapi` 76 passed, 20 skipped, 4 suites (2 skipped). The skipped suites are
  the live ones, skipping with their reason.
- **The audit** (Measured, CI run 42512698615): `npm run audit` fails in the packages on
  `deepmerge` (through `jest-config`), `glob` and `minimatch` (through `@jest/reporters`,
  `jest-runtime`, `babel-plugin-istanbul`). The root audit is clean. Every path in the log
  runs through Jest.
- **The Jest API in use** (Code, counts over `src` of `auth-providers`; `auth-spnego-gssapi`
  in parentheses):
  - module mocks `jest.mock`: 28 (0) — `axios` 19, `node:child_process` 3,
    `../../auth/oidcToken` 2, `../../auth/oidcDiscovery` 2, `../../auth/tokenRefresher` 1,
    `../../auth/saml2TokenExchange` 1;
  - `jest.fn` 109 (1), `jest.spyOn` 28 (0), `toHaveBeenCalled…` 165 (11);
  - fake timers in 3 files (`auth/attemptSignals`, `auth/devicePoll`,
    `strategies/noLoginTimeout`): `advanceTimersByTimeAsync` 10, `advanceTimersByTime` 3;
  - `it.each` 251 (10), `describe.each` 41 (1), `.rejects` 40, `expect.objectContaining` 8;
  - module-registry resets: `jest.isolateModules` / `jest.resetModules` in
    `strategies/manualDrain`, `strategies/manualStrategiesAbort`, `snc/sncRows`
    (`gssapiTokenSource` in the other package); no snapshots.
- **Where the runs are started** (Code): the root `npm test` (`tools/each-package.js`),
  CI (`ci.yml`, two `npm test` steps), `tests/stand/run.sh`
  (`npm test -- src/__tests__/integration/stand`), `tests/xsuaa/run.sh`
  (`npm test -- src/__tests__/integration/xsuaa`), the Kerberos client container
  (`tests/stand/kerberos/client/run-suite.sh`: `npm test -- src/__tests__/stand` in
  `auth-spnego-gssapi`), `test:shape` and `docs:tables`, and `prepublishOnly` through
  `test:shape`.
- **The model already proven elsewhere** (Code, `mcp-abap-adt-auth-errors` after #12):
  `tsc -p tsconfig.test.json` compiles the tests to `.test-build/`; `tools/run-tests.mjs`
  runs `node --test` over the compiled `*.test.js`, fails when it finds none, takes
  `--env NAME=VALUE` instead of a shell prefix, and passes the other options to
  `node --test`.

## 2. The build and the runner

- **Each package compiles its tests with its own `tsc`** into `.test-build/`
  (`tsconfig.test.json`: the strict options of today's `tsconfig.json`, CommonJS,
  `noEmitOnError`), removed before each build, gitignored. `test:check` stays the type
  check of the whole of `src`, tests included.
- **`tools/run-tests.mjs` per package, after auth-errors'.** It runs every compiled
  `*.test.js` with `node --test`, one process per file (`node --test`'s own isolation),
  `--test-concurrency=1` as today's `maxWorkers: 1`, no `--test-timeout`, no
  `forceExit`. A file named on the command line runs alone and must exist; a run that
  finds no file fails. `--env NAME=VALUE` sets a variable for the run.
- **A file that leaves a handle open does not pass by being cut.** Without `forceExit`, a
  file whose process does not end is a hang, and the hang is the test's defect, found and
  fixed in the move (goal: a test ends on its result). Today's `forceExit: true` hides
  which files those are (Inference: the run above printed Jest's "Force exiting" line).
- **`--experimental-vm-modules` goes.** It has been in the script since the package's first
  commit (Code, `git log -S`) and nothing compiled to CommonJS needs it (Inference; the
  plan's first step measures it).
- **Scripts.** `test` builds and runs; `test:file` runs named files; `test:shape` runs the
  compiled `shapeCheck.test.js` alone; `docs:tables` is that test run with
  `--env WRITE_README_TABLES=1`, still refused under `CI`. `prepublishOnly` and the release
  workflow keep naming `npm run test:shape`. The root scripts are unchanged.

## 3. The child-process guard

- **The guard runs in every test process before any test module loads.** It moves from
  Jest's `setupFiles` to a module each test file process loads first: `node --test
  --require <compiled guard>` from the runner (`--require` applies to every file's
  process). It denies the same entry points with the same exceptions; `allowExecutable`
  keeps its signature.
- **A test proves the guard is in every process**: a fixture file run through the runner
  tries a `spawn` of an unregistered program and is refused, and every file's process is
  started with the preload (the runner is the only way a test file runs). The guard's own
  tests (`noRealBrowser.test.ts`) move as they are.
- **`process.execPath` stays the one hole**, confined as today (the browser child gets a
  `PATH` of fakes only).

## 4. Moving a test

- `describe` / `it` / hooks from `node:test`; `expect` becomes `node:assert/strict`
  (`assert.equal`, `deepEqual`, `match`, `throws`, `rejects`); `.each` tables become loops
  calling `it`; `expect.objectContaining` becomes an assertion over the fields named.
- `jest.fn` / `jest.spyOn` become `mock.fn` / `mock.method`, restored in the file's hooks;
  `toHaveBeenCalled…` read `mock.calls`.
- "Attach a rejection expectation before triggering it" stays the convention: the
  `assert.rejects(p, …)` promise is created before the trigger and awaited after.
- A module-registry reset (`jest.isolateModules` / `resetModules`) becomes a fresh process
  (the file is already its own) or a fresh module instance through `require.cache`,
  whichever the test needs (plan, per file).
- A moved test asserts what it asserted before. One that turns out to prove nothing is
  fixed and named in the PR.

## 5. Module mocks

No `jest.mock` survives. What replaces each depends on §9 question 1. The facts:

- Production code reaches axios as a property of the module object at every call
  (`axios.post`, `axios.get`, `axios(…)` compiled to `(0, axios_1.default)(…)`), and the
  four internal modules are reached the same way (`oidcToken_1.fn(…)`) (Code: CommonJS
  emit of `tsc`). A `mock.method` on that module object therefore replaces what production
  calls, with no production change (Inference; the plan's first step measures it on one
  axios site and one internal module).
- `node:test`'s `mock.module` needs `--experimental-test-module-mocks` and is experimental
  on every supported Node line (Inference).
- Several suites already prove the wire on a real socket (`refreshAfterDispatch`,
  `tokenRequestRedirect`, `basicCredentialEcho`) (Code).

## 6. Fake timers

Three files use Jest's fake timers, ten of their calls `advanceTimersByTimeAsync`
(Code). `node:test`'s `mock.timers` advances with `tick(ms)`, synchronously; whether a
promise chain between timers settles as it does under `advanceTimersByTimeAsync` is
unproven (Inference). See §9 question 2.

## 7. The live runs

- The stand suites, the XSUAA suites and the Kerberos suite run through the same runner,
  by directory: `run.sh` and `run-suite.sh` call `npm run test:file -- <dir>` (the runner
  takes a directory under `.test-build/` too), and keep their skip-with-reason, their
  cleanup on failure and their exit status.
- The Kerberos container keeps running over the git-tracked files only; `.test-build/` is
  built inside it, as `dist/` is today.
- The interactive cases keep their gate (`interactive_login: true` or
  `MCP_ABAP_ADT_INTERACTIVE=1`) and pass no browser.

## 8. Dependencies, CI, docs

- Removed from both manifests: `jest`, `ts-jest`, `jest-util`, `@jest/globals`,
  `@types/jest`; `jest.config.js` deleted. Nothing is added. The lockfiles are regenerated
  by npm; none holds `"link": true`.
- `npm run audit` passes on the root and both packages (Measured at the end; if an
  advisory remains that does not come from the test runner, it is reported to the owner,
  not silenced).
- CI keeps its steps; its `npm test` runs the new runner. The Node versions are those of
  `engines` (`^22 || ^24 || ^26`); a `node:test` feature the plan uses must exist on the
  lowest 22 the CI runs (Measured in CI).
- README, CHANGELOG (a new entry for each package, a patch: no published contract
  changes), the package docs that name Jest. `CLAUDE.md`'s Testing and Build sections
  name Jest throughout; their new text goes to the owner for approval before it is applied.

## 9. Questions for the owner

1. **What replaces a module mock?**
   - **(a) `mock.method` on the module object (recommended).** No production change, no
     experimental flag; the same mock lifecycle as the spies. Con: it depends on the
     CommonJS emit reading the property at each call — the plan measures it first, and
     a test pins it for each mocked module.
   - (b) `mock.module` with `--experimental-test-module-mocks`. Closest to today's tests.
     Con: an experimental flag in every run, on three Node lines.
   - (c) An injection point in production code (an HTTP client seam). Con: changes the
     package's code and possibly its contract, outside the goal unless you add it.
2. **What replaces Jest's fake timers in the three files?**
   - **(a) `mock.timers` where it proves the same thing, measured per file (recommended)**;
     a case `tick` cannot express is reported to you with its options before it is
     changed.
   - (b) Rewrite the three files on real timers with short real delays. Con: slower, and a
     delay is a timing assumption the goal's "a test ends on its result" dislikes.
