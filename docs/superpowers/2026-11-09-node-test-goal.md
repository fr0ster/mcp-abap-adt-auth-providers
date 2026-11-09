# Goal: the tests run on node:test

## Goal

The tests of both packages, `packages/auth-providers` and `packages/auth-spnego-gssapi`,
run on Node's own test runner, `node:test`, with `node:assert/strict`. Jest is gone: no
`jest`, `ts-jest`, `jest-util`, `@jest/globals` or `@types/jest` in any manifest, no Jest
configuration, no Jest API in a test. The repository's audit (`npm run audit`, development
dependencies included) is no longer held red by the test runner's dependencies. A failure
in a run is a failure of a provider or of the test, never of the runner holding them.

## Invariants

- **A file is its own process.** Every test file runs in a process of its own; no heap,
  module registry, global or open handle is shared between files.
- **A test ends on its result.** No runner-chosen timeout cuts a test or a hook. A test
  ends when its work settles, or when an `AbortSignal` it was given aborts and its work ends
  on that.
- **Cleanup runs to its end.** A cleanup starts only after the body it cleans up after has
  settled, and nothing ends a file's process while a cleanup runs.
- **No test starts a real program.** Every `child_process` entry point stays denied by
  default in every test process, with the same exceptions as today: node itself and an
  exact path a test registered. A child node process that launches stays confined to its
  own fake programs. The guard is as strong in every file as it is today, and nothing lifts
  it.
- **The live guarantees stay whole.** A test that needs a stand, a real BTP subaccount, a
  test configuration or an interactive user keeps stating where it runs and skipping with
  the reason elsewhere. The provider stand, the Kerberos stand (inside its container, over
  the git-tracked files only) and the live XSUAA checks keep running what they run today,
  and their cleanup keeps running on failure.
- **The release gates stay whole.** The shape check stays a test that fails on any finding
  and still blocks a publish (`prepublishOnly`, the release workflow). The README refusal
  tables stay checked by a test, and are written only outside CI.
- **A unit test needs no outside service.** The unit run (`npm test`) reaches no network
  service and no local daemon. A test that needs one runs in a run of its own, which states
  where it runs.
- **npm scripts only.** Every run is an npm script that works the same on every supported
  platform and Node version. No shell prefix, no global tool.
- **Dependencies from the registry, nothing new at run time.** No new runtime dependency.
  Nothing in the test tooling is linked or installed from anywhere but the npm registry.
- **Static first.** A moved test is type-checked as strictly as today, by the repository's
  own `tsc`. It is compiled by `tsc`, not by Node's type stripping.

## Out of scope

- Changing what any test proves. A moved test asserts what it asserted before, unless
  the move exposes a test that proves nothing, which is then fixed and named.
- Changing a provider's behaviour, the packages' published contracts or their runtime
  dependencies. An injection point a test needs in production code goes to the owner
  before it is added.
- Code coverage measurement.
- The other repositories' moves.
