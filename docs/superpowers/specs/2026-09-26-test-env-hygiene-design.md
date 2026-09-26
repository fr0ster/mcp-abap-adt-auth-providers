# Test environment hygiene

**Status:** draft for the owner's approval. The plan follows it as a
separate step.

## Goal

The test environment and the published package carry no junk:

- the development tree resolves one `interfaces-auth`;
- the tarball carries no test code;
- no test opens a browser unless the owner asked for one.

The live authorization tests take their tokens from a session file the owner
chooses.

There are no public API changes and no behaviour changes in anything
published, apart from which files the tarball contains. Release: a patch,
**4.1.1**.

## What changes

### 1. `auth-stores` ^1.2.1 (done in this branch)

`auth-stores` 1.2.1 depends on `interfaces-auth` ^2.0.1, so the development
tree drops its nested `interfaces-auth` 1.2.0. `dotenv` moves from 17 to 18
with it; it is dev-only and transitive.

### 2. The tarball carries no test code

`tsconfig.json` compiles all of `src/` except `*.test.ts`, so non-test files
under `src/__tests__/` are built into `dist/__tests__/`, and 4.0.0 and 4.1.0
published them. The affected files are `helpers/*` and
`integration/stand/formLogin.ts`.

- The build uses a `tsconfig.build.json` that extends `tsconfig.json` and
  excludes `src/__tests__/**`.
- `npm run test:check` keeps type-checking everything, tests included, through
  `tsconfig.json`.
- A test pins both sides:
  - `package.json`'s `build` script uses `tsconfig.build.json`;
  - that file excludes `src/__tests__`.
- The release step checks `npm pack --dry-run` for zero `dist/__tests__`
  entries.

### 3. Live authorization tests use a session file and never open a browser by default

**Today.** With `tests/test-config.yaml` present,
`src/__tests__/providers/AuthorizationCodeProvider.test.ts` deliberately
starts from an empty temporary session. It then logs in through the **system
browser**, and the run waits for a human. It is not under `integration/`, so
the owner has to be warned before any test run in the main checkout.

**From now on:**

- **The session file is configurable: any file, with a standard default.**
  The test resolves one file, and the first rule that applies wins:
  1. **`MCP_ABAP_ADT_SESSION_FILE`**, if set, for a single run.
  2. **`session_path`** in `test-config.yaml`, if set. It may be absolute, may
     start with `~` (expanded to the home directory), or may be relative to the
     project root. Today the helper resolves it only relative to the project
     root; this spec widens it.
  3. **The standard folder the stores use**:
     `<destination_dir>/sessions/<destination>.env`. `destination_dir` defaults
     per platform, as the helper already does: `~/.config/mcp-abap-adt` on
     Unix, `<home>/Documents/mcp-abap-adt` on Windows.

  The resolved file needs no particular name or folder. The test copies it
  into its temporary sessions directory as `<destination>.env`, which is the
  name `AbapSessionStore` reads.
- **Token scenarios run from the file.** The test copies the chosen session
  into a temporary sessions directory, so the owner's file is never written or
  deleted. It then runs, without a browser:
  - reuse of a still-valid token;
  - refresh through the session's refresh token.

  If the file does not exist or holds no usable token, these cases skip with a
  message naming the path they looked at.
- **Browser scenarios are opt-in.** Scenario 1 (service key only → browser
  login) and every other case that launches a browser run only when
  `test-config.yaml` has `interactive_login: true`, or when
  `MCP_ABAP_ADT_INTERACTIVE=1` is set. Otherwise they skip with a message that
  says how to enable them. The same gate applies to
  `src/__tests__/auth/browserAuth.integration.test.ts` if it launches a
  browser.
- **Never print a token.** No log line, assertion message or skip message
  carries a token or a secret value, only paths and key names.
- **Documentation.** `tests/test-config.yaml.template` documents
  `session_path`, the platform default, `MCP_ABAP_ADT_SESSION_FILE`,
  `interactive_login` and `MCP_ABAP_ADT_INTERACTIVE`. `CLAUDE.md` "Testing"
  says a default test run opens no browser.

## Constraints

- Nothing is published but the package. The tarball changes only by losing
  `dist/__tests__`.
- The owner's session files are read-only to the tests.
- Every new rule gets a test that goes red when the rule is removed: the build
  config exclusion, and the browser gate. The browser gate is proved by
  showing the browser case skips without the flag, with a unit-level check on
  the gate function.
- The file-resolution order has its own unit test, one case per rule and one
  per path form (absolute, `~`, relative), plus the Windows default. The rules
  are the environment variable over `session_path` over the standard folder.
  The resolver takes the platform and environment as arguments, so the Windows
  case runs on Linux.
- No secrets in output.

## Out of scope

- Changing the providers.
- Changing how `auth-broker` or `auth-stores` store sessions.
- Recreating the missing `trial.env`. That file is the owner's; this spec
  only makes the path configurable.
