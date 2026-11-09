# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-09

The tests run on Node's own runner, `node:test`, with `node:assert/strict`. No published contract
changes: the package's code, its exports and its runtime dependencies are as in 0.1.0.

### Changed
- Tests: `npm test` compiles them with the package's own `tsc` (`tsconfig.test.json`, into
  `.test-build/`) and runs every compiled file in a process of its own, one at a time, with no
  timeout, through `tools/run-tests.mjs`; `npm run test:file -- <compiled path>` runs a file or a
  directory. The Kerberos stand's suite runs through `test:file` inside its container.

### Removed
- `jest`, `ts-jest`, `jest-util`, `@jest/globals` and `@types/jest` from devDependencies, and
  `jest.config.js`.

## [0.1.0] - 2026-10-26

### Added
- `gssapiTokenSource({ mechanism })`: an `INegotiateTokenSource` (`@mcp-abap-adt/interfaces-auth`
  ^8.0.1) over the system's GSS-API (SSPI on Windows) through `kerberos` ^7.0.0, loaded on the
  first call. `mechanism` (`'spnego'` | `'kerberos'`) is required; any other option is a
  `RangeError`. Each call builds a new client and takes one token; nothing is kept. Answers a
  token or a problem — `no-credential`, `service-unknown`, `kdc-unreachable`, `clock-skew`,
  `binding-unavailable`, `source-failed`, `mechanism-unsupported` — and no text of the binding's error.
- Measured on a Windows x64 GitHub runner with no domain (2026-10-25): `kerberos` raises
  `InitializeSecurityContext: No credentials are available in the security package` (`no-credential`);
  `spnego` returns a token whose bytes are an NTLM NEGOTIATE message (type 1), not an error (that
  this is SSPI's fallback is Inference).
- The identity is the process's default one (the ticket cache, the domain logon); no principal
  option.
- The binding's texts for an unknown service and an unreachable KDC are measured on MIT krb5
  1.20.1 against a real KDC (auth-providers' Kerberos stand): MIT names the principal inside the
  unknown-service text, so it is read only as the end of the message — the fixed text, a name
  with no space or quote, the fixed tail; an unknown client is not `service-unknown`, whatever its
  name holds.
