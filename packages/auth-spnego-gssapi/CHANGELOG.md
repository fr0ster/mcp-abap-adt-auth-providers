# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added
- `gssapiTokenSource({ mechanism })`: an `INegotiateTokenSource` (`@mcp-abap-adt/interfaces-auth`
  ^8.0.1) over the system's GSS-API (SSPI on Windows) through `kerberos` ^7.0.0, loaded on the
  first call. `mechanism` (`'spnego'` | `'kerberos'`) is required; any other option is a
  `RangeError`. Each call builds a new client and takes one token; nothing is kept. Answers a
  token or a problem — `no-credential`, `service-unknown`, `kdc-unreachable`, `clock-skew`,
  `binding-unavailable`, `source-failed`, `mechanism-unsupported` — and no text of the binding's error.
- The identity is the process's default one (the ticket cache, the domain logon); no principal
  option.
