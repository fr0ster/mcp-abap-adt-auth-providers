# @mcp-abap-adt/auth-spnego-gssapi

A negotiate token source for `SpnegoAuthProvider` of
[`@mcp-abap-adt/auth-providers`](https://www.npmjs.com/package/@mcp-abap-adt/auth-providers):
SPNEGO or Kerberos tokens from the operating system's GSS-API — MIT Kerberos or Heimdal on Linux
and macOS, SSPI on Windows — through the [`kerberos`](https://www.npmjs.com/package/kerberos)
native binding.

It implements `INegotiateTokenSource` of `@mcp-abap-adt/interfaces-auth` and depends on nothing
else. It mints no error: it answers a token or a problem from a closed list, and the provider
turns the problem into its refusal. Neither package depends on the other — the consumer composes
them.

```ts
import { SpnegoAuthProvider } from '@mcp-abap-adt/auth-providers';
import { gssapiTokenSource } from '@mcp-abap-adt/auth-spnego-gssapi';

const provider = new SpnegoAuthProvider({
  servicePrincipal: 'HTTP@sap.example.com',
  tokenSource: gssapiTokenSource({ mechanism: 'spnego' }),
});
```

## Install

The package itself is plain JavaScript. Its dependency `kerberos` is a native addon, built on the
consumer's machine by its install script — so the consumer's install must allow that one script.

What the build needs, per platform:

| Platform | Install before the build |
|---|---|
| Linux (x64) | the Kerberos headers and a C++ toolchain: `libkrb5-dev` (Debian, Ubuntu) or `krb5-devel` (RHEL, Fedora), with `python3`, `make` and `g++`. The binding opens `libgssapi_krb5.so.2` at run time |
| macOS | the Xcode Command Line Tools (`xcode-select --install`); the system's Kerberos is used |
| Windows (x64) | Visual Studio Build Tools with the C++ workload, and Python; SSPI is part of Windows |

Windows on arm64 is not supported.

### Allowing the binding's install script

npm 11 records which dependencies may run install scripts in `allowScripts` of the consumer's
`package.json`. Allow `kerberos` alone — npm writes the entry pinned to the version you reviewed:

```bash
npm approve-scripts kerberos
```

```json
{
  "allowScripts": {
    "kerberos@7.0.0": true
  }
}
```

`kerberos`'s install script tries a prebuilt binary first (`prebuild-install`) and builds with
`node-gyp` otherwise. To build from source with nothing downloaded, install with scripts off and
rebuild that one package:

```bash
npm ci --ignore-scripts
npm rebuild kerberos --build-from-source
```

A consumer that installs with `--ignore-scripts` and never builds the binding still gets a working
source: every `token()` answers `binding-unavailable`, which the provider refuses as such.

## `gssapiTokenSource({ mechanism })`

`mechanism` is **required**, with no default — which one a service accepts is the service's:

| `mechanism` | Token | Binding |
|---|---|---|
| `'spnego'` | an SPNEGO token, the mechanism RFC 4559's `Negotiate` names | `GSS_MECH_OID_SPNEGO` |
| `'kerberos'` | a bare Kerberos token, for a service that takes one | `GSS_MECH_OID_KRB5` |

A missing or other `mechanism`, or any other option, is a `RangeError` naming the option (never
its value), thrown by the factory — a programming error at composition, before any request.

Each `token(servicePrincipal, { signal })` call:

- loads `kerberos` on the first call (a dynamic import), keeping the loaded module; a failed load
  is tried again on the next call;
- builds a **new** client for the service principal, takes its first token (`step('')`) and keeps
  nothing — a fresh token for every request, as the contract requires;
- hands the binding the service principal in its own form: the GSS host-based name
  `service@host` as it is on Linux and macOS, `service/host` (an SPN) for SSPI on Windows.

The binding cannot be cancelled. An aborted `signal` is checked before the call — the binding is
not called — and again when it returns, the token then dropped; either answers `source-failed`.

### Answers

`{ ok: true, token }`, the token as it goes after `Negotiate `, or `{ ok: false, problem }`:

| Problem | When |
|---|---|
| `no-credential` | no ticket, or an expired one |
| `service-unknown` | the KDC does not know the service principal |
| `kdc-unreachable` | no KDC answered, or none is known for the realm |
| `clock-skew` | the clock differs from the KDC's beyond its tolerance |
| `mechanism-unsupported` | the mechanism asked for is not supported where it ran (measured: macOS's GSS.framework answering `spnego` with no ticket) |
| `binding-unavailable` | `kerberos` could not be loaded (not built, or the system's Kerberos library missing) |
| `source-failed` | anything else, an aborted signal included |

The binding's error carries no status code, only text: the source reads it for fixed phrases of
the Kerberos libraries' error tables (plain substring search, case-sensitive) and returns only the
problem. Nothing of the text — which may name the ticket cache, the user or the realm — reaches
an answer. Measured (2026-10-25, MIT krb5 1.20.1): no ticket, an unknown service and an
unreachable KDC on MIT — the last two against a real KDC on auth-providers' Kerberos stand
(`tests/stand/kerberos`, whose suite is this package's `src/__tests__/stand/spnego.test.ts`) —
and no ticket on macOS. The others — an expired ticket, clock skew, Heimdal's and SSPI's texts
beyond no ticket — are taken from the libraries' error tables and are Pending. Windows' SSPI
texts are localised, so on a Windows that does not speak English, a failure other than an
unloadable binding may answer `source-failed`.

Received on the Kerberos stand (measured 2026-10-25, MIT krb5 1.20.1, `kerberos` 7.0.0; the
same text for `spnego` and `kerberos`):

| Case | Text the binding raised | Answer |
|---|---|---|
| a service the KDC does not know | `Unspecified GSS failure. … : Server HTTP/<host>@<REALM> not found in Kerberos database` | `service-unknown` |
| a TGT in the cache, no KDC answering | `Unspecified GSS failure. … : Cannot contact any KDC for realm '<REALM>'` | `kdc-unreachable` |

The first names the principal between two fixed texts, so the source reads it only as the end of
the message: `Minor code may provide more information: Server `, a name with no space and no quote,
then ` not found in Kerberos database`. An unknown *client* (`Client '…' not found in Kerberos
database`) is not `service-unknown`, whatever its name holds.

Received with no ticket (measured 2026-10-25), and what the source answers:

| System | `mechanism` | Text the binding raised | Answer |
|---|---|---|---|
| Linux, MIT krb5 1.20.1 (Debian bookworm, Docker) | `spnego` | `No credentials were supplied, … : SPNEGO cannot find mechanisms to negotiate` | `no-credential` |
| Linux, MIT krb5 1.20.1 (Debian bookworm, Docker) | `kerberos` | `No credentials were supplied, … : No Kerberos credentials available (default cache: …)` | `no-credential` |
| macOS arm64 (GitHub runner), GSS.framework (Heimdal) | `kerberos` | ` Miscellaneous failure (see text): get-pricipal open(<cache file>): No such file or directory` | `no-credential` |
| macOS arm64 (GitHub runner), GSS.framework (Heimdal) | `spnego` | ` An unsupported mechanism was requested: unknown mech-code 0 for mech unknown` | `mechanism-unsupported` |

On macOS the source matches the texts received in that condition: `get-pricipal open(` (Heimdal's
spelling) as `no-credential`, and `unknown mech-code 0 for mech unknown` as `mechanism-unsupported`.

## Whose identity

The token is for the **default identity of the process**: on Linux and macOS the default
principal of the ticket cache (`KRB5CCNAME`, else the system's default cache — `kinit` fills it),
on Windows the logged-on domain user. The binding takes no cache name, and this package never
writes the environment; to use another cache, start the process with `KRB5CCNAME` set.

**There is no principal option.** The binding's Windows (SSPI) path ignores a client principal
and always uses the logon credentials, so the option would select an identity on Linux and macOS
and silently not on Windows. A consumer needing another identity supplies its own
`INegotiateTokenSource`.

## License

LGPL-3.0-only — see `LICENSE` and `COPYING`.
