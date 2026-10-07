# Authorization strategies by composition — goal

Part of auth-providers 6.0.0. The error contract's goal and the renewal
goal bind everything else. The spec and the plan answer this file; if either
needs to depart from anything under *Holds throughout*, this file changes
first.

## Goal

Everything between "the provider has built an authorization URL" and "the
provider has the payload it exchanges for a secret" is composed from three
independent parts, each a strategy the consumer may pick or replace:

- **presentation** — how the URL reaches the user: open a browser, show it
  in the terminal, hand it to the consumer's UI;
- **transport** — how the user's answer reaches us: an HTTP listener on an
  address of the consumer's choice, a paste into the terminal, the
  consumer's own code;
- **protocol** — what the answer is and how it is checked: an OAuth code
  with its `state` and error, an OIDC code, a SAML response, a passcode.

An authorization strategy is a composition of the three. The package ships
the parts and named compositions for the common cases; the consumer
composes others without writing a new strategy class.

**Success:**
- An HTTP listener is written once and serves every protocol; no listener
  is specific to one kind of payload.
- Where the listener listens is a choice among separate transports:
  IPv6 loopback, IPv4 loopback, both, or a non-local address the consumer
  names. A machine with only one loopback family picks the transport that
  fits.
- A protocol is written once and works over every transport: the same
  OAuth code check applies whether the code arrives on a listener or is
  pasted.
- The case "show the URL, the user types the code" for any provider is a
  composition, not a new class.
- Today's named strategies keep their names as compositions.

## Why

Today one strategy class serves three payload kinds, each HTTP server is
built for one payload, and rules that belong to one part leak into others:
the login-CSRF gate (a protocol rule) needs a flag to stay off for SAML;
the bind address and the advertised redirect (a transport rule) could
disagree, so a redirect to `localhost` could reach a listener that is not
ours. Each new case — another payload, another address family, another way
to show a URL — multiplies classes instead of adding one part.

## Holds throughout

1. **The consumer composes.** Each part is a strategy; the package offers
   parts and named compositions, and no implicit default.
2. **One responsibility per part.** Presentation knows nothing of payloads;
   a transport knows nothing of what a payload means; a protocol knows
   nothing of sockets or terminals.
3. **A transport advertises only what it owns.** The redirect it hands out
   reaches only the addresses it listens on.
4. **A protocol's checks hold on every transport.** Nothing a protocol
   requires (a `state`, a form token, a payload's shape) is skipped because
   of how the answer arrived.
5. **Everything already decided stays.** The login-CSRF protection, the
   loopback default, the `Host` check, no built-in timeouts, no secret or
   server text in a log line, the error contract — each moves to the part
   it belongs to and keeps its guarantees and tests.
6. **The provider's contract does not change.** A provider builds the URL
   and exchanges the payload; how the payload is obtained stays the
   authorization strategy's.

## Out of scope

- The provider side: URL building, `state` and PKCE minting, the exchange.
- Renewal and persistence strategies.
- Non-interactive grants.

## Open — for the spec

1. The three part contracts, and whether they live in interfaces-auth.
2. The shipped parts and the named compositions, with their names.
3. How a transport and a protocol meet: what the listener hands the
   protocol, and how the protocol answers (accept, refuse and keep
   waiting, end).
4. Where the paste form and its token belong.
5. What the existing `ICallbackServer` contract becomes.
6. The migration for a consumer of today's strategies and options.
