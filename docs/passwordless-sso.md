# Passwordless login: SNC, certificates, Kerberos

SAP GUI can log a user on without a password: the SAP Secure Login Client is
installed and configured, a certificate or a Kerberos ticket is available, and
the connection has Secure Network Communication (SNC) switched on. This page
explains what that is, why an HTTP client such as this package cannot use it
as it stands, and which HTTP mechanisms give the same result.

Researched 2026-09-26 against SAP Help and SAP Community. Every claim carries
its source, with the same tags as [btp-setup.md](btp-setup.md):

- **SAP** — SAP Help or other official SAP documentation, linked.
- **Community** — an SAP Community post, linked.
- **Inference** — reasoning from the facts above; no source states it.

Nothing on this page has been tried against a live system yet.

## Contents

- [Summary](#summary)
- [What SAP GUI does](#what-sap-gui-does)
- [How Eclipse ADT does it](#how-eclipse-adt-does-it)
- [HTTP mechanisms](#http-mechanisms)
- [Where each applies](#where-each-applies)
- [From Node.js](#from-nodejs)
- [Checking a machine](#checking-a-machine)
- [Options for this package](#options-for-this-package)
- [Open questions](#open-questions)

## Summary

- The SAP GUI experience is **SNC single sign-on from SAP Single Sign-On
  (Secure Login)**, a licensed product. SNC protects SAP GUI (DIAG) and RFC
  traffic. HTTP has no SNC, so an HTTP client cannot switch it on.
- **Eclipse ADT does the same on-premise over RFC, not over HTTP**: ADT's REST
  requests travel inside the RFC function module `SADT_REST_RFC_ENDPOINT`. For
  the BTP ABAP environment and S/4HANA Cloud it uses a browser logon instead.
- On-premise AS ABAP has two HTTP equivalents: **X.509 client-certificate
  logon over TLS** and **SPNego (Kerberos)**. Secure Login can issue
  short-lived X.509 certificates that SAP documents as usable for TLS, which
  links the SAP GUI setup to an HTTP client.
- On BTP and S/4HANA Cloud the passwordless path is **IAS** — certificate or
  Kerberos logon at IAS, federated to XSUAA. The browser-based providers in
  this package already benefit from it.

## What SAP GUI does

| Item | Facts | Source |
|---|---|---|
| Product | SAP Single Sign-On 3.0: "SAP Single Sign-On requires additional software licenses." Secure Login gives "single sign-on between SAP GUI or Web GUI and ABAP platform with Secure Network Communications (SNC)", with Kerberos and X.509 "separately or in parallel" | SAP ([SSO on ABAP platform](https://help.sap.com/docs/ABAP_PLATFORM_NEW/e815bb97839a4d83be6c4fca48ee5777/7c82ea543d864dacb24f371f6655dccd.html)) |
| Secure Login Client | On the desktop, Windows and macOS. Uses a smart card or USB token; an existing certificate from the Windows store; the Windows domain logon, as a Kerberos ticket or to obtain a certificate from the Secure Login Server; or a user name and password against the Secure Login Server | SAP ([Secure Login Client](https://help.sap.com/docs/SAP_SINGLE_SIGN-ON/df185fd53bb645b1bd99284ee4e4a750/32214d0f7aab464880ca9b12726e39f0.html)) |
| Secure Login Server | On-premise, on AS Java. Authenticates the user and issues a short-lived X.509 certificate, "available in the Microsoft Certificate Store (User Certificate Store)" | SAP ([Secure Login Server](https://help.sap.com/docs/SAP_SINGLE_SIGN-ON/df185fd53bb645b1bd99284ee4e4a750/41212dae66494accb0641a7577af2016.html)) |
| SAP Secure Login Service for SAP GUI | The cloud counterpart of the Secure Login Server, with IAS or a corporate identity provider as the authenticator. Its short-lived certificate "can be used for SNC, SSF, or TLS" | SAP ([Secure Login Service](https://help.sap.com/docs/SAP%20SECURE%20LOGIN%20SERVICE/c35917ca71e941c5a97a11d2c55dcacd/28d654c4459d4693bbf34e5103867f97.html)) |
| Where the certificate lands | Windows: the user certificate store. Firefox: through the Secure Login **PKCS#11 module**. macOS: the Keychain | SAP ([Firefox](https://help.sap.com/docs/SAP_SINGLE_SIGN-ON/df185fd53bb645b1bd99284ee4e4a750/e1352ad909f74a4fa4391ec34920d6e0.html), [macOS](https://help.sap.com/docs/SAP_SINGLE_SIGN-ON/df185fd53bb645b1bd99284ee4e4a750/3230d0d109374e938eca3a4a286564f9.html)) |
| The private key | "non-persistent (like temporary keys provided by Secure Login)". Whether it is marked non-exportable is not documented | SAP ([glossary](https://help.sap.com/docs/SAP_SINGLE_SIGN-ON/df185fd53bb645b1bd99284ee4e4a750/cc21894b907440e08457faa3c3bcd1a9.html)) |
| On the server | CommonCryptoLib, the default cryptographic library since SSO 2.0 SP03 | SAP ([SPNego prerequisites](https://help.sap.com/docs/SAP_SINGLE_SIGN-ON/df185fd53bb645b1bd99284ee4e4a750/aa8b1e80b82340c5b4cdb7e4aabe8d9a.html)) |
| SNC Client Encryption | A free variant that "only offers encryption"; the user still types a password | SAP ([SNC Client Encryption](https://help.sap.com/docs/SAP_S4HANA_ON-PREMISE/e73bba71770e4c0ca5fb2a3c17e8e229/38ac67ee22ef49b5818b574956532f27.html)) |

No SAP page declares SSO 3.0 or the on-premise Secure Login Server deprecated.
That the cloud service succeeds them is Inference.

## How Eclipse ADT does it

- On-premise, ADT connects through the SAP Logon connection, with
  "Single-Sign-On via Secure Network Communication (recommended)"; in the BTP
  ABAP environment and S/4HANA Cloud, "you use a browser-based
  authentication" (SAP,
  [ADT connection](https://help.sap.com/docs/ABAP_Cloud/bbcee501b99848bdadecd4e290db3ae4/4ec2b5a56e391014adc9fffe4e204223.html)).
  The connection dialog asks for the RFC gateway and offers "Activate Secure
  Network Communication (SNC)" (SAP,
  [connection dialog](https://help.sap.com/docs/ABAP_Cloud/bbcee501b99848bdadecd4e290db3ae4/706fa37a6bf41014b5040bee4e204223.html)).
- The transport is RFC: ADT's REST requests go through
  `SADT_REST_RFC_ENDPOINT`, which needs `S_RFC` for it (SAP,
  [ADT authorizations](https://help.sap.com/docs/SAPUI5/b2f662dd9d7a4ec680056733050b4d34/91f3ecc06f4d1014b6dd926db0e91070.html)).
- ADT for VS Code keeps the split: on-premise through RFC, cloud through HTTP
  (Community,
  [VS Code ADT](https://community.sap.com/t5/technology-blog-posts-by-members/the-future-of-abap-is-here-vs-code-adt-zero-config-mcp-and-ai-co-pilots/ba-p/14408186)).

A client that talks HTTP to `/sap/bc/adt/*` therefore cannot reuse ADT's SSO
path; it needs one of the HTTP mechanisms below (Inference).

## HTTP mechanisms

### X.509 client certificate (mTLS), on-premise

ICM asks for a client certificate during the TLS handshake, and ICF maps it to
an ABAP user (SAP,
[certificate logon](https://help.sap.com/docs/SAP_S4HANA_ON-PREMISE/d528eef3dca14679bcb47b069aa17a9d/4e1260981e3d2287e10000000a15822b.html)).
The administrator:

1. sets `icm/HTTPS/verify_client` to `1` (accept) or `2` (require), and
   restarts ICM;
2. imports the issuing CA into the SSL server PSE in `STRUST`;
3. maps certificates to users with rule-based mapping in `CERTRULE`
   (`login/certificate_mapping_rulebased`), or the older table `USREXTID`
   (SAP, [rule-based mapping](https://help.sap.com/docs/SAP_S4HANA_ON-PREMISE/d528eef3dca14679bcb47b069aa17a9d/c830fd902dc8473b9e59db1576cc784b.html));
4. behind SAP Web Dispatcher, forwards the certificate as a header
   (`icm/HTTPS/forward_ccert_as_header`) and trusts the dispatcher on the
   backend (`icm/trusted_reverse_proxy_<xx>`, kernel 7.45+) (SAP,
   [Web Dispatcher](https://help.sap.com/docs/ABAP_PLATFORM_NEW/683d6a1797a34730a6e005d1e8de6f22/2a6cec67c50842aab1444f7dfd0257e1.html)).

For a Secure Login certificate, the system must trust the Secure Login user CA
and map its subject (Inference; no single page describes it end to end).
Whether the `/sap/bc/adt` ICF node accepts certificate logon depends on its
logon procedure in `SICF`; the standard sequence includes it (Inference).

### SPNego (Kerberos), on-premise

The client obtains a Kerberos service ticket for `HTTP/<host>` and sends it as
`Authorization: Negotiate …`.

- Needs a Single Sign-On licence (SAP Note 1848999), CommonCryptoLib and SNC
  activated; "SPNego does not provide transport layer security", so HTTPS
  (SAP, [SPNego prerequisites](https://help.sap.com/docs/SAP_SINGLE_SIGN-ON/df185fd53bb645b1bd99284ee4e4a750/aa8b1e80b82340c5b4cdb7e4aabe8d9a.html)).
- Configured with `spnego/enable` and `spnego/krbspnego`, a keytab in
  transaction `SPNEGO` or `SNCWIZARD`, and the Kerberos principal mapped to
  the user in `SU01` (SAP,
  [SPNego configuration](https://help.sap.com/docs/ABAP_PLATFORM_NEW/9737050ef01843f19572591b42128f1b/87d573d0413949c2aead2f50dd48e636.html)).
- Needs access to the domain controller, so it "cannot be used for most
  internet-facing deployment scenarios" without a VPN (SAP,
  [network constraint](https://help.sap.com/docs/SAP_S4HANA_ON-PREMISE/22bbe89ef68b4d0e98d05f0d56a7f6c8/0058eb5ca4204d67be89ff5d49da5b5f.html)).

A system whose SAP GUI already uses Kerberos over SNC has the licence and
CommonCryptoLib; SPNego for HTTP is additional configuration (Inference).

### Logon tickets

Logon tickets (`MYSAPSSO2`) are "no longer recommended by SAP" (SAP,
[Business Client](https://help.sap.com/docs/SAP_BUSINESS_CLIENT/f526c7c14c074e7b9d18c4fd0c88c593/c9567d6a739a4b4f97abdf26d021711e.html)).
A ticket only carries a session that something else authenticated first; it is
not a way to log on by itself (Inference).

### IAS, for BTP and S/4HANA Cloud

- **Certificate:** "users don't need to enter a password"; the certificate's
  subject or SAN maps to the login name, user ID or e-mail. A custom CA needs
  a support incident and "may take between two and four weeks" (SAP,
  [IAS certificate logon](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/52c7dcb7bbb94f38ab75a4cc9a8cbe03.html)).
- **Kerberos:** lets "users log on without a username and password when they
  are in the corporate network" (SAP,
  [IAS Kerberos](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/4bb4b247a47e47a59b88378500ffbe82.html)).
- Both happen in the browser. `AuthorizationCodeProvider`,
  `UaaPasscodeProvider` and `OidcBrowserProvider` get a passwordless login
  whenever the browser holds the certificate or the Kerberos session
  (Inference). No documented IAS grant takes a user's certificate without a
  browser.

## Where each applies

| Mechanism | On-premise / private cloud | BTP ABAP environment | S/4HANA Cloud Public | From Node.js over HTTP |
|---|---|---|---|---|
| SNC through Secure Login, as in SAP GUI and Eclipse ADT | Yes (SAP) | No, browser logon (SAP) | No, browser logon (SAP) | **No**: RFC and DIAG only |
| X.509 client certificate at ICF | Yes (SAP) | Not configurable for business users (Inference) | No (Inference) | **Yes** when the key is reachable (Inference) |
| Short-lived Secure Login certificate over TLS | Yes, with trust and `CERTRULE` (Inference) | — | — | Only when the key can be reached (Inference) |
| SPNego at ICF | Yes, licence required (SAP) | No (Inference) | No (Inference) | **Yes** with a Kerberos ticket on the corporate network (Inference) |
| IAS certificate or Kerberos → XSUAA | Where the system trusts IAS over SAML (SAP) | Yes, in the browser (SAP) | Yes, in the browser (SAP) | **Yes, today**, through the browser providers |

## From Node.js

- **A certificate in a file** (PEM or PFX, from a corporate PKI): Node's
  `https.Agent` takes `cert`, `key` or `pfx` directly (Inference). The
  simplest case.
- **A certificate Secure Login put into the system store**: Node cannot take a
  private key from the Windows store or the macOS Keychain. `--use-system-ca`
  covers CA certificates only (Node.js,
  [TLS](https://nodejs.org/api/tls.html)). The ways that remain are the Secure
  Login PKCS#11 module (a binding such as `pkcs11js` plus an OpenSSL provider
  — fragile and platform-specific) or a local helper that performs the TLS
  handshake (Inference).
- **Kerberos**: the `kerberos` npm package wraps GSSAPI on Unix and SSPI on
  Windows and can produce the `Negotiate` token, given a ticket (a domain
  logon, or `kinit`) and a registered `HTTP/<fqdn>` service principal
  (Inference; untested).
- **RFC with SNC**: `node-rfc` is deprecated — "No longer supported" on npm,
  and SAP archived the repository on 2026-05-28 with no successor named
  ([SAP/node-rfc#329](https://github.com/SAP/node-rfc/issues/329)). And an
  RFC transport is not an authorization credential; it would belong in a
  connection package, not here (Inference).

The certificate or `Negotiate` header has to reach every request to
`/sap/bc/adt`, or a provider logs on once and hands over the session cookies,
as `Saml2PureProvider` does (Inference).

## Checking a machine

On a machine where SAP GUI already logs on without a password (Inference —
SAP does not describe these checks):

1. Open the Secure Login Client console and see which profile is active:
   Kerberos, or an X.509 certificate (and from where). That decides between
   SPNego and a client certificate.
2. Open `https://<host>/sap/bc/adt/discovery` in a browser. If it answers
   without asking for a password, the system already accepts a passwordless
   HTTP logon, by certificate or by SPNego; the browser's developer tools
   show which (a TLS client certificate, or an `Authorization: Negotiate`
   header).
3. If it asks for a password, the system accepts SNC only; HTTP needs the
   administrator's configuration above.

## Options for this package

None is decided. Each follows the package's rule that anything pluggable is a
strategy with a shipped default (Inference, design).

- **A — documentation only.** Describe passwordless login through IAS for
  BTP and S/4HANA Cloud. No code, and it covers the cloud today.
- **B — `SpnegoProvider`**, on-premise: sends `Authorization: Negotiate`,
  follows the `401 WWW-Authenticate: Negotiate` round trip, and returns the
  session cookies, as `Saml2PureProvider` does. The token source is a strategy;
  the default uses `kerberos` as an optional peer dependency. Refuses
  `http://`. A KDC in Docker could prove the wire contract, as the provider
  stand proves OAuth.
- **C — `X509CertificateProvider`**, on-premise: one request with the client
  certificate, returning the session cookies. The certificate source is a
  strategy: PEM or PFX from a file by default, a PKCS#11 or system-store
  source supplied by the consumer. Never logs the key, the certificate or the
  passphrase. Holding the key is the hard part.
- **Rejected — an RFC/SNC transport.** A different transport, not a
  credential, and `node-rfc` is archived.

Session cookies declare no lifetime, so B and C need an expiry policy — a
configured TTL or a probe request; refreshing means logging on again, which
needs no user. Whether `@mcp-abap-adt/interfaces-auth` already has a contract
for a cookie result, as `Saml2PureProvider` returns, is to be checked before
proposing one.

## Open questions

1. Does `/sap/bc/adt/*` accept a certificate or an SPNego logon on a standard
   system? [Checking a machine](#checking-a-machine) answers it for one system.
2. Does the Secure Login Server or Secure Login Service offer an enrolment API
   through which a client other than Secure Login Client obtains a
   certificate for its own key?
3. Are the keys Secure Login puts in the Windows store non-exportable?
4. Does IAS offer a user-token grant authenticated by a user certificate,
   without a browser?
5. Can current Eclipse ADT reach an on-premise system over HTTP at all?
6. When does SSO 3.0 go out of maintenance relative to Secure Login Service?
