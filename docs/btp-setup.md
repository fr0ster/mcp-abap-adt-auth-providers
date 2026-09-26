# What each provider needs on the SAP side

A provider gets a token. Whether ADT (`/sap/bc/adt/...`) accepts that token is
decided elsewhere: by the XSUAA client that issued it, by the trust configured
in the subaccount, and by the user the ABAP system maps it to. This page lists,
per provider, what has to exist on the SAP side, and whether the result is
usable for ADT at all.

Researched 2026-09-26 against SAP Help and SAP Community. Every claim carries
its source:

- **SAP** — SAP Help or other official SAP documentation, linked.
- **Community** — an SAP Community blog or answer, linked. Useful, not
  authoritative.
- **Measured** — measured by this project, on the provider stand or a BTP
  trial (see [Testing](../README.md#testing)). SAP does not document it.
- **Inference** — reasoning from the facts above; no source states it.

Where this page and a system you run disagree, the system wins. Please report
it.

## Contents

- [Summary](#summary)
- [The three rules](#the-three-rules)
- [Shared building blocks](#shared-building-blocks)
- [Per provider](#per-provider)
- [IAS and other OIDC issuers](#ias-and-other-oidc-issuers)
- [Where the sources are weak](#where-the-sources-are-weak)
- [Open questions](#open-questions)

## Summary

Usable for ADT on:

- **(a)** SAP BTP ABAP environment (`standard` plan)
- **(b)** SAP BTP ABAP trial (`shared` plan)
- **(c)** on-premise AS ABAP / S/4HANA, reached by other means

| Provider | Grant on the wire | (a) ABAP environment | (b) Trial | (c) On-premise | What decides it |
|---|---|---|---|---|---|
| `ClientCredentialsProvider` | `client_credentials` at XSUAA | **No** (Inference, Community) | **No**: 401 (Community) | No (Inference) | The token carries no user; ADT runs as a business user |
| `AuthorizationCodeProvider` | `authorization_code` at XSUAA | **Yes**: the documented flow (SAP) | **Yes** (Community, Measured) | Only through Destination + Cloud Connector, reachable from inside CF only (Inference) | The user must exist as a business user |
| `UaaPasscodeProvider` | `password` + `passcode` at XSUAA | **Yes** (Inference from the trial) | **Yes**: ADT discovery 200 (Measured) | As above | As above; an unprovisioned user gets a token and a 401 (Measured) |
| `OidcBrowserProvider` | `authorization_code` + PKCE | **Only with XSUAA as the issuer** (Inference) | Same | No bearer path (Inference) | The ABAP environment trusts XSUAA tokens only |
| `OidcDeviceFlowProvider` | RFC 8628 `device_code` | **No** (Inference) | No | No | Neither XSUAA nor IAS documents a device endpoint |
| `OidcPasswordProvider` | `password` | **Yes against XSUAA**, OIDC origins only (SAP, Community) | **Yes** (Community) | No | XSUAA refuses the password grant for SAML origins (SAP) |
| `OidcTokenExchangeProvider` | RFC 8693 token exchange | **No** directly (Inference) | No | No | XSUAA's cross-issuer grant is `jwt-bearer`, which this package does not send |
| `Saml2BearerProvider` | `saml2-bearer` at XSUAA | **Conditional**, unverified (Inference) | Unverified | Only if ADT can be an OAuth scope (open) | Whether the ABAP instance's client allows the grant — [open question 1](#open-questions) |
| `Saml2PureProvider` | SAML Response → cookies | **No** (Inference) | No | **Plausible**: AS ABAP as a SAML 2.0 service provider (Inference) | The ABAP environment is not a SAML service provider |

## The three rules

Every row above follows from three documented facts.

1. **The ABAP environment trusts JWTs from its own subaccount's XSUAA, and
   nothing else.** "The ABAP environment system in turn trusts SAP
   Authorization and Trust Management service" (SAP,
   [Identity Federation](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/2abdc1d4373648799a8b1275084b7975.html)).
   A token issued by IAS, Entra ID or Keycloak and sent straight to ADT should
   fail (Inference).
2. **The token must carry a user.** ABAP maps it "internally to the business
   user" by e-mail or user name, according to `login_attribute` (SAP, same
   page). A client-only token has nothing to map.
3. **That user must already exist in the ABAP system**, as a business user with
   a developer role. ABAP does not create it on first login (SAP,
   [User Provisioning](https://help.sap.com/docs/ABAP_ENVIRONMENT/250515df61b74848810389e964f8c367/ef52a682060c4051a0645f4ecc5859d0.html)).

## Shared building blocks

### The ABAP environment's own OAuth client

| Item | Finding | Source |
|---|---|---|
| Where the client comes from | A service key on the ABAP environment instance. Its `uaa` section holds `url`, `clientid` and `clientsecret`; the root `url` is the ABAP host | SAP ([service keys](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/7af8259f4b2a4a2b9ef2fa42b436fb7e.html)) |
| Eclipse no longer needs the key | Eclipse ADT connects from the service instance URL with a browser logon; a key is only one way to find the URL | SAP ([connect to the ABAP system](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/41ec2d3a18474743888bbffd05ee81f3.html)) |
| Grants that client allows | `authorization_code` with a `http://localhost:<port>` redirect; `password`; `passcode`; `client_credentials` issues a token. `saml2-bearer` and `jwt-bearer`: unknown | Community ([Postman](https://community.sap.com/t5/technology-blog-posts-by-sap/manually-testing-sap-btp-abap-environment-apis-with-postman-using-oauth-2-0/ba-p/13556445), [headless trial](https://community.sap.com/t5/abap-blog-posts/reading-abap-source-code-from-a-btp-abap-environment-trial-with-a-headless/ba-p/14475022)), Measured (passcode) |
| Editing its `xs-security.json` | The ABAP service broker creates this client; you cannot edit it as you edit your own `xsuaa` instance | Inference |
| A separate `xsuaa`/`application` instance | Its tokens carry that application's audience and scopes. Whether ADT accepts them is unverified; expect a 401 | Inference — [open question 2](#open-questions) |
| X.509 or secret | XSUAA supports `binding-secret` (the default) and `x509`. `instance-secret` is refused for new keys since 2026-01-19 | SAP ([xs-security.json](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/517895a9612241259d6941dbf9ad81cb.html), [token endpoint](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/fd5865e124ab411790cacc0e72df2852.html)) |
| X.509 in this package | Not supported: every provider sends `client_id` and `client_secret`; there is no mTLS client certificate | This repository |
| GET on `/oauth/token` | Deprecated by XSUAA from 2026-06-30. The providers use POST | Community ([announcement](https://community.sap.com/t5/technology-blog-posts-by-sap/effective-from-june-30th-2026-xsuaa-deprecation-of-get-method-for-oauth/ba-p/14418281)) |

### `xs-security.json`, for an `xsuaa` instance you own

Relevant only where you control the client — a test client, or an application
of your own.

| Key | Rule | Source |
|---|---|---|
| `oauth2-configuration.token-validity` | 60–86400 s, default 43200 | SAP ([xs-security.json](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/517895a9612241259d6941dbf9ad81cb.html)) |
| `refresh-token-validity` | 60–31536000 s, default 604800 | SAP (same) |
| `redirect-uris` | An allow-list, wildcards allowed. For `AuthorizationCodeProvider` it must cover `http://localhost:61001/callback`, the default | SAP for the syntax; the value is this package's default |
| `credential-types` | `binding-secret`, `x509` | SAP (same) |
| `grant-types` | **Not on SAP's syntax page.** A community blog says an absent key allows every supported grant, so listing `urn:ietf:params:oauth:grant-type:saml2-bearer` matters only when the list is restricted. `tests/xsuaa/xs-security.json` lists it explicitly | Community ([grant types](https://community.sap.com/t5/technology-blog-posts-by-sap/how-grant-types-keep-your-application-secure/ba-p/13523970)) |
| `allowedproviders` | Restricts which trust origins may log in through this client | SAP (same) |
| Scopes, role templates | Meaningful for your own application only. ADT authorization lives in ABAP business roles, not XSUAA scopes | Inference |

### Trust in the subaccount

| Option | Facts | Source |
|---|---|---|
| IAS over OIDC | SAP "strongly recommends OIDC", and connecting corporate identity providers through IAS rather than configuring several trusts | SAP ([trust](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/2ce3938c66d94479848bff3090999027.html)) |
| Custom SAML IdP, cockpit | Security → Trust Configuration → **Add SAML Trust**: paste the IdP metadata, download `saml-<subdomain>-sp.xml`, import it into the IdP. NameID E-Mail recommended; a `Groups` attribute maps role collections | SAP (same) |
| Custom SAML IdP, scripted | `btp create security/trust` trusts only IAS tenants. The `xsuaa`/`apiaccess` plan's `/sap/rest/identity-providers` can create a SAML trust; SAP Help still describes that plan, and only SAP Community calls it deprecated | SAP ([btp create security/trust](https://help.sap.com/docs/BTP/btp-cli_command-documentation_btp-cli/btp-create-security-trust.html), [apiaccess](https://help.sap.com/docs/HANA_CLOUD_DATABASE/b9902c314aef4afb8f7a29bf8c5b37b3/c6f36d5d49844bd790798ea36538e024.html)), Measured |
| Password grant and trust type | The resource-owner password grant works only with OIDC origins (`sap.default`, `sap.custom`), never SAML | SAP ([token endpoint](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/fd5865e124ab411790cacc0e72df2852.html)) |
| saml2-bearer endpoint | `<xsuaa>/oauth/token/alias/<alias>`, listed in `<xsuaa>/saml/metadata`. Recipient is that URL, Audience the metadata's entityID | SAP ([SAML bearer, Connectivity](https://help.sap.com/docs/CP_CONNECTIVITY/cca91383641e40ffbe03bdc78f00f681/8ebf60c82a8e4cfc904f441c0c0acd6b.html)), Measured |
| `InResponseTo` | The saml2-bearer grant refuses an assertion carrying `InResponseTo`, so only an IdP-initiated assertion passes | Measured (UAA stand, XSUAA trial) |

### The user and the ABAP mapping

| Item | Facts | Source |
|---|---|---|
| Business users need a custom identity service | "For the business users in the ABAP environment, you must set up a custom identity service", normally IAS; SAP ID Service is for platform users | SAP ([user types](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/550251abaf49432bbaa65147b65a1f39.html)) |
| Mapping key | `login_attribute`, `email` (the default) or `user_name`, is set **only when the system is created**; changing it takes a support ticket | SAP ([instance parameters](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/50b32f144e184154987a06e4b55ce447.html)) |
| What must match | With `email`, the employee's e-mail equals the token's; with `user_name`, the business user name equals the IAS login name. The IAS application's subject name identifier must agree | SAP ([User Provisioning](https://help.sap.com/docs/ABAP_ENVIRONMENT/250515df61b74848810389e964f8c367/ef52a682060c4051a0645f4ecc5859d0.html)) |
| Provisioning | Maintain Employees (CSV), SOAP `SAP_COM_0093`, or Identity Provisioning through `SAP_COM_0193`, recommended, with IAS as the source | SAP (same) |
| Developer role | A business role built from the template **`SAP_BR_DEVELOPER`**. The predefined role is for initial setup; SAP recommends your own copy | SAP ([business roles](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/13b2cfb49c8046d8a031e137b6142127.html)) |
| Changing objects | `is_development_allowed` must be true, the default | SAP ([instance parameters](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/50b32f144e184154987a06e4b55ce447.html)) |
| Communication users | Authenticated locally, without identity federation; they reach only the services of their communication arrangement's scenario. No scenario exposing ADT was found | SAP ([Identity Federation](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/2abdc1d4373648799a8b1275084b7975.html)); the ADT part is Inference |
| A user the ABAP system does not know | A token is issued; ADT answers 401 | Measured (trial, IAS origin, not provisioned) |

### Trial

The ABAP trial is one `shared` instance: "The instance is shared between all
trial users" (SAP,
[trial plan](https://help.sap.com/docs/help/01cd1c17c9304dc0ba6bc8650bdf3386/6f8b4bb841674d259bc2affead0fa9ed.html)).
You control neither `login_attribute`, nor provisioning into the system, nor
the grants of its OAuth client, so only the pre-onboarded SAP ID user works
reliably (Inference, consistent with what was measured: the `sap.default` user
reaches ADT, an IAS user gets 401).

## Per provider

### `ClientCredentialsProvider`

| Aspect | Setup | Source |
|---|---|---|
| XSUAA | Any client allowing `client_credentials`; the ABAP instance's key client issues a token | Community |
| Trust, user | None — and that is the problem: the token names no user | Community ([grant types](https://community.sap.com/t5/technology-blog-posts-by-sap/how-grant-types-keep-your-application-secure/ba-p/13523970)) |
| ABAP | Nothing to map; ADT answered 401 on a trial | Community ([headless trial](https://community.sap.com/t5/abap-blog-posts/reading-abap-source-code-from-a-btp-abap-environment-trial-with-a-headless/ba-p/14475022), one author, trial only) |
| Use it for | Non-ADT BTP APIs, and services of an ABAP communication scenario through the system's own token endpoint | Inference |

### `AuthorizationCodeProvider`

| Aspect | Setup | Source |
|---|---|---|
| XSUAA | The ABAP instance's key client: `/oauth/authorize` and `/oauth/token`, a `http://localhost:<port>` redirect accepted | Community ([Postman](https://community.sap.com/t5/technology-blog-posts-by-sap/manually-testing-sap-btp-abap-environment-apis-with-postman-using-oauth-2-0/ba-p/13556445)) |
| Trust | IAS over OIDC, or a custom SAML IdP; the user logs in with whatever the subaccount offers | SAP ([Identity Federation](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/2abdc1d4373648799a8b1275084b7975.html)) |
| User | In the IdP **and** as a business user matching `login_attribute`, with a `SAP_BR_DEVELOPER`-based role | SAP |
| On-premise | Only a BTP application forwarding the token through a Destination with principal propagation and the Cloud Connector (X.509 to ABAP). The connectivity proxy is reachable only from inside CF, so a local MCP server cannot use it | SAP for the mechanism ([principal propagation](https://help.sap.com/docs/CP_CONNECTIVITY/cca91383641e40ffbe03bdc78f00f681/70b8ef33812e486d8b745a0b47fd093e.html)); Inference for the limit |

### `UaaPasscodeProvider`

| Aspect | Setup | Source |
|---|---|---|
| XSUAA | A client allowing `password` and `refresh_token`; the ABAP instance's key client works | Measured |
| Mechanism | The user opens `<xsuaa>/passcode`, logs in and copies a one-time code; the provider sends `grant_type=password&passcode=…` | Community ([grant types](https://community.sap.com/t5/technology-blog-posts-by-sap/how-grant-types-keep-your-application-secure/ba-p/13523970)); the grant is documented by [Cloud Foundry UAA](https://docs.cloudfoundry.org/api/uaa/version/79.7.0/index.html) |
| Trust | Whatever the browser login offers, SAML or OIDC, since authentication happens in the browser | Inference; untested with a SAML origin |
| User, ABAP | As for `AuthorizationCodeProvider`. An unprovisioned user gets a token and a 401 | Measured |
| Fits | A remote or containerised MCP server: no callback, and SSO and MFA stay in the user's browser | Inference |

### `OidcBrowserProvider`

| Aspect | Setup | Source |
|---|---|---|
| Issuer XSUAA | The ABAP instance's key client allows the authorization code flow with a localhost redirect. XSUAA's PKCE support is not documented in what was found | Community; PKCE is [open question 3](#open-questions) |
| Issuer IAS | An IAS OIDC application: *Authorization Code*, optionally *Enforce PKCE (S256)*, up to 20 redirect URIs, optional public client | SAP ([IAS OIDC application](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/72c478e4321e499a9696b74292a69216.html)) |
| An IAS token at ADT | Expected to fail: rule 1 | Inference |
| Bridging IAS to XSUAA | XSUAA's `urn:ietf:params:oauth:grant-type:jwt-bearer` with the IAS token as `assertion`. **Not implemented in this package** | Community ([grant types](https://community.sap.com/t5/technology-blog-posts-by-sap/how-grant-types-keep-your-application-secure/ba-p/13523970)) |
| PKCE clients of the ABAP system itself | A communication scenario can be consumed by a public client with PKCE — OData of that scenario, not ADT | SAP ([inbound OAuth](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/d62e16c461de4e09aaa5f50147a7eabb.html)); ADT exclusion is Inference |
| On-premise | AS ABAP can be an OIDC relying party for an interactive browser session — not a bearer token for an external client | SAP ([OIDC on AS ABAP](https://help.sap.com/docs/ABAP_PLATFORM_NEW/e815bb97839a4d83be6c4fca48ee5777/d72c1a254a584d579c476a998b8ec0b2.html)) |

### `OidcDeviceFlowProvider`

IAS lists authorization code (with PKCE), client credentials, password,
implicit, JWT bearer and token exchange — no device authorization. No XSUAA
grant list includes it either (Inference from absence; SAP
[IAS OIDC application](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/72c478e4321e499a9696b74292a69216.html)).
A device-flow token from Entra ID or Keycloak is not XSUAA-issued, so ADT
refuses it (rule 1). For "log in on another device", use
`UaaPasscodeProvider`.

### `OidcPasswordProvider`

| Aspect | Setup | Source |
|---|---|---|
| XSUAA | The ABAP instance's key client, `grant_type=password&username&password`. XSUAA accepts a `login_hint` naming the origin; this provider does not send one | Community; this repository |
| Trust | OIDC origins only (`sap.default`, `sap.custom`), never SAML | SAP ([token endpoint](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/fd5865e124ab411790cacc0e72df2852.html)) |
| SAP Universal ID | A separate SAP ID password must be set (SAP Note 3085908) | SAP (same) |
| IAS | Supports the password flow for OIDC applications, but its token is an IAS token, which ADT refuses | SAP ([IAS password flow](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/3e10136191f647588a68f6cd32dc451b.html)); the ABAP part is Inference |
| MFA | A user with enforced MFA cannot use this grant | Inference |

### `OidcTokenExchangeProvider`

| Aspect | Setup | Source |
|---|---|---|
| IAS | Supports RFC 8693 token exchange. Requested types include `access_token`, `id_token` and a SAML 2.0 assertion; exchanging an external token needs a confidential client | SAP ([IAS token exchange](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/632df37fb9e2463393715ec1facf39bf.html)) |
| XSUAA | No RFC 8693 found; its cross-issuer exchange is `jwt-bearer` | Community; absence is Inference |
| A possible chain | IAS token exchange yields a SAML assertion that `Saml2BearerProvider` could exchange at XSUAA — if it carries no `InResponseTo` and names XSUAA's audience and recipient | SAP (IAS returns it); the chain is [open question 6](#open-questions) |

### `Saml2BearerProvider`

| Aspect | Setup | Source |
|---|---|---|
| XSUAA client | One allowing `saml2-bearer` and `refresh_token`, **whose token ADT accepts**. The grant was proven only with a separate `xsuaa`/`application` client, which says nothing about ADT | Measured; ADT acceptance is [open question 1](#open-questions) |
| Trust | A custom SAML trust for the assertion's issuer; NameID matching `login_attribute`; `Groups` for role collections | SAP |
| Assertion | A signed Assertion, unencrypted; Audience the XSUAA entityID; Recipient the bearer endpoint; no `InResponseTo` | Measured; see [SAML assertion validation](../README.md#saml-assertion-validation) |
| User, ABAP | The NameID resolves to an existing business user | SAP for the rule; Inference for the SAML path |
| Against SAP's advice | SAP recommends IAS over OIDC instead of custom SAML trusts; this grant needs one | SAP ([trust](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/2ce3938c66d94479848bff3090999027.html)) |
| The ABAP system's own endpoint | `https://<host>/sap/bc/sec/oauth2/token` accepts SAML bearer assertions, with a communication user as the client and a communication arrangement. Its tokens reach that scenario's services — OData only, not generic HTTP services — so not ADT | SAP ([SAML bearer in the ABAP environment](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/5ee4735543e3401e8af688a2931db153.html), [OData only](https://help.sap.com/docs/ABAP_Cloud/eede1416d18c436e8810eaaeb20c38ae/d1151fa58003467e893155f284c85a37.html)); ADT is Inference |
| On-premise | The AS ABAP OAuth server supports the SAML 2.0 bearer grant (`SOAUTH2`, trusted providers in `SAML2`) for OAuth-scoped services | SAP ([AS ABAP OAuth](https://help.sap.com/docs/ABAP_PLATFORM_NEW/e815bb97839a4d83be6c4fca48ee5777/1241087770d9441682e3e02958997846.html)); ADT as a scope is [open question 7](#open-questions) |

### `Saml2PureProvider`

On the ABAP environment the business-user logon is an OAuth authorization code
flow through XSUAA; the system is a resource server, not a SAML service
provider, so there is nowhere to post a SAMLResponse for cookies (SAP for the
premise, [Identity Federation](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/2abdc1d4373648799a8b1275084b7975.html);
Inference for the conclusion). On-premise, AS ABAP can be a SAML 2.0 service
provider (transaction `SAML2`), and a `cookieProvider` would post the Response
to its assertion consumer service and keep the session cookies (Inference; the
ACS path and cookie names are unverified). This package validates the
assertion; the ABAP-specific half is the consumer's `cookieProvider`.

## IAS and other OIDC issuers

| IAS capability | Status | Source |
|---|---|---|
| Authorization code, PKCE S256, public clients | Supported | SAP ([IAS OIDC application](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/72c478e4321e499a9696b74292a69216.html)) |
| Resource-owner password | Supported, once the grant is enabled on the application | SAP ([IAS password flow](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/3e10136191f647588a68f6cd32dc451b.html)) |
| Token exchange (RFC 8693) | Supported; confidential clients for external tokens | SAP ([IAS token exchange](https://help.sap.com/docs/IDENTITY_AUTHENTICATION/6d6d63354d1242d185ab4830fc04feb1/632df37fb9e2463393715ec1facf39bf.html)) |
| JWT bearer, client credentials, implicit | Supported | SAP (IAS OIDC application, related links) |
| Device authorization (RFC 8628) | Not listed | Inference from absence |
| Registering an application | Administration console → Applications → create → Trust → OpenID Connect Configuration (name, redirect URIs, grant types) → Client Authentication | SAP (IAS OIDC application) |
| IAS as the ABAP subaccount's IdP | IAS configured as the subaccount's identity provider, the subaccount registered as an application in IAS, the subject name identifier matching `login_attribute` | SAP ([Identity Federation](https://help.sap.com/docs/BTP/65de2977205c403bbc107264b8eccf4b/2abdc1d4373648799a8b1275084b7975.html)) |

For ADT, IAS — like Entra ID or Keycloak — is useful to the OIDC providers only
as the login in front of XSUAA. Its own token must first become an XSUAA token
through the `jwt-bearer` grant, which this package does not implement
(Inference).

## Where the sources are weak

1. **`grant-types` in `xs-security.json`** appears only in a community blog, not
   on SAP's syntax page.
2. **`client_credentials` against ADT**: one community author, on a trial, who
   invites corrections. Rule 2 supports the conclusion regardless.
3. **The `apiaccess` plan** is called deprecated only in SAP Community; SAP Help
   still describes it. The cockpit's Add SAML Trust is documented but cannot be
   scripted with `btp`.
4. **`InResponseTo` refused on saml2-bearer** is measured here, on UAA and on
   XSUAA, and documented by neither SAP nor the UAA project.
5. **Eclipse ADT changed its logon**: SAP Help now says no service key is
   needed. Whether the key client's password and passcode grants will be
   retired is unknown.

## Open questions

To be settled against a live system, most important first.

1. **Does the ABAP instance's key client allow `saml2-bearer` and
   `jwt-bearer`?** Send a saml2-bearer request with that `clientid` to
   `/oauth/token/alias/<alias>`. If it is refused, `Saml2BearerProvider`
   cannot produce an ADT token on the ABAP environment.
2. **Does ADT accept a token issued to another client** in the same subaccount,
   such as an `xsuaa`/`application` instance? Decode `aud` and `scope`, then
   call `/sap/bc/adt/discovery`.
3. **XSUAA discovery**: read `<xsuaa>/.well-known/openid-configuration` for
   `device_authorization_endpoint`, `code_challenge_methods_supported` and
   `grant_types_supported`.
4. **`UaaPasscodeProvider` with a SAML-origin user**, on a paid system with IAS
   and `SAP_COM_0193` provisioning.
5. **`client_credentials` on a paid system**: confirm the 401 on
   `/sap/bc/adt/discovery`.
6. **IAS token exchange → SAML assertion → `Saml2BearerProvider`**: can the
   assertion be IdP-initiated and addressed to XSUAA?
7. **On-premise**: can `/sap/bc/adt` be an OAuth 2.0 scope under `SOAUTH2`, or
   is a SAML service provider with cookies the only route?
8. **Trial**: can provisioning into the shared ABAP trial be set up at all?
9. **The password grant with MFA or SAP Universal ID users** against the ABAP
   instance's client.
10. **Redirect allow-list of the ABAP instance's client** on paid systems: is
    `http://localhost:61001/callback` accepted?
