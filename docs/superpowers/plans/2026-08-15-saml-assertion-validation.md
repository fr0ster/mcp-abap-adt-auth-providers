# SAML Assertion Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `@mcp-abap-adt/auth-providers` establish that a SAML assertion is genuine, addressed to us, currently valid and not a replay — through a strategy with a shipped default — instead of accepting any non-empty string.

**Architecture:** `IAssertionValidator` and `IAssertionReplayStore` come from `@mcp-abap-adt/interfaces-auth` (published in 1.2.0); the shipped default lives in `auth-providers/src/validation/`, built from small pure modules (date parsing, document-ID rules, signature resolution, replay store) that an orchestrator composes. Both SAML providers run the validator and take their expiry from its result.

**Tech Stack:** TypeScript, `xml-crypto` for XML-DSig, `@xmldom/xmldom` for the DOM, Jest, Biome. `@mcp-abap-adt/auth-mocks` as a devDependency for the tests.

**Spec:** `docs/superpowers/specs/2026-08-13-saml-assertion-validation-design.md`. Read it before Task 1 — every rule below is justified there, and the check table is the contract this plan implements.

**Status:** approved 2026-09-02; revised 2026-09-24 after the interfaces split, the `auth-mocks` 0.3.0 release and `auth-providers` 2.2.1; **revised again 2026-09-25 for option B of the spec's decision 4 and the 3.0.0 release.** The revision needs its own approval before execution resumes. No task has been executed in this repository yet.

**What changed since approval.**

- **Option B (2026-09-25).** UAA and XSUAA refuse, on the saml2-bearer grant,
  any assertion carrying `InResponseTo` — measured on the provider stand and
  on a live XSUAA. The spec's decision 4 now has three sources for the
  expected request ID — minted, declared, or none by an explicit
  `idpInitiated: true` — and step 10 requires `InResponseTo` **absent** in the
  third. That reopens **Task 1** (`AssertionContext.expectedInResponseTo`
  becomes optional, in `interfaces-auth@2.0.0`) and changes **Tasks 9, 10, 11
  and 12**, each marked below.
- **3.0.0 has shipped without this work** — Node 22/24, `UaaPasscodeProvider`,
  `DeviceFlowProvider` removed, the RFC 7522 conversion (#40), the provider
  stand and the live XSUAA checks. This work is now **4.0.0**, and several
  things it planned to add are already there (Task 3).

- The `@mcp-abap-adt/interfaces` facade is deleted. **Task 1 is done upstream** — the five types and an error code are in `@mcp-abap-adt/interfaces-auth@1.2.0`, with one difference from what Task 1 described (see Task 1). The move off the facade was PR #29.
- **Task 2 is done upstream** — `@mcp-abap-adt/auth-mocks@0.3.0` is published with `signWhat`, and review added one thing the task did not describe: `signXml` takes a `location`, and the signed Response carries its `Signature` after its own `Issuer`, as SAML Core requires (see Task 2). Task 9's fixture uses the same placement.
- What is left of **Task 3** is adding the XML libraries and `auth-mocks`.
- `Saml2BearerProvider` now spends its refresh token (PR #31, `auth-providers` 2.2.1). A refresh carries no assertion, so there is nothing for the validator to run on; **Task 11** pins that, and updates the refresh tests that construct the provider without identity-provider configuration.

## Global Constraints

- **Interface-only communication.** Anything crossing a package boundary is an interface from a contract package — `@mcp-abap-adt/interfaces-auth`, `-auth-sap` or `-utils`, never `interfaces-adt`. A logger is `ILogger`, never a local abstraction.
- **Everything pluggable is a strategy**, shipped with a working default the consumer can replace.
- **Nothing writes to `process.stdout`.** Under an MCP or LSP stdio transport a stray line corrupts the protocol.
- **Absent is refused, not skipped.** A rule phrased "present and not X" is one an attacker satisfies by deleting the field. Every field the check table names refuses when it is missing.
- **Every rule gets a test that fails when the rule is deleted.** For a conjunction, mutate **each half separately** — a whole-block mutation cannot tell you which half is load-bearing.
- **Assert on a message fragment unique to the rule.** A shared prefix kept a test green after the rule it protected was deleted, twice, during the `auth-mocks` cycle.
- Node 22 or 24 (`^22 || ^24`, following SAP BTP), CommonJS, TypeScript `strict: true`.
- `npm run lint:check`, `npm run build`, `npm run test:check` and `npm test` pass before every commit.
- The agent never runs `npm publish`, never merges a PR, and never creates a tag before a merge exists.

## Facts established before this plan was written

Do not re-derive these; do verify anything you depend on that is not listed.

- **The contracts are in `@mcp-abap-adt/interfaces-auth@^1.2.0`.** Since PR #29
  `auth-providers` depends on `interfaces-auth`, `interfaces-auth-sap` and
  `interfaces-utils` instead of the deleted facade. `ILogger` comes from
  `@mcp-abap-adt/interfaces-utils`.
- **The error code is `ASSERTION_ERROR_CODES.VALIDATION_ERROR`**, a constant of
  its own in `interfaces-auth`, not an entry in `TOKEN_PROVIDER_ERROR_CODES`. Its
  value is the string `'ASSERTION_VALIDATION_ERROR'`, as this plan intended.
- `auth-providers` is at **3.0.0**. `@xmldom/xmldom` is already a runtime
  dependency (#40, for `toBearerAssertion`), and `@mcp-abap-adt/auth-mocks`
  `^0.3.0` already a devDependency (#38). `xml-crypto` is not yet.
- The provider stand (`npm run test:stand`) runs UAA and Keycloak; Keycloak
  issues real, signed SAML assertions, IdP-initiated among them
  (`src/__tests__/integration/stand/keycloakSaml.test.ts`). The live XSUAA
  suite (`npm run test:xsuaa`) signs with a key generated per run.
- The stand's Keycloak signs **both** the Response and the Assertion (its
  realm clients set `saml.server.signature` and `saml.assertion.signature`).
  Measured 2026-09-25: both signatures verify with `xml-crypto` against the
  certificate in Keycloak's metadata, and each is enveloped by the element it
  references. Task 6's every-signature rule accepts that; the earlier
  one-signature rule refused it.
- `Saml2CommonConfig` lives in `auth-providers/src/providers/saml2Utils.ts:10`, **not** in a contract package. The new configuration fields go there.
- `@mcp-abap-adt/auth-mocks@0.3.0` is published: `signWhat?: 'assertion' | 'response'`, and `signXml(xml, key, { referenceXPath?, location? })`, where `location` (`SignatureLocation`) says where the `Signature` goes. Without `location`, a custom `referenceXPath` gets the `Signature` appended as the referenced element's last child — schema-invalid for a Response. `startMockSamlIdp` requires `acsUrls` — with none registered it refuses every `AuthnRequest`.
- `xml-crypto@6`: `checkSignature` **throws** when the signature value fails, and returns `false` only for a reference-digest mismatch. Both outcomes mean "invalid".
- `@xmldom/xmldom@0.9`: `getAttribute` decodes entities; `parseFromString` throws on input with no root element. `Node` must be imported from the package — this project has no `dom` lib.

---

## File Structure

**`@mcp-abap-adt/interfaces-auth`** — nothing to create: `src/auth/IAssertionValidator.ts` and `src/auth/AssertionErrorCodes.ts` are published in 1.2.0.

**`@mcp-abap-adt/auth-providers`**

- Create `src/validation/xsdDateTime.ts` — parse an `xsd:dateTime` strictly. Pure, no SAML knowledge.
- Create `src/validation/documentIds.ts` — the ID rules: uniqueness across the document, presence on the assertion. Pure DOM.
- Create `src/validation/signedNode.ts` — verify the signature and report **which element** it covers.
- Create `src/validation/inMemoryReplayStore.ts` — `createInMemoryReplayStore`, plus the module-level default.
- Create `src/validation/assertionValidator.ts` — the orchestrator: the twelve checks in order.
- Create `src/errors/AssertionValidationError.ts` — one error carrying the failed check.
- Modify `src/auth/saml2Auth.ts` — `buildSamlAuthorizationUrl` returns the minted request ID; `parseSamlNotOnOrAfter` is deleted.
- Modify `src/providers/saml2Utils.ts` — new config fields; `getSamlAssertion` yields the request ID alongside the payload.
- Modify `src/providers/Saml2PureProvider.ts`, `src/providers/Saml2BearerProvider.ts` — run the validator.
- Modify `src/index.ts` — export both shipped validators, the store factory and the error.

The pure modules are separate because each is a rule with its own failure modes, and because `assertionValidator.ts` would otherwise be a file nobody can hold in their head — the check table alone is twelve steps.

---

### Task 1: The interfaces — reopened for `interfaces-auth@2.0.0`

**Repository:** `/home/okyslytsia/prj/mcp-abap-adt-interfaces`, package
`interfaces-auth`.

`@mcp-abap-adt/interfaces-auth@1.2.0` publishes `AssertionContext`,
`ValidatedAssertion`, `IAssertionValidator`, `AssertionReplayKey` and
`IAssertionReplayStore` field for field as this task first specified them. One
difference stays: the error code is `ASSERTION_ERROR_CODES.VALIDATION_ERROR`
(same string value as the planned `TOKEN_PROVIDER_ERROR_CODES.ASSERTION_VALIDATION_ERROR`);
Task 8 uses it.

**What option B needs.** In `src/auth/IAssertionValidator.ts`:

```ts
  /**
   * The AuthnRequest ID this response must answer. Absent for a login declared
   * IdP-initiated: then no request was sent, and a validator must refuse an
   * assertion that carries `InResponseTo` at all.
   */
  readonly expectedInResponseTo?: string;
```

Required → optional on an input context is breaking for implementers of
`IAssertionValidator`: they read a `string` that may now be `undefined`. It
ships in `interfaces-auth@2.0.0`, which the owner has accepted and may batch
with other breaking contract changes. The changelog entry says what an
implementer must now handle.

- [ ] Make the field optional with the comment above; add the changelog entry.
- [ ] `npm run check` in the interfaces repository.
- [ ] Open the PR and stop. Version, tag and publish of 2.0.0 are the owner's.

Task 3 installs `^2.0.0` and stops if it is not published.

---

### Task 2: `auth-mocks` gains a signed-Response mode — done upstream

`@mcp-abap-adt/auth-mocks@0.3.0` is published (auth-mocks PR #2, tag
`v0.3.0`) with what this task specified:

- `SamlOptions.signWhat?: 'assertion' | 'response'`, defaulting to
  `'assertion'`, so every existing consumer gets what it got before;
- `'response'` makes the `Reference` name the `samlp:Response`, and the
  `wrongKey` and `tamperedAfterSign` variants stay detectable in that mode —
  the mock's own suite checks both, after checking that a valid
  response-signed document verifies.

One addition review required and this task had not foreseen: with only a
`referenceXPath`, `signXml` appended the `Signature` as the Response's last
child, after `Status` and the `Assertion`. SAML Core's `ResponseType` puts it
right after `Issuer`. `signXml` now takes `location: { reference, action }`,
and the response mode passes the Response's own `Issuer` with
`action: 'after'`. Anything in this plan that signs a Response with `signXml`
does the same — see Task 9's fixture.

Nothing to do in this task.

---

### Task 3: The XML libraries and auth-mocks

**Repository:** `/home/okyslytsia/prj/mcp-abap-adt-auth-providers` — and every task from here on.

**Files:**

- Modify: `package.json`

**Interfaces:**

- Consumes: `@mcp-abap-adt/interfaces-auth@^2.0.0` from Task 1; `@mcp-abap-adt/auth-mocks@^0.3.0` and `@xmldom/xmldom`, already dependencies.

The move off the facade is already done (PR #29). This task only adds what validation needs.

- [ ] **Step 1: Record what passes now**

```bash
npm test 2>&1 | grep -E "^Tests:|^Test Suites:"
```

Write the numbers down; Step 4 compares against them.

- [ ] **Step 2: Change the dependencies**

In `package.json`:

- `dependencies`: `"@mcp-abap-adt/interfaces-auth"` to `^2.0.0` (Task 1), and add `"xml-crypto": "^6.1.2"`. `@xmldom/xmldom` is already there (#40).
- `devDependencies`: `@mcp-abap-adt/auth-mocks` `^0.3.0` is already there (#38). Keep the caret on `0.3`: `^0.1.1` or `^0.2.0` would resolve to a version without `signWhat`.

If `interfaces-auth@2.0.0` is not published, **stop and say so**.

```bash
npm install
```

- [ ] **Step 3: Compile**

```bash
npm run build && npm run test:check
```

Expected: PASS.

- [ ] **Step 4: Run the suite**

```bash
npm test 2>&1 | grep -E "^Tests:|^Test Suites:"
```

Expected: identical to Step 1. Any change is a finding.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add package.json package-lock.json
git commit -m "chore: the XML libraries validation needs, and auth-mocks with signWhat"
```

---

### Task 4: Strict `xsd:dateTime`

**Files:**

- Create: `src/validation/xsdDateTime.ts`
- Test: `src/__tests__/validation/xsdDateTime.test.ts`

**Interfaces:**

- Produces: `parseXsdDateTime(value: string | null | undefined): Date | null` — the `Date` when the value is a valid `xsd:dateTime`, `null` otherwise. Never throws.

**Why this is its own module.** Every temporal check in the validator depends on it, and `Date.parse` is not it: `Date.parse('2026-02-30T00:00:00Z')` silently rolls over to 2 March, and any two digits are accepted as a timezone offset. Both traps were found and fixed in `auth-mocks`; this is the same rule, implemented once.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/validation/xsdDateTime.test.ts`:

```ts
import { describe, expect, it } from "@jest/globals";
import { parseXsdDateTime } from "../../validation/xsdDateTime";

describe("parseXsdDateTime", () => {
  it("accepts a UTC instant", () => {
    expect(parseXsdDateTime("2026-08-15T10:30:00Z")?.toISOString()).toBe(
      "2026-08-15T10:30:00.000Z",
    );
  });

  it("accepts fractional seconds", () => {
    expect(parseXsdDateTime("2026-08-15T10:30:00.250Z")?.toISOString()).toBe(
      "2026-08-15T10:30:00.250Z",
    );
  });

  it("accepts a positive and a negative offset", () => {
    expect(parseXsdDateTime("2026-08-15T12:30:00+02:00")?.toISOString()).toBe(
      "2026-08-15T10:30:00.000Z",
    );
    expect(parseXsdDateTime("2026-08-15T08:30:00-02:00")?.toISOString()).toBe(
      "2026-08-15T10:30:00.000Z",
    );
  });

  // Date.parse normalises this into 2 March rather than rejecting it. The
  // calendar round-trip is the only thing that catches it.
  it("refuses a day that does not exist in its month", () => {
    expect(parseXsdDateTime("2026-02-30T00:00:00Z")).toBeNull();
    expect(parseXsdDateTime("2026-04-31T12:00:00Z")).toBeNull();
  });

  // The mirror of the case above: a real leap day must survive, so nobody
  // "fixes" the rule with a flat 28-day February.
  it("accepts a genuine leap day", () => {
    expect(parseXsdDateTime("2028-02-29T00:00:00Z")).not.toBeNull();
  });

  it("refuses an offset outside ±14:00", () => {
    expect(parseXsdDateTime("2026-08-15T10:30:00+99:99")).toBeNull();
    expect(parseXsdDateTime("2026-08-15T10:30:00+15:00")).toBeNull();
    expect(parseXsdDateTime("2026-08-15T10:30:00+05:99")).toBeNull();
  });

  it("refuses 14:01 but accepts the legal maximum and minimum", () => {
    expect(parseXsdDateTime("2026-08-15T10:30:00+14:01")).toBeNull();
    expect(parseXsdDateTime("2026-08-15T10:30:00+14:00")).not.toBeNull();
    expect(parseXsdDateTime("2026-08-15T10:30:00-14:00")).not.toBeNull();
  });

  // An in-range hour with a non-zero minute: without this the "hour 14 implies
  // minute 0" half of the rule can be deleted unnoticed.
  it("accepts a non-zero offset minute below the maximum hour", () => {
    expect(parseXsdDateTime("2026-08-15T10:30:00+05:30")).not.toBeNull();
  });

  it("refuses an out-of-range time of day", () => {
    expect(parseXsdDateTime("2026-08-15T24:00:00Z")).toBeNull();
    expect(parseXsdDateTime("2026-08-15T10:60:00Z")).toBeNull();
  });

  it("refuses shapes that are not xsd:dateTime at all", () => {
    for (const bad of [
      "2026-08-15",
      "15/08/2026",
      "Aug 15 2026",
      "",
      "not-a-date",
    ]) {
      expect(parseXsdDateTime(bad)).toBeNull();
    }
  });

  it("refuses a missing value without throwing", () => {
    expect(parseXsdDateTime(null)).toBeNull();
    expect(parseXsdDateTime(undefined)).toBeNull();
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/validation/xsdDateTime.test.ts
```

Expected: FAIL — `Cannot find module '../../validation/xsdDateTime'`.

- [ ] **Step 3: Implement `src/validation/xsdDateTime.ts`**

```ts
/**
 * Parsing an `xsd:dateTime` strictly enough to trust the result.
 *
 * `Date.parse` is not this. It normalises `2026-02-30` into 2 March instead of
 * rejecting it, and it will read a timezone offset no calendar has. Both traps
 * were found in `@mcp-abap-adt/auth-mocks` and fixed there the same way: match
 * the lexical shape, then require every component to survive a round trip.
 *
 * Deliberately not implemented: negative (BCE) years, the `24:00:00`
 * end-of-day form, and leap seconds. No identity provider in this family emits
 * them, and pretending to cover them would be worse than saying so.
 */

const SHAPE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** Returns the instant, or null when the value is not a valid xsd:dateTime. */
export function parseXsdDateTime(
  value: string | null | undefined,
): Date | null {
  if (!value) return null;
  const m = SHAPE.exec(value);
  if (!m) return null;

  const [, y, mo, d, h, mi, s, fraction, zone] = m;
  const year = Number(y);
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(s);

  if (month < 1 || month > 12) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  // The calendar round trip. Date.UTC rolls 2026-02-30 into 2026-03-02, so a
  // component that comes back changed means the date does not exist.
  const utc = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    utc.getUTCFullYear() !== year ||
    utc.getUTCMonth() !== month - 1 ||
    utc.getUTCDate() !== day
  ) {
    return null;
  }

  if (zone !== "Z") {
    const offsetHour = Number(zone.slice(1, 3));
    const offsetMinute = Number(zone.slice(4, 6));
    // xsd:dateTime bounds the offset at ±14:00, and exactly 14 allows no
    // minutes. Both halves matter: +15:00 fails the first, +14:01 the second.
    if (offsetHour > 14 || offsetMinute > 59) return null;
    if (offsetHour === 14 && offsetMinute !== 0) return null;
  }

  const parsed = new Date(
    `${y}-${mo}-${d}T${h}:${mi}:${s}${fraction ?? ""}${zone}`,
  );
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/validation/xsdDateTime.test.ts
```

Expected: PASS, eleven cases.

- [ ] **Step 5: Prove each half is load-bearing, one at a time**

Four mutations, each applied alone and reverted before the next. Report per case with `-t` which single test went red:

1. Delete the calendar round-trip block — `refuses a day that does not exist in its month` must go red.
2. Delete `if (offsetHour > 14 || offsetMinute > 59) return null;` — `refuses an offset outside ±14:00` must go red.
3. Delete `if (offsetHour === 14 && offsetMinute !== 0) return null;` — `refuses 14:01 but accepts the legal maximum and minimum` must go red.
4. Delete `if (hour > 23 || minute > 59 || second > 59) return null;` — `refuses an out-of-range time of day` must go red.

If a mutation turns more than the named test red, say so; if it turns none red, stop and report rather than adjusting a fixture.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add src/validation/xsdDateTime.ts src/__tests__/validation/xsdDateTime.test.ts
git commit -m "feat: parse xsd:dateTime strictly enough to trust it"
```

---

### Task 5: Document ID rules

**Files:**

- Create: `src/validation/documentIds.ts`
- Test: `src/__tests__/validation/documentIds.test.ts`

**Interfaces:**

- Produces:
  - `findDuplicateId(doc: Document): string | null` — the first `ID` value that appears more than once, or `null`.
  - `readRequiredId(element: Element): string | null` — the element's non-empty `ID`, or `null`.

**Why this comes before the signature.** XML-DSig resolves its reference by `ID`. A document with two elements sharing an `ID` makes "which element is signed" a question the parser answers rather than the specification — the classic lever for signature wrapping. The uniqueness check therefore runs before any reference is resolved.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/validation/documentIds.test.ts`:

```ts
import { DOMParser, type Document, type Element } from "@xmldom/xmldom";
import { describe, expect, it } from "@jest/globals";
import { findDuplicateId, readRequiredId } from "../../validation/documentIds";

const parse = (xml: string) =>
  new DOMParser().parseFromString(xml, "text/xml") as unknown as Document;

describe("findDuplicateId", () => {
  it("passes a document whose IDs are unique", () => {
    const doc = parse('<r ID="_a"><c ID="_b"/><c ID="_c"/></r>');
    expect(findDuplicateId(doc)).toBeNull();
  });

  it("names the value that appears twice", () => {
    const doc = parse('<r ID="_a"><c ID="_dup"/><c ID="_dup"/></r>');
    expect(findDuplicateId(doc)).toBe("_dup");
  });

  // The wrapping shape: the duplicate is between the root and a nested
  // element, not between siblings.
  it("finds a duplicate shared between an ancestor and a descendant", () => {
    const doc = parse('<r ID="_same"><c ID="_same"/></r>');
    expect(findDuplicateId(doc)).toBe("_same");
  });

  it("ignores elements with no ID at all", () => {
    const doc = parse('<r ID="_a"><c/><c/></r>');
    expect(findDuplicateId(doc)).toBeNull();
  });
});

describe("readRequiredId", () => {
  it("returns the ID", () => {
    const doc = parse('<a ID="_x"/>');
    expect(readRequiredId(doc.documentElement as unknown as Element)).toBe(
      "_x",
    );
  });

  it("returns null when the attribute is absent", () => {
    const doc = parse("<a/>");
    expect(
      readRequiredId(doc.documentElement as unknown as Element),
    ).toBeNull();
  });

  it("returns null when the attribute is empty", () => {
    const doc = parse('<a ID=""/>');
    expect(
      readRequiredId(doc.documentElement as unknown as Element),
    ).toBeNull();
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/validation/documentIds.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/validation/documentIds.ts`**

```ts
import type { Document, Element } from "@xmldom/xmldom";

/**
 * The `ID` rules, which run before any signature reference is resolved.
 *
 * XML-DSig resolves its reference by `ID`. Two elements sharing one make
 * "which element is signed" a question the parser answers rather than the
 * specification, and that ambiguity is the classic lever for signature
 * wrapping. So uniqueness is established first, across the whole document —
 * not only across the two elements this validator happens to read.
 */

/** The first ID value appearing more than once, or null when all are unique. */
export function findDuplicateId(doc: Document): string | null {
  const seen = new Set<string>();
  const elements = doc.getElementsByTagName("*");
  for (let i = 0; i < elements.length; i++) {
    const id = elements[i].getAttribute("ID");
    if (!id) continue;
    if (seen.has(id)) return id;
    seen.add(id);
  }
  return null;
}

/** The element's ID, or null when it is absent or empty. */
export function readRequiredId(element: Element): string | null {
  const id = element.getAttribute("ID");
  return id ? id : null;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/validation/documentIds.test.ts
```

Expected: PASS, seven cases.

- [ ] **Step 5: Prove the rules**

Two mutations, one at a time:

1. Make `findDuplicateId` always return `null` — `names the value that appears twice` **and** `finds a duplicate shared between an ancestor and a descendant` must both go red.
2. Change `readRequiredId` to `return element.getAttribute('ID')` — `returns null when the attribute is empty` must go red while the other two stay green. This is the half that distinguishes empty from absent.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add src/validation/documentIds.ts src/__tests__/validation/documentIds.test.ts
git commit -m "feat: refuse duplicate IDs before a reference is resolved"
```

---

### Task 6: Which element the signature covers

**Files:**

- Create: `src/validation/signedNode.ts`
- Test: `src/__tests__/validation/signedNode.test.ts`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `resolveSignedElements(xml: string, doc: Document, certificates: readonly string[]): Element[]` — the elements the document's signatures cover, having verified **every** signature against one of the certificates. Throws `Error` with a message naming the failure otherwise. Several signatures are normal — identity providers often sign the Response and the Assertion both — and each is held to every rule (spec: "Several signatures are accepted, and every one of them is held to the rule").

**This is the rule everything else rests on.** The question is not "does the document contain a valid signature" but "which element does the valid signature cover" — and the caller then reads only that element. A document holding a genuinely signed fragment beside an unsigned one is the signature wrapping attack, and this function is what refuses it.

**Two library facts, established in `auth-mocks`, that shape the code:**

- `checkSignature` **throws** when the signature value fails against an unrelated certificate, and returns `false` only for a reference-digest mismatch. Both mean invalid, so both must be caught.
- Certificates are a list because identity providers rotate keys. Try each; the signature is valid when any accepts it.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/validation/signedNode.test.ts`. It signs its fixtures with the mock's own key material, which is exactly what `auth-mocks` exports it for:

```ts
import { DOMParser, type Document, type Element } from "@xmldom/xmldom";
import { describe, expect, it } from "@jest/globals";
import { SignedXml } from "xml-crypto";
import { generateKeyMaterial, signXml } from "@mcp-abap-adt/auth-mocks";
import { resolveSignedElements, toPem } from "../../validation/signedNode";

const parse = (xml: string) =>
  new DOMParser().parseFromString(xml, "text/xml") as unknown as Document;

const ASSERTION = (id = "_a1") =>
  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}">` +
  `<saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>`;

const RESPONSE = (inner: string, id = "_r1") =>
  `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${id}">` +
  `${inner}</samlp:Response>`;

describe("resolveSignedElements", () => {
  it("returns the Assertion when the Assertion is signed", () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [
      key.certificatePem,
    ]);
    expect(element.localName).toBe("Assertion");
  });

  // The spec promises PEM or base64 DER, and metadata carries the latter.
  // Measured: xml-crypto throws DECODER routines::unsupported on bare base64,
  // and the same bytes armoured verify — so this is a real conversion, not a
  // formatting preference.
  it("accepts a certificate given as bare base64 DER", () => {
    const key = generateKeyMaterial();
    const der = key.certificatePem
      .replace(/-----[^-]+-----/g, "")
      .replace(/\s+/g, "");
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [der]);
    expect(element.localName).toBe("Assertion");
  });

  it("refuses a certificate that is neither PEM nor base64", () => {
    expect(() => toPem("not a certificate!")).toThrow(
      /neither PEM nor base64/i,
    );
  });

  // Base64 syntax is not enough: this armours cleanly, and only OpenSSL knows
  // it is not a certificate. Without the X509Certificate parse it would reach
  // verification and be reported as a bad signature — the configuration
  // blamed on the assertion again.
  it("refuses base64 that is not a certificate", () => {
    expect(() => toPem("AAAA")).toThrow(/not a valid X.509 certificate/i);
  });

  it("accepts a certificate later in the rotation list", () => {
    const other = generateKeyMaterial();
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [
      other.certificatePem,
      key.certificatePem,
    ]);
    expect(element.localName).toBe("Assertion");
  });

  it("refuses a document with no signature", () => {
    const wrapped = RESPONSE(ASSERTION());
    expect(() => resolveSignedElements(wrapped, parse(wrapped), ["x"])).toThrow(
      /no signature/i,
    );
  });

  it("refuses a signature made with a key we do not trust", () => {
    const key = generateKeyMaterial();
    const other = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [other.certificatePem]),
    ).toThrow(/signature does not verify/i);
  });

  it("refuses content altered after signing", () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key).replace("mock-idp", "other-idp");
    const wrapped = RESPONSE(signed);
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/signature does not verify/i);
  });

  // The attack this function exists for: a validly signed assertion beside a
  // forged one. Whatever is returned must be the signed element, and the
  // caller reads only that.
  it("refuses a signature detached from the element it references", () => {
    const key = generateKeyMaterial();
    // Lift the Signature out of the Assertion and into the Response. The bytes
    // it covers are unchanged, so it still verifies — only the parent check
    // catches this.
    const signed = signXml(ASSERTION(), key);
    const signature =
      /<[^>]*Signature[\s\S]*<\/[^>]*Signature>/.exec(signed)?.[0] ?? "";
    const wrapped = RESPONSE(`${signed.replace(signature, "")}${signature}`);
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/does not envelope/i);
  });

  it("refuses a signature with an empty URI that sits below the root", () => {
    const key = generateKeyMaterial();
    // An empty URI signs the whole document, so the element it references is
    // the root. Placing the Signature inside the Assertion still verifies —
    // the enveloped-signature transform removes it before digesting, wherever
    // it sits — but its parent is then the Assertion, not the root. Only the
    // enveloping check catches that, and an early return for the empty-URI
    // case is exactly how the check stops applying.
    //
    // Rewriting URI in an already-signed document would not do: URI lives
    // inside SignedInfo, which is itself signed, so the edit breaks
    // SignatureValue and the test would fail at "does not verify" instead —
    // passing for the wrong reason, or rather failing for it.
    const unsigned = RESPONSE(ASSERTION());
    const sig = new SignedXml({
      privateKey: key.privateKeyPem,
      publicCert: key.certificatePem,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    });
    sig.addReference({
      xpath: "/*",
      uri: "",
      // Without this, xml-crypto calls ensureHasId() on the referenced node
      // and overwrites `uri` with "#<id>" — the fixture would be an ordinary
      // reference and would test nothing about the empty-URI path. Verified
      // against the installed xml-crypto, whose signed-xml.js branches on
      // isEmptyUri at exactly that point.
      isEmptyUri: true,
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      transforms: [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
      ],
    });
    sig.computeSignature(unsigned, {
      location: {
        reference: "//*[local-name(.)='Assertion']",
        action: "append",
      },
    });
    const wrapped = sig.getSignedXml();

    // The fixture must be what it claims before it can prove anything: a setup
    // that silently produced a different document would pass or fail for a
    // reason nobody chose.
    expect(wrapped).toContain('URI=""');

    // And it must verify, or this tests the signature check rather than the
    // enveloping one. Measured against the installed xml-crypto: an empty-URI
    // signature nested inside the Assertion returns true here, because the
    // enveloped-signature transform removes it wherever it sits. If a future
    // version stops verifying it, this line fails with a clear reason instead
    // of the case below passing for the wrong one.
    const probe = new SignedXml({ publicCert: key.certificatePem });
    probe.loadSignature(
      parse(wrapped).getElementsByTagNameNS(
        "http://www.w3.org/2000/09/xmldsig#",
        "Signature",
      )[0] as never,
    );
    expect(probe.checkSignature(wrapped)).toBe(true);

    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/does not envelope/i);
  });

  it("refuses a signature carrying more than one reference", () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const reference =
      /<[^>]*Reference[\s\S]*?<\/[^>]*Reference>/.exec(signed)?.[0] ?? "";
    const wrapped = RESPONSE(
      signed.replace(reference, `${reference}${reference}`),
    );
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/exactly one is required/i);
  });

  it("returns the signed assertion, not the forged sibling", () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION("_real"), key);
    const forged = ASSERTION("_forged").replace("mock-idp", "attacker");
    const wrapped = RESPONSE(`${forged}${signed}`);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [
      key.certificatePem,
    ]);
    expect(element.getAttribute("ID")).toBe("_real");
  });

  // Identity providers often sign both levels — Keycloak does by default. The
  // Assertion is signed first, then the Response around it, with the
  // Response's Signature as its first child (this fixture has no Response
  // Issuer; with one, the Signature goes right after it).
  const doubleSigned = (
    assertionKey: ReturnType<typeof generateKeyMaterial>,
    responseKey = assertionKey,
  ) =>
    signXml(RESPONSE(signXml(ASSERTION(), assertionKey)), responseKey, {
      referenceXPath: "//*[local-name(.)='Response']",
      location: { reference: "//*[local-name(.)='Response']", action: "prepend" },
    });

  it("returns both elements when the Response and the Assertion are signed", () => {
    const key = generateKeyMaterial();
    const xml = doubleSigned(key);
    const covered = resolveSignedElements(xml, parse(xml), [key.certificatePem]);
    expect(covered.map((e) => e.localName).sort()).toEqual([
      "Assertion",
      "Response",
    ]);
  });

  it("refuses the document when one of two signatures does not verify", () => {
    const key = generateKeyMaterial();
    const untrusted = generateKeyMaterial();
    // The Assertion is signed by a trusted key, the Response by another: the
    // Assertion alone would pass, and the document must still be refused.
    const xml = doubleSigned(key, untrusted);
    expect(() =>
      resolveSignedElements(xml, parse(xml), [key.certificatePem]),
    ).toThrow(/does not verify against any configured certificate/);
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/validation/signedNode.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/validation/signedNode.ts`**

```ts
/**
 * Which element the signature covers.
 *
 * Not "is there a valid signature" — that question has a true answer in a
 * document built for a wrapping attack, where a genuinely signed fragment sits
 * beside a forged one. The caller must read the element this returns and no
 * other.
 */

import { X509Certificate } from "node:crypto";
import type { Document, Element, Node as XmlNode } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";

const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

/**
 * PEM in, PEM out; bare base64 DER gets its armour — and the result is proved
 * to be a certificate before anything uses it.
 *
 * The spec promises `idpCertificates` accepts either, and a consumer copying
 * `<X509Certificate>` out of identity-provider metadata has bare base64 DER in
 * their hand — the armour is not in the metadata. `xml-crypto` accepts only
 * PEM or a Buffer: measured, a bare base64 certificate makes OpenSSL throw
 * `DECODER routines::unsupported`, while the same bytes re-armoured verify.
 *
 * Left unnormalised that throw would be swallowed by the verification loop and
 * reported as "the signature does not verify against any configured
 * certificate" — blaming the assertion for the consumer's formatting.
 *
 * Base64 syntax alone does not make a string a certificate: `"AAAA"` passes
 * the character class, armours cleanly, and fails only inside OpenSSL, which
 * lands back at the same misleading message. So the armoured result is parsed
 * with `node:crypto`'s `X509Certificate`, which rejects `"AAAA"` with
 * `asn1 encoding routines::wrong tag` — measured, not assumed. Called once per
 * certificate at construction, so the cost never falls on a login.
 */
export function toPem(certificate: string): string {
  const trimmed = certificate.trim();
  const pem = trimmed.includes("-----BEGIN")
    ? trimmed
    : (() => {
        const body = trimmed.replace(/\s+/g, "");
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
          throw new Error(
            "a configured certificate is neither PEM nor base64 DER",
          );
        }
        const wrapped = body.replace(/(.{64})/g, "$1\n").trim();
        return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
      })();

  try {
    new X509Certificate(pem);
  } catch (error) {
    throw new Error(
      `a configured certificate is not a valid X.509 certificate: ${(error as Error).message}`,
    );
  }
  return pem;
}

/**
 * Verifies every signature in the document against the certificates and
 * returns the elements they reference. Throws when there is no signature, or
 * when any one of them fails a rule below.
 *
 * Several signatures are normal — identity providers often sign the Response
 * and the Assertion both. Each is held to every rule on its own; the caller
 * then takes the element it requires from the returned list.
 */
export function resolveSignedElements(
  xml: string,
  doc: Document,
  certificates: readonly string[],
): Element[] {
  const signatures = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
  if (signatures.length === 0) {
    throw new Error("the document carries no signature");
  }
  // Every signature is held to every rule: an extra signature that fails is
  // something that should not be there, not noise to skip. Two verifying
  // signatures over one element cannot occur — under the enveloped-signature
  // transform the later one changes the bytes the earlier one's digest
  // covered — so no separate rule guards against it.
  const covered: Element[] = [];
  for (let i = 0; i < signatures.length; i++) {
    covered.push(resolveOne(xml, doc, signatures[i], certificates));
  }
  return covered;
}

/** One signature: verified, exactly one reference, enveloped by its target. */
function resolveOne(
  xml: string,
  doc: Document,
  signatureNode: Element,
  certificates: readonly string[],
): Element {
  let verified = false;
  for (const certificate of certificates) {
    // Already normalised and proved at construction, so a throw here really
    // is a bad signature rather than a formatting mistake.
    const verifier = new SignedXml({ publicCert: certificate });
    verifier.loadSignature(signatureNode as unknown as XmlNode);
    try {
      // Returns false for a digest mismatch and throws when the signature
      // value itself fails. Both mean "not this certificate".
      if (verifier.checkSignature(xml)) {
        verified = true;
        break;
      }
    } catch {
      // Try the next certificate in the rotation list.
    }
  }
  if (!verified) {
    throw new Error(
      "the signature does not verify against any configured certificate",
    );
  }

  // The signature is valid; now find what it actually covers. Exactly one
  // reference: two would be two candidate answers to "what is signed", the
  // ambiguity this module exists to remove.
  const references = signatureNode.getElementsByTagNameNS(DSIG_NS, "Reference");
  if (references.length !== 1) {
    throw new Error(
      `the signature carries ${references.length} references; exactly one is required`,
    );
  }
  const uri = references[0].getAttribute("URI") ?? "";
  let referenced: Element | null = null;

  if (uri === "") {
    // An empty URI signs the whole document. It must still satisfy the
    // enveloping rule below — returning early here is exactly how a detached
    // signature with an empty reference walks straight past that rule.
    referenced = doc.documentElement as unknown as Element;
  } else if (!uri.startsWith("#")) {
    throw new Error(
      `the signature reference is not a same-document URI: ${uri}`,
    );
  } else {
    const id = uri.slice(1);
    const elements = doc.getElementsByTagName("*");
    for (let i = 0; i < elements.length; i++) {
      if (elements[i].getAttribute("ID") === id) {
        referenced = elements[i] as unknown as Element;
        break;
      }
    }
  }

  if (!referenced) {
    throw new Error(
      `the signature references ${uri}, which is not in the document`,
    );
  }

  // The enveloped signature must sit inside the element it references. A
  // signature moved elsewhere stays cryptographically valid over the bytes it
  // covers, so the maths alone will not catch it — this comparison is what
  // does. It is the check @node-saml/node-saml makes, and the one whose
  // absence made every response @mcp-abap-adt/auth-mocks produced
  // unacceptable to a real library until it was fixed there.
  if ((signatureNode.parentNode as unknown as Element | null) !== referenced) {
    throw new Error(
      "the signature is not inside the element it references, so it does not envelope it",
    );
  }

  return referenced;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/validation/signedNode.test.ts
```

Expected: PASS, fourteen cases. RSA key generation makes this suite slower than the others; that is expected.

If the detached-signature fixture verifies where you expected refusal, or fails
to verify at all because lifting the element changed the canonicalised bytes,
**say so and reshape the fixture** rather than deleting the case. The rule it
protects is the one the whole design rests on. Moving the `Signature` to a
sibling position inside the same parent is the other shape worth trying.

- [ ] **Step 5: Prove the rules**

If the double-signed fixture fails to verify, check which `Signature`
`xml-crypto`'s enveloped-signature transform removes: an implementation that
removes the first `Signature` it finds under the referenced element, rather
than the one being checked, breaks on nested signatures. Measure it — against
this fixture and against a double-signed response from the stand's Keycloak —
and report; do not weaken the every-signature rule to get past it.

Seven mutations, one at a time — the five below, and two for several
signatures: resolve only `signatures[0]` (the one-of-two case must go red),
and return only the first covered element (the both-levels case must go red):

1. Return `doc.documentElement` unconditionally instead of resolving the reference — `returns the signed assertion, not the forged sibling` must go red.
2. Delete the `if (signatures.length === 0)` guard — `refuses a document with no signature` must go red. Note what it becomes: a different error, or a crash. Either is red; say which you saw.
3. Treat a thrown `checkSignature` as success — `refuses a signature made with a key we do not trust` must go red while `refuses content altered after signing` stays red for its own reason, the digest mismatch that returns `false`. Report both.
4. Delete the `parentNode !== referenced` comparison — `refuses a signature detached from the element it references` must go red. If it stays green the fixture is not actually detached; say so rather than moving on.
5. Change `references.length !== 1` to `references.length === 0` — `refuses a signature carrying more than one reference` must go red.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add src/validation/signedNode.ts src/__tests__/validation/signedNode.test.ts
git commit -m "feat: resolve which element a valid signature covers"
```

---

### Task 7: The replay store

**Files:**

- Create: `src/validation/inMemoryReplayStore.ts`
- Test: `src/__tests__/validation/inMemoryReplayStore.test.ts`

**Interfaces:**

- Consumes: `IAssertionReplayStore`, `AssertionReplayKey` from Task 1.
- Produces:
  - `createInMemoryReplayStore(): IAssertionReplayStore`
  - `defaultReplayStore: IAssertionReplayStore` — the module-level instance the shipped validator uses when the consumer supplies none.

**The default is process-wide, and that is deliberate.** A store held per provider instance is no defence: replaying an assertion would need only a second provider constructed in the same process. `createInMemoryReplayStore()` exists so a test — or a consumer wanting isolation — gets its own.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/validation/inMemoryReplayStore.test.ts`:

```ts
import { describe, expect, it } from "@jest/globals";
import { createInMemoryReplayStore } from "../../validation/inMemoryReplayStore";

const future = () => new Date(Date.now() + 60_000);

describe("createInMemoryReplayStore", () => {
  it("records an unseen key and reports it as new", async () => {
    const store = createInMemoryReplayStore();
    expect(
      await store.recordIfUnseen(
        { issuer: "idp", assertionId: "_a" },
        future(),
      ),
    ).toBe(true);
  });

  it("reports the second sighting of the same key as a replay", async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: "idp", assertionId: "_a" };
    await store.recordIfUnseen(key, future());
    expect(await store.recordIfUnseen(key, future())).toBe(false);
  });

  // The reason the key is a pair: two identity providers may legitimately mint
  // the same ID, and refusing the second is a working login broken, not an
  // attack stopped.
  it("keeps two issuers apart when they mint the same ID", async () => {
    const store = createInMemoryReplayStore();
    expect(
      await store.recordIfUnseen(
        { issuer: "a", assertionId: "_same" },
        future(),
      ),
    ).toBe(true);
    expect(
      await store.recordIfUnseen(
        { issuer: "b", assertionId: "_same" },
        future(),
      ),
    ).toBe(true);
  });

  it("forgets an entry once its retention has passed", async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: "idp", assertionId: "_a" };
    await store.recordIfUnseen(key, new Date(Date.now() - 1));
    expect(await store.recordIfUnseen(key, future())).toBe(true);
  });

  // Concurrency: a check followed by a separate write is the race a replay
  // exploits, so exactly one of two simultaneous calls may be told `true`.
  it("lets only one of two simultaneous calls record the key", async () => {
    const store = createInMemoryReplayStore();
    const key = { issuer: "idp", assertionId: "_a" };
    const results = await Promise.all([
      store.recordIfUnseen(key, future()),
      store.recordIfUnseen(key, future()),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("gives each store its own memory", async () => {
    const key = { issuer: "idp", assertionId: "_a" };
    await createInMemoryReplayStore().recordIfUnseen(key, future());
    expect(
      await createInMemoryReplayStore().recordIfUnseen(key, future()),
    ).toBe(true);
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/validation/inMemoryReplayStore.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/validation/inMemoryReplayStore.ts`**

```ts
/**
 * Remembering assertions so a replay is refused.
 *
 * In memory, and therefore per process. That is honest rather than sufficient:
 * a deployment running several processes needs a shared store, which is why
 * the interface exists at all. What this must not be is per provider instance —
 * a store an attacker escapes by causing a second provider to be constructed
 * is no store.
 *
 * Pruning is lazy, on access, so nothing here holds a timer and nothing needs
 * disposing.
 */

import type {
  AssertionReplayKey,
  IAssertionReplayStore,
} from "@mcp-abap-adt/interfaces-auth";

const compositeKey = (key: AssertionReplayKey): string =>
  // The issuer is length-prefixed so that two different pairs cannot collide
  // by putting the separator inside an identifier.
  `${key.issuer.length}:${key.issuer}:${key.assertionId}`;

/** A store of its own, for a test or a consumer wanting isolation. */
export function createInMemoryReplayStore(): IAssertionReplayStore {
  const seen = new Map<string, number>();

  return {
    async recordIfUnseen(key, retainUntil) {
      const now = Date.now();

      // Lazy prune: drop everything whose retention has passed, so the map
      // cannot grow without bound and no timer is needed.
      for (const [existing, until] of seen) {
        if (until <= now) seen.delete(existing);
      }

      const composite = compositeKey(key);
      if (seen.has(composite)) return false;

      // Nothing awaits between the check and the write, so this is atomic
      // against other callers on the same event loop. A shared-store
      // implementation must achieve the same with a conditional write.
      seen.set(composite, retainUntil.getTime());
      return true;
    },
  };
}

/**
 * The store the shipped validator uses when the consumer supplies none.
 *
 * Module-level, so every default validator in the process shares it.
 */
export const defaultReplayStore: IAssertionReplayStore =
  createInMemoryReplayStore();
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/validation/inMemoryReplayStore.test.ts
```

Expected: PASS, six cases.

- [ ] **Step 5: Prove the rules**

Three mutations, one at a time:

1. Key on `key.assertionId` alone — `keeps two issuers apart when they mint the same ID` must go red.
2. Delete the pruning loop — `forgets an entry once its retention has passed` must go red.
3. Insert `await Promise.resolve();` between the `seen.has` check and `seen.set` — `lets only one of two simultaneous calls record the key` must go red. This is the race the interface's doc comment warns about, made real.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add src/validation/inMemoryReplayStore.ts src/__tests__/validation/inMemoryReplayStore.test.ts
git commit -m "feat: an in-memory replay store, atomic and namespaced by issuer"
```

---

### Task 8: The error

**Files:**

- Create: `src/errors/AssertionValidationError.ts`
- Modify: `src/errors/TokenProviderErrors.ts` (re-export only, following the file's existing pattern)
- Test: `src/__tests__/errors/AssertionValidationError.test.ts`

**Interfaces:**

- Produces:
  - `type AssertionCheck` — a union of fourteen names (the spec's twelve rows, with `document`, `duplicateId` and `signedNode` separated because they fail for different reasons): `'document' | 'duplicateId' | 'signature' | 'signedNode' | 'status' | 'assertionId' | 'issuer' | 'conditions' | 'notBefore' | 'notOnOrAfter' | 'audience' | 'bearerConfirmation' | 'destination' | 'replay'`.
  - `class AssertionValidationError extends TokenProviderError` with `readonly check: AssertionCheck`.

**Why a discriminable field rather than a message.** A consumer needs to tell "your identity provider declined the login" from "this response was not addressed to us" — the first is something to show a user, the second is something to alert on. Parsing a message to learn which is a contract nobody wrote down.

- [ ] **Step 1: Read the existing error file**

```bash
sed -n '1,40p' src/errors/TokenProviderErrors.ts
```

Follow whatever `TokenProviderError` subclasses already do for `code`, `name` and `cause`. Do not invent a second convention.

- [ ] **Step 2: Write the failing test**

`src/__tests__/errors/AssertionValidationError.test.ts`:

```ts
import { describe, expect, it } from "@jest/globals";
import { AssertionValidationError } from "../../errors/AssertionValidationError";
import { TokenProviderError } from "../../errors/TokenProviderErrors";

describe("AssertionValidationError", () => {
  it("is a TokenProviderError", () => {
    const error = new AssertionValidationError("status", "the IdP declined");
    expect(error).toBeInstanceOf(TokenProviderError);
    expect(error).toBeInstanceOf(Error);
  });

  it("carries the failed check as a field, not only in the message", () => {
    const error = new AssertionValidationError(
      "audience",
      "not addressed to us",
    );
    expect(error.check).toBe("audience");
    expect(error.message).toContain("not addressed to us");
  });

  it("keeps a stack", () => {
    expect(
      new AssertionValidationError("replay", "seen before").stack,
    ).toBeTruthy();
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

```bash
npm test -- src/__tests__/errors/AssertionValidationError.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 4: Implement**

```ts
/**
 * An assertion was refused, and by which check.
 *
 * The check is a field rather than something to read out of the message: a
 * consumer telling "your identity provider declined" from "this was not
 * addressed to us" should not be parsing prose to do it.
 */

import { ASSERTION_ERROR_CODES } from "@mcp-abap-adt/interfaces-auth";
import { TokenProviderError } from "./TokenProviderErrors";

/** The checks the shipped validator performs, in the order it performs them. */
export type AssertionCheck =
  | "document"
  | "duplicateId"
  | "signature"
  | "signedNode"
  | "status"
  | "assertionId"
  | "issuer"
  | "conditions"
  | "notBefore"
  | "notOnOrAfter"
  | "audience"
  | "bearerConfirmation"
  | "destination"
  | "replay";

export class AssertionValidationError extends TokenProviderError {
  readonly check: AssertionCheck;

  constructor(check: AssertionCheck, message: string) {
    super(message, ASSERTION_ERROR_CODES.VALIDATION_ERROR);
    this.name = "AssertionValidationError";
    this.check = check;
    // Every sibling in TokenProviderErrors.ts does this; without it
    // `instanceof` fails across a compiled boundary.
    Object.setPrototypeOf(this, AssertionValidationError.prototype);
  }
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
npm test -- src/__tests__/errors/AssertionValidationError.test.ts
```

Expected: PASS, three cases.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add src/errors/AssertionValidationError.ts src/__tests__/errors/AssertionValidationError.test.ts
git commit -m "feat: an assertion refusal that names the check that failed"
```

---

### Task 9: The two shipped validators

**Files:**

- Create: `src/validation/assertionValidator.ts`
- Test: `src/__tests__/validation/assertionValidator.test.ts`

**Interfaces:**

- Consumes: `parseXsdDateTime` (Task 4); `findDuplicateId`, `readRequiredId` (Task 5); `resolveSignedElements` (Task 6); `defaultReplayStore`, `createInMemoryReplayStore` (Task 7); `AssertionValidationError`, `AssertionCheck` (Task 8); `IAssertionValidator`, `AssertionContext`, `ValidatedAssertion`, `IAssertionReplayStore` (Task 1).
- Produces:

```ts
/** Shared by both shipped validators, so switching is one identifier. */
export interface ShippedValidatorOptions {
  readonly idpCertificates: readonly string[];
  readonly clockSkewMs?: number;
  readonly replayStore?: IAssertionReplayStore;
}

/**
 * Requires the signature to cover the `Response`. All checks are then
 * controls, because every field they read is inside the signature. This is
 * `Saml2PureProvider`'s default: what it builds when the consumer configures no
 * validator. `Saml2BearerProvider` defaults to `createSignedAssertionValidator`.
 */
export function createSignedResponseValidator(
  options: ShippedValidatorOptions,
): IAssertionValidator;

/**
 * Accepts a signature covering the `Assertion`. Does **not** read `Status`,
 * `Response/Issuer` or `Destination` — not "reads them weakly". A check
 * performed on a field an attacker controls reads, in the code and in the
 * logs, as though something was verified.
 */
export function createSignedAssertionValidator(
  options: ShippedValidatorOptions,
): IAssertionValidator;
```

Neither takes the placement as a parameter: a `placement` option would be the
validator-with-a-mode the spec's "Two validators" section exists to remove, and
it would hide the choice from anyone reading the call site.

**What the signature actually protects, and what it does not.**

This restates the spec's "What each placement actually protects" — a section
added to the spec on 2026-08-30 precisely because this plan had adopted the
reading without it. If that section has not been re-approved, stop: the plan is
ahead of its spec, and that is the owner's gate to pass, not mine.

The spec allows the signature on the `Response` **or** on the `Assertion`, and
those two placements do not protect the same fields. Three checks read from the
`Response`: `Status`, `Response/Issuer` and `Destination`. When only the
assertion is signed, all three sit outside the signature and an attacker who
can deliver a response at all can set them to whatever we expect.

Each validator reads only what its own signature covers, which is what keeps
"everything is read from the signed element" true for both. What differs is
which fields each one reads at all:

| Read from                                                                                                           | Signature on `Response` | Signature on `Assertion` only |
| ------------------------------------------------------------------------------------------------------------------- | ----------------------- | ----------------------------- |
| Everything inside the assertion — `Issuer`, `Conditions`, `Audience`, the bearer confirmation, the assertion's `ID` | protected               | protected                     |
| `Status`, `Response/Issuer`, `Destination`                                                                          | read, and controls      | **not read at all**           |

The assertion-only flow is not thereby unsafe, and the reason is worth stating
because it is not obvious: **a declined login carries no assertion.** An
identity provider that refuses does not mint one, so an attacker who flips
`Status` from a failure to `Success` still has no validly signed assertion to
put underneath it, and signature resolution fails before `Status` is ever read.
What establishes success in that flow is the signed assertion satisfying every
assertion-level check — not the `Status` element.

The three checks belong to the signed-Response validator and to it alone. There
they are controls, because the fields are inside the signature. The
assertion-only validator does not perform them in any form — not as
misconfiguration checks, not as warnings. A check run against a field an
attacker sets reads, in the code and in the logs, as though something had been
verified, and that is worse than an absence anyone can see.

A consumer who needs `Status`, `Destination` and the response issuer verified
must therefore require their identity provider to sign the `Response` and use
the signed-Response validator — `Saml2PureProvider`'s default; with
`Saml2BearerProvider`, whose default is the assertion-only one, by passing it as
`assertionValidator`. The README says so in Task 13.

**This is the largest file in the plan, and its shape is fixed by the spec's check table.** Implement the checks in the table's order, each throwing `AssertionValidationError` with its own `check` value and its own message. No two messages may share a distinguishing fragment: a test asserting `/Destination/` must not be satisfiable by the `Recipient` refusal.

The structure below gives the skeleton and every rule with its exact condition. Write the body from it; the tests in Step 1 pin every branch.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/validation/assertionValidator.test.ts`. The fixtures are built here rather than taken from the mock, because the mock corrupts values and never removes them, and half these rules are about removal:

```ts
import { describe, expect, it } from "@jest/globals";
import { generateKeyMaterial, signXml } from "@mcp-abap-adt/auth-mocks";
import { createInMemoryReplayStore } from "../../validation/inMemoryReplayStore";
import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
} from "../../validation/assertionValidator";

const KEY = generateKeyMaterial();
const ACS = "http://localhost:61001/acs";
const ISSUER = "urn:mock:idp";
const AUDIENCE = "urn:mock:sp";
const REQUEST_ID = "_req1";

const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

/**
 * One valid response, with named holes so a test can remove or alter exactly
 * one thing. Every parameter defaults to the correct value.
 */
function buildResponse(
  o: {
    status?: string;
    assertionId?: string | null;
    issuer?: string | null;
    responseIssuer?: string | null;
    conditions?: string | null;
    notBefore?: string | null;
    notOnOrAfter?: string | null;
    audiences?: string[][] | null;
    confirmations?: string[] | null;
    destination?: string | null;
    /**
     * Defaults to `"response"`, because the signed-Response validator — this
     * suite's main subject, and `Saml2PureProvider`'s default — requires it.
     * A fixture signing the assertion while the test runs the signed-Response
     * validator fails at `signedNode` before reaching the check it was written
     * for — every negative case would then pass for the wrong reason.
     */
    signWhat?: "assertion" | "response";
  } = {},
): string {
  const status = o.status ?? "urn:oasis:names:tc:SAML:2.0:status:Success";
  const assertionId = o.assertionId === null ? "" : (o.assertionId ?? "_a1");
  const idAttr = o.assertionId === null ? "" : ` ID="${assertionId}"`;
  const issuer =
    o.issuer === null ? "" : `<saml:Issuer>${o.issuer ?? ISSUER}</saml:Issuer>`;
  const responseIssuer =
    o.responseIssuer === undefined
      ? ""
      : o.responseIssuer === null
        ? ""
        : `<saml:Issuer>${o.responseIssuer}</saml:Issuer>`;
  const audiences =
    o.audiences === null
      ? ""
      : (o.audiences ?? [[AUDIENCE]])
          .map(
            (group) =>
              `<saml:AudienceRestriction>${group
                .map((a) => `<saml:Audience>${a}</saml:Audience>`)
                .join("")}</saml:AudienceRestriction>`,
          )
          .join("");
  const conditions =
    o.conditions === null
      ? ""
      : `<saml:Conditions${o.notBefore === null ? "" : ` NotBefore="${o.notBefore ?? iso(-60_000)}"`}` +
        `${o.notOnOrAfter === null ? "" : ` NotOnOrAfter="${o.notOnOrAfter ?? iso(300_000)}"`}>` +
        `${audiences}</saml:Conditions>`;
  const confirmations =
    o.confirmations === null
      ? ""
      : (
          o.confirmations ?? [
            `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
              `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
              `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`,
          ]
        ).join("");

  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"${idAttr}>` +
    `${issuer}<saml:Subject><saml:NameID>mock-user</saml:NameID>${confirmations}</saml:Subject>` +
    `${conditions}</saml:Assertion>`;

  const destination =
    o.destination === null ? "" : ` Destination="${o.destination ?? ACS}"`;

  if ((o.signWhat ?? "response") === "assertion") {
    const signed = signXml(assertion, KEY);
    return (
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1"${destination}>` +
      `${responseIssuer}<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
      `${signed}</samlp:Response>`
    );
  }
  const response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1"${destination}>` +
    `${responseIssuer}<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
    `${assertion}</samlp:Response>`;
  // Where SAML Core's ResponseType puts it: right after the Response's own
  // Issuer when there is one, otherwise first — Issuer is optional and nothing
  // else may precede the Signature. The default fixture has no Response
  // Issuer, so a location naming it would find nothing and signXml would
  // throw. Without any `location` the Signature would follow the Assertion.
  return signXml(response, KEY, {
    referenceXPath: "//*[local-name(.)='Response']",
    location: responseIssuer
      ? {
          reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
          action: "after",
        }
      : { reference: "//*[local-name(.)='Response']", action: "prepend" },
  });
}

const encode = (xml: string) => Buffer.from(xml, "utf8").toString("base64");

const context = {
  expectedInResponseTo: REQUEST_ID,
  audience: AUDIENCE,
  acsUrl: ACS,
  expectedIssuer: ISSUER,
};

/** Saml2PureProvider's default: requires the Response to be signed. */
const validator = (over: Partial<{ clockSkewMs: number }> = {}) =>
  createSignedResponseValidator({
    idpCertificates: [KEY.certificatePem],
    replayStore: createInMemoryReplayStore(),
    ...over,
  });

/** The other one: accepts a signature over the Assertion. */
const assertionValidator = (over: Partial<{ clockSkewMs: number }> = {}) =>
  createSignedAssertionValidator({
    idpCertificates: [KEY.certificatePem],
    replayStore: createInMemoryReplayStore(),
    ...over,
  });

describe("the signed-Response validator (Saml2PureProvider's default)", () => {
  it("refuses a malformed certificate at construction, not at login", () => {
    expect(() =>
      createSignedResponseValidator({ idpCertificates: ["AAAA"] }),
    ).toThrow(/not a valid X.509 certificate/i);
  });

  // A bad entry must not hide a good one: normalising the whole list up front
  // is what stops the rotation loop aborting on its first element.
  it("refuses a list whose first entry is malformed, whatever follows", () => {
    expect(() =>
      createSignedResponseValidator({
        idpCertificates: ["AAAA", KEY.certificatePem],
      }),
    ).toThrow(/not a valid X.509 certificate/i);
  });

  it("accepts a well-formed assertion and reports what the flow needs", async () => {
    const result = await validator().validate(encode(buildResponse()), context);
    expect(result.assertionId).toBe("_a1");
    // signedXml is the element this validator required — the Response, which
    // carries Status. Without this the assertion-only case below is the only
    // one pinning signedXml, and an implementation that always returned the
    // Assertion would satisfy the suite.
    expect(result.signedXml).toContain("samlp:Response");
    expect(result.signedXml).toContain("samlp:Status");
    expect(result.issuer).toBe(ISSUER);
    expect(result.nameId).toBe("mock-user");
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("accepts an assertion-signed document through the other validator", async () => {
    const result = await assertionValidator().validate(
      encode(buildResponse({ signWhat: "assertion" })),
      context,
    );
    expect(result.assertionId).toBe("_a1");
  });

  // Each validator refuses the placement it was not built for. This is the
  // refusal that makes shipping two meaningful rather than decorative.
  it("the signed-Response validator refuses an assertion-signed document", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ signWhat: "assertion" })),
        context,
      ),
    ).rejects.toMatchObject({ check: "signedNode" });
  });

  it("the assertion-only validator refuses a response-signed document", async () => {
    await expect(
      assertionValidator().validate(
        encode(buildResponse({ signWhat: "response" })),
        context,
      ),
    ).rejects.toMatchObject({ check: "signedNode" });
  });

  // The three fields it does not read. Each is a refusal for the
  // signed-Response validator and an acceptance here, and both halves need
  // pinning: a validator that silently dropped a check and one documented as
  // not performing it look identical from outside.
  it("the assertion-only validator accepts a failed Status", async () => {
    const result = await assertionValidator().validate(
      encode(
        buildResponse({
          signWhat: "assertion",
          status: "urn:oasis:names:tc:SAML:2.0:status:Responder",
        }),
      ),
      context,
    );
    expect(result.assertionId).toBe("_a1");
  });

  it("the assertion-only validator accepts a wrong Destination", async () => {
    const result = await assertionValidator().validate(
      encode(
        buildResponse({
          signWhat: "assertion",
          destination: "http://elsewhere/acs",
        }),
      ),
      context,
    );
    expect(result.assertionId).toBe("_a1");
  });

  it("the assertion-only validator accepts a missing Destination", async () => {
    const result = await assertionValidator().validate(
      encode(buildResponse({ signWhat: "assertion", destination: null })),
      context,
    );
    expect(result.assertionId).toBe("_a1");
  });

  // signedXml is the signed element, not the response — the difference
  // between "signed" and "arrived".
  it("reports the signed element separately from what arrived", async () => {
    const result = await assertionValidator().validate(
      encode(buildResponse({ signWhat: "assertion" })),
      context,
    );
    expect(result.signedXml).toContain("Assertion");
    expect(result.signedXml).not.toContain("samlp:Status");
    expect(Buffer.from(result.raw, "base64").toString("utf8")).toContain(
      "samlp:Status",
    );
  });

  it("refuses a Status that is not Success", async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            status: "urn:oasis:names:tc:SAML:2.0:status:Responder",
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({ check: "status" });
  });

  it("refuses an assertion with no ID", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ assertionId: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: "assertionId" });
  });

  it("refuses an assertion with no Issuer", async () => {
    await expect(
      validator().validate(encode(buildResponse({ issuer: null })), context),
    ).rejects.toMatchObject({ check: "issuer" });
  });

  it("refuses an Issuer that is not the one configured", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ issuer: "urn:someone:else" })),
        context,
      ),
    ).rejects.toMatchObject({ check: "issuer" });
  });

  it("refuses a Response Issuer disagreeing with the Assertion Issuer", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ responseIssuer: "urn:someone:else" })),
        context,
      ),
    ).rejects.toMatchObject({ check: "issuer" });
  });

  it("refuses an assertion with no Conditions", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ conditions: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: "conditions" });
  });

  it("refuses an assertion with no NotOnOrAfter", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: "notOnOrAfter" });
  });

  it("refuses a NotOnOrAfter that is not a valid xsd:dateTime", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: "2026-02-30T00:00:00Z" })),
        context,
      ),
    ).rejects.toMatchObject({ check: "notOnOrAfter" });
  });

  it("refuses an expired assertion", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: iso(-1000) })),
        context,
      ),
    ).rejects.toMatchObject({ check: "notOnOrAfter" });
  });

  it("accepts an expired assertion inside the configured skew", async () => {
    const result = await validator({ clockSkewMs: 60_000 }).validate(
      encode(buildResponse({ notOnOrAfter: iso(-1000) })),
      context,
    );
    expect(result.assertionId).toBe("_a1");
  });

  it("refuses an assertion that is not yet valid", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notBefore: iso(300_000) })),
        context,
      ),
    ).rejects.toMatchObject({ check: "notBefore" });
  });

  it("refuses an assertion with no AudienceRestriction", async () => {
    await expect(
      validator().validate(encode(buildResponse({ audiences: null })), context),
    ).rejects.toMatchObject({ check: "audience" });
  });

  it("refuses an audience that is not ours", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ audiences: [["urn:someone:else"]] })),
        context,
      ),
    ).rejects.toMatchObject({ check: "audience" });
  });

  it("accepts our audience among alternatives inside one restriction", async () => {
    const result = await validator().validate(
      encode(buildResponse({ audiences: [["urn:someone:else", AUDIENCE]] })),
      context,
    );
    expect(result.assertionId).toBe("_a1");
  });

  // AND across restrictions: one permitting and one excluding must be refused.
  // Implemented as "our audience appears somewhere", this passes.
  it("refuses when a second restriction excludes us", async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({ audiences: [[AUDIENCE], ["urn:someone:else"]] }),
        ),
        context,
      ),
    ).rejects.toMatchObject({ check: "audience" });
  });

  it("refuses when there is no bearer confirmation at all", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ confirmations: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: "bearerConfirmation" });
  });

  // Option B. Each case is load-bearing on its own half of the rule: without
  // the `hasAttribute` branch the second goes green wrongly; without the
  // equality the third does.
  const unsolicitedConfirmation =
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData Recipient="${ACS}" ` +
    `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`;
  // The same context with no expected request ID — an IdP-initiated login.
  const { expectedInResponseTo: _requestId, ...unsolicitedContext } = context;

  it("accepts an unsolicited assertion when no request ID is expected", async () => {
    const result = await validator().validate(
      encode(buildResponse({ confirmations: [unsolicitedConfirmation] })),
      unsolicitedContext,
    );
    expect(result.assertionId).toBe("_a1");
  });

  it("refuses an InResponseTo when no request ID is expected", async () => {
    // The ordinary valid fixture, whose confirmation answers REQUEST_ID.
    await expect(
      validator().validate(encode(buildResponse()), unsolicitedContext),
    ).rejects.toMatchObject({ check: "bearerConfirmation" });
  });

  it("refuses a missing InResponseTo when one is expected", async () => {
    // Absence never satisfies an expectation.
    await expect(
      validator().validate(
        encode(buildResponse({ confirmations: [unsolicitedConfirmation] })),
        context,
      ),
    ).rejects.toMatchObject({ check: "bearerConfirmation" });
  });

  it("accepts a response signed at both levels, under either validator", async () => {
    // Many identity providers sign the Response and the Assertion both: take
    // the assertion-signed fixture and sign the Response around it, the
    // Signature first since this fixture has no Response Issuer.
    const both = signXml(buildResponse({ signWhat: "assertion" }), KEY, {
      referenceXPath: "//*[local-name(.)='Response']",
      location: { reference: "//*[local-name(.)='Response']", action: "prepend" },
    });
    expect((await validator().validate(encode(both), context)).assertionId).toBe("_a1");
    expect(
      (await assertionValidator().validate(encode(both), context)).assertionId,
    ).toBe("_a1");
  });

  // The saml2-bearer grant exchanges an Assertion; 3.0.0 accepts one bare.
  const bareAssertion = () =>
    /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(
      buildResponse({ signWhat: "assertion" }),
    )?.[0] ?? "";

  it("the assertion-only validator accepts a bare signed Assertion", async () => {
    const result = await assertionValidator().validate(
      Buffer.from(bareAssertion()).toString("base64url"),
      context,
    );
    expect(result.assertionId).toBe("_a1");
  });

  it("the signed-Response validator refuses a bare Assertion", async () => {
    await expect(
      validator().validate(encode(bareAssertion()), context),
    ).rejects.toMatchObject({ check: "document" });
  });

  it("refuses a confirmation whose InResponseTo is not ours", async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="_other" Recipient="${ACS}" ` +
                `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({ check: "bearerConfirmation" });
  });

  it("refuses a confirmation whose Recipient is not our ACS", async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" ` +
                `Recipient="http://elsewhere/acs" NotOnOrAfter="${iso(300_000)}"/>` +
                `</saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({ check: "bearerConfirmation" });
  });

  it("refuses a confirmation whose own window has closed, though Conditions are open", async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            notOnOrAfter: iso(300_000),
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
                `NotOnOrAfter="${iso(-1000)}"/></saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({ check: "bearerConfirmation" });
  });

  // The fields must come from ONE confirmation. Here each is right in a
  // different element, and the assertion must still be refused.
  it("refuses when the right values are spread across two confirmations", async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" ` +
                `Recipient="http://elsewhere/acs" NotOnOrAfter="${iso(300_000)}"/>` +
                `</saml:SubjectConfirmation>`,
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="_other" Recipient="${ACS}" ` +
                `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({ check: "bearerConfirmation" });
  });

  it("refuses a Response with no Destination", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ destination: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: "destination" });
  });

  it("refuses a Destination naming somewhere else", async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ destination: "http://elsewhere/acs" })),
        context,
      ),
    ).rejects.toMatchObject({ check: "destination" });
  });

  it("refuses the same assertion twice", async () => {
    const shared = validator();
    const payload = encode(buildResponse());
    await shared.validate(payload, context);
    await expect(shared.validate(payload, context)).rejects.toMatchObject({
      check: "replay",
    });
  });

  // Retention must outlast the skew window: inside it the assertion is still
  // acceptable, so the store must still remember it.
  it("refuses a replay inside the skew window", async () => {
    const shared = createSignedResponseValidator({
      idpCertificates: [KEY.certificatePem],
      replayStore: createInMemoryReplayStore(),
      clockSkewMs: 60_000,
    });
    const payload = encode(buildResponse({ notOnOrAfter: iso(-1000) }));
    await shared.validate(payload, context);
    await expect(shared.validate(payload, context)).rejects.toMatchObject({
      check: "replay",
    });
  });

  it("takes expiresAt from whichever window closes first", async () => {
    const result = await validator().validate(
      encode(
        buildResponse({
          notOnOrAfter: iso(600_000),
          confirmations: [
            `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
              `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
              `NotOnOrAfter="${iso(120_000)}"/></saml:SubjectConfirmation>`,
          ],
        }),
      ),
      context,
    );
    expect(result.expiresAt.getTime()).toBeLessThan(Date.now() + 300_000);
  });

  // The wrapping shape at the validator level: one genuinely signed assertion,
  // one forged beside it. Reading only the signed one is not enough, because
  // `raw` travels on to the cookie provider and to UAA.
  it("refuses a response carrying a second, forged assertion", async () => {
    const forged =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged">` +
      `<saml:Issuer>urn:attacker</saml:Issuer></saml:Assertion>`;
    const doctored = buildResponse().replace(
      "</samlp:Response>",
      `${forged}</samlp:Response>`,
    );
    await expect(
      validator().validate(encode(doctored), context),
    ).rejects.toMatchObject({ check: "signedNode" });
  });

  it("refuses a document carrying two elements with the same ID", async () => {
    const doctored = buildResponse().replace('ID="_r1"', 'ID="_a1"');
    await expect(
      validator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: "duplicateId",
    });
  });

  it("refuses something that is not XML", async () => {
    await expect(
      validator().validate(
        Buffer.from("nope", "utf8").toString("base64"),
        context,
      ),
    ).rejects.toMatchObject({ check: "document" });
  });
});
```

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/validation/assertionValidator.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/validation/assertionValidator.ts`**

The skeleton, with every rule's exact condition. Fill in the reading helpers; do not change the order, and give each refusal its own message.

````ts
/**
 * The shipped assertion validator: the spec's check table, in order.
 *
 * Two properties matter more than any individual check. First, the signature
 * is resolved to an element and every assertion-level field is read *from that
 * element* — a document holding a validly signed fragment beside a forged one
 * is the wrapping attack, and reading the wrong node is how it succeeds.
 * Second, no two refusals share a distinguishing phrase, so a test cannot pass
 * for a neighbouring check's reason.
 *
 * Three fields live on the Response rather than the assertion: Status,
 * Response/Issuer and Destination. The signed-Response validator reads them,
 * because there they are inside the signature. The assertion-only validator
 * does not read them at all — not weakly. That is safe because a declined
 * login carries no assertion, so flipping Status buys an attacker nothing they
 * can sign, and addressing rests on Recipient inside the signed assertion.
 */

import {
  DOMParser,
  XMLSerializer,
  type Document,
  type Element,
} from '@xmldom/xmldom';
import type {
  AssertionContext,
  IAssertionReplayStore,
  IAssertionValidator,
  ValidatedAssertion,
} from '@mcp-abap-adt/interfaces-auth';
import {
  type AssertionCheck,
  AssertionValidationError,
} from '../errors/AssertionValidationError';
import { findDuplicateId, readRequiredId } from './documentIds';
import { defaultReplayStore } from './inMemoryReplayStore';
import { resolveSignedElements, toPem } from './signedNode';
import { parseXsdDateTime } from './xsdDateTime';

const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

export interface ShippedValidatorOptions {
  readonly idpCertificates: readonly string[];
  readonly clockSkewMs?: number;
  readonly replayStore?: IAssertionReplayStore;
}

/**
 * Which element this validator insists the signature covers.
 *
 * Internal. The public surface is two factories, so a reader of a call site
 * sees the choice; making it a public parameter would put it back where nobody
 * looks.
 */
type SignedElement = 'response' | 'assertion';

export const createSignedResponseValidator = (
  options: ShippedValidatorOptions,
): IAssertionValidator => createValidator('response', options);

export const createSignedAssertionValidator = (
  options: ShippedValidatorOptions,
): IAssertionValidator => createValidator('assertion', options);

function createValidator(
  require: SignedElement,
  options: ShippedValidatorOptions,
): IAssertionValidator {
  const skew = options.clockSkewMs ?? 0;
  if (!Number.isInteger(skew) || skew < 0) {
    throw new Error(
      `clockSkewMs must be a finite non-negative integer, got ${String(options.clockSkewMs)}`,
    );
  }
  if (options.idpCertificates.length === 0) {
    throw new Error(
      'idpCertificates must not be empty: nothing could be verified',
    );
  }
  // Normalised and proved here, once, rather than inside verification. Three
  // reasons, and the last bites hardest: a malformed entry standing first in
  // the list would abort the rotation loop before a later valid certificate
  // was tried; a constructor is where this package already refuses a bad
  // configuration; and a login happens after a human has used a browser, so a
  // formatting mistake found then wastes their work, not ours.
  const certificates = options.idpCertificates.map(toPem);
  const store = options.replayStore ?? defaultReplayStore;

  return {
    async validate(samlResponse, context): Promise<ValidatedAssertion> {
      // 1. Parses, and the document element is a samlp:Response.
      const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
      let doc: Document;
      try {
        doc = new DOMParser().parseFromString(xml, 'text/xml') as unknown as Document;
      } catch {
        return fail('document', 'the SAMLResponse did not parse as XML');
      }
      const root = doc.documentElement as unknown as Element | null;
      if (!root) return fail('document', 'the SAMLResponse did not parse as XML');
      const rootIsResponse =
        root.localName === 'Response' && root.namespaceURI === PROTOCOL_NS;
      const rootIsAssertion =
        root.localName === 'Assertion' && root.namespaceURI === SAML_NS;
      // A bare Assertion is a document only the assertion-only validator
      // accepts: the saml2-bearer grant exchanges an Assertion, and 3.0.0
      // already takes one as Saml2BearerProvider's payload.
      if (!rootIsResponse && !(require === 'assertion' && rootIsAssertion)) {
        return fail(
          'document',
          require === 'assertion'
            ? `expected a samlp:Response or a saml:Assertion, got ${root.localName}`
            : `expected the document element to be a samlp:Response, got ${root.localName}`,
        );
      }

      // 1b. Unique IDs, before any reference is resolved.
      const duplicate = findDuplicateId(doc);
      if (duplicate) {
        return fail(
          'duplicateId',
          `the document uses the ID ${duplicate} more than once, so which element is signed is ambiguous`,
        );
      }

      // 2 + 3. Verify every signature, then take the element this validator
      // requires from among those they cover. A response signed at both
      // levels — as many identity providers send — satisfies either validator.
      let covered: Element[];
      try {
        covered = resolveSignedElements(xml, doc, certificates);
      } catch (error) {
        return fail('signature', (error as Error).message);
      }
      const signed =
        require === 'response'
          ? covered.find((element) => element === root)
          : covered.find(
              (element) =>
                element.localName === 'Assertion' &&
                element.namespaceURI === SAML_NS,
            );

      // The signed element must be the Assertion, or a Response holding exactly
      // one. Everything below is read from `assertion` and nowhere else.
      const assertion = signed ? assertionInside(signed, root, require) : null;
      if (!assertion) {
        return fail(
          'signedNode',
          'the signature does not cover the assertion this response carries',
        );
      }

      // 4. Status. Only when the Response is the signed element: otherwise it
      // lies outside the signature, and checking a field an attacker sets is
      // worse than not checking it — it reads like verification.
      if (require === 'response') {
      const status = directChild(root, PROTOCOL_NS, 'Status');
      const codeValue = status
        ? directChild(status, PROTOCOL_NS, 'StatusCode')?.getAttribute('Value')
        : null;
      if (!codeValue) return fail('status', 'the response carries no samlp:Status');
      if (codeValue !== SUCCESS) {
        return fail('status', `the identity provider declined the login: ${codeValue}`);
      }

      }

      // 4b. The assertion's own ID.
      const assertionId = readRequiredId(assertion);
      if (!assertionId) return fail('assertionId', 'the assertion carries no ID');

      // 5. The assertion's Issuer — inside the signature either way, so both
      // validators check it.
      const issuer = directChild(assertion, SAML_NS, 'Issuer')?.textContent ?? '';
      if (!issuer) return fail('issuer', 'the assertion carries no Issuer');
      if (context.expectedIssuer && issuer !== context.expectedIssuer) {
        return fail('issuer', `the assertion was issued by ${issuer}, not the trusted issuer`);
      }
      // 5b. The cross-check against the Response's Issuer belongs to the
      // signed-Response validator alone: only there are both inside the
      // signature.
      if (require === 'response') {
        const responseIssuer = directChild(root, SAML_NS, 'Issuer')?.textContent;
        if (responseIssuer && responseIssuer !== issuer) {
          return fail(
            'issuer',
            'the response and the assertion name different issuers',
          );
        }
      }

      // 6, 7, 8. Conditions and their window.
      const conditions = directChild(assertion, SAML_NS, 'Conditions');
      if (!conditions) return fail('conditions', 'the assertion carries no Conditions');

      const notBeforeRaw = conditions.getAttribute('NotBefore');
      if (notBeforeRaw) {
        const notBefore = parseXsdDateTime(notBeforeRaw);
        if (!notBefore) {
          return fail('notBefore', `Conditions NotBefore is not a valid xsd:dateTime: ${notBeforeRaw}`);
        }
        if (notBefore.getTime() - skew > Date.now()) {
          return fail('notBefore', 'the assertion is not valid yet');
        }
      }

      const conditionsExpiry = parseXsdDateTime(conditions.getAttribute('NotOnOrAfter'));
      if (!conditionsExpiry) {
        return fail(
          'notOnOrAfter',
          'Conditions carries no usable NotOnOrAfter, so the assertion states no lifetime',
        );
      }
      if (conditionsExpiry.getTime() + skew <= Date.now()) {
        return fail('notOnOrAfter', 'the assertion has expired');
      }

      // 9. Every AudienceRestriction must name us; several Audience inside one
      // are alternatives.
      const restrictions = directChildren(conditions, SAML_NS, 'AudienceRestriction');
      if (restrictions.length === 0) {
        return fail('audience', 'the assertion restricts no audience');
      }
      for (const restriction of restrictions) {
        const names = directChildren(restriction, SAML_NS, 'Audience').map(
          (a) => a.textContent ?? '',
        );
        if (!names.includes(context.audience)) {
          return fail(
            'audience',
            'an AudienceRestriction on this assertion does not name us',
          );
        }
      }

      // 10. One bearer confirmation satisfying everything together.
      const chosen = chooseBearerConfirmation(assertion, context, skew);
      if (!chosen) {
        return fail(
          'bearerConfirmation',
          'no single bearer SubjectConfirmation answers our request, names our ACS and is still open',
        );
      }

      // 11. Destination — the signed-Response validator only, for the same
      // reason as Status. Addressing in the other flow rests on Recipient,
      // which step 10 required and which sits inside the signed assertion.
      if (require === 'response') {
        const destination = root.getAttribute('Destination');
        if (!destination) {
          return fail('destination', 'the response carries no Destination');
        }
        if (destination !== context.acsUrl) {
          return fail(
            'destination',
            `the response is addressed to ${destination}, not to us`,
          );
        }
      }

      // Expiry: the earlier of the two windows.
      const expiresAt = new Date(
        Math.min(conditionsExpiry.getTime(), chosen.notOnOrAfter.getTime()),
      );

      // 12. Replay — retained past the skew window, because inside it the
      // assertion would still be accepted.
      const fresh = await store.recordIfUnseen(
        { issuer, assertionId },
        new Date(expiresAt.getTime() + skew),
      );
      if (!fresh) {
        return fail('replay', 'this assertion has been presented before');
      }

      return {
        expiresAt,
        assertionId,
        issuer,
        nameId: (() => {
          // Subject, then NameID — no `?? assertion` fallback, which would
          // read a NameID from outside the Subject when the Subject is absent.
          const subject = directChild(assertion, SAML_NS, 'Subject');
          return subject
            ? (directChild(subject, SAML_NS, 'NameID')?.textContent ?? undefined)
            : undefined;
        })(),
        raw: samlResponse,
        // The signed element, not the response: this is what a consumer may
        // parse without re-deriving what the signature covered.
        signedXml: new XMLSerializer().serializeToString(signed),
      };
    },
  };
}

function fail(check: AssertionCheck, message: string): never {
  throw new AssertionValidationError(check, message);
}

/**
 * Direct children with this namespace and local name — **not** descendants.
 *
 * `getElementsByTagNameNS` searches the whole subtree, and that is the wrong
 * tool for a structural path. An assertion with no `Conditions` of its own but
 * a `Conditions` buried somewhere inside it would answer the descendant search
 * and satisfy a check it does not meet; the same trick works for `Issuer`,
 * `Status` and `Subject`. Each segment of a SAML path is therefore walked
 * explicitly, one level at a time.
 */
function directChildren(parent: Element, ns: string, local: string): Element[] {
  const out: Element[] = [];
  const nodes = parent.childNodes;
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i] as unknown as Element;
    // nodeType 1 is ELEMENT_NODE; the constant is unavailable without the dom
    // lib, which this project deliberately does not use.
    if (
      node.nodeType === 1 &&
      node.namespaceURI === ns &&
      node.localName === local
    ) {
      out.push(node);
    }
  }
  return out;
}

/** The single direct child with this name, or null when there is not exactly one. */
function directChild(parent: Element, ns: string, local: string): Element | null {
  const found = directChildren(parent, ns, local);
  // Not "the first": two siblings sharing a name is an ambiguity, and
  // resolving it silently in favour of the first is how a forged element comes
  // to be read in preference to a real one.
  return found.length === 1 ? found[0] : null;
}

/**
 * The assertion the signature covers, or null when the signed element is not
 * one and does not contain exactly one.
 *
 * "Exactly one" matters: a signed Response wrapping two assertions leaves
 * "which did we verify" ambiguous, which is the wrapping question again.
 */
function assertionInside(
  signed: Element,
  root: Element,
  require: SignedElement,
): Element | null {
  // The signature must cover what this validator was built to require. A
  // signed-Response validator handed an assertion-signed document refuses
  // here, and vice versa — that refusal is the whole point of shipping two.
  const signedIsResponse =
    signed.localName === 'Response' && signed.namespaceURI === PROTOCOL_NS;
  const signedIsAssertion =
    signed.localName === 'Assertion' && signed.namespaceURI === SAML_NS;
  if (require === 'response' && !signedIsResponse) return null;
  if (require === 'assertion' && !signedIsAssertion) return null;

  // A bare Assertion is its own document: the only assertion there is, and
  // it must be the element signed.
  if (root.localName === 'Assertion' && root.namespaceURI === SAML_NS) {
    return signed === root ? root : null;
  }

  // Whatever was signed, the response must carry exactly one assertion.
  //
  // Reading only from the signed element is not enough: `raw` — the whole
  // response — travels on to the cookie provider and to UAA, and they read
  // whatever is in it. A forged assertion placed beside the signed one must
  // therefore end the login, not merely be ignored here.
  const assertions = directChildren(root, SAML_NS, 'Assertion');
  if (assertions.length !== 1) return null;
  const only = assertions[0];

  if (signed.localName === 'Assertion' && signed.namespaceURI === SAML_NS) {
    return signed === only ? only : null;
  }
  if (signed.localName === 'Response' && signed.namespaceURI === PROTOCOL_NS) {
    return signed === root ? only : null;
  }
  return null;
}

/**
 * The bearer confirmation this login may rely on.
 *
 * Every part must hold on the **same** element: gathering `InResponseTo` from
 * one confirmation and `Recipient` from another is how a document satisfies a
 * check nothing in it actually satisfies. When several qualify — which a real
 * identity provider does not produce — the earliest window wins, so the
 * outcome is a shorter session rather than a longer one.
 */
function chooseBearerConfirmation(
  assertion: Element,
  context: AssertionContext,
  skew: number,
): { notOnOrAfter: Date } | null {
  const now = Date.now();
  let best: Date | null = null;

  const subject = directChild(assertion, SAML_NS, 'Subject');
  if (!subject) return null;

  for (const confirmation of directChildren(subject, SAML_NS, 'SubjectConfirmation')) {
    if (confirmation.getAttribute('Method') !== BEARER) continue;

    const data = directChild(confirmation, SAML_NS, 'SubjectConfirmationData');
    if (!data) continue;
    // Option B: an expected ID must be matched exactly; no expected ID — an
    // IdP-initiated login — means the attribute must not be there at all.
    if (context.expectedInResponseTo === undefined) {
      if (data.hasAttribute('InResponseTo')) continue;
    } else if (data.getAttribute('InResponseTo') !== context.expectedInResponseTo) {
      continue;
    }
    if (data.getAttribute('Recipient') !== context.acsUrl) continue;

    const notOnOrAfter = parseXsdDateTime(data.getAttribute('NotOnOrAfter'));
    if (!notOnOrAfter) continue;
    if (notOnOrAfter.getTime() + skew <= now) continue;

    const notBeforeRaw = data.getAttribute('NotBefore');
    if (notBeforeRaw) {
      const notBefore = parseXsdDateTime(notBeforeRaw);
      if (!notBefore || notBefore.getTime() - skew > now) continue;
    }

    if (!best || notOnOrAfter.getTime() < best.getTime()) best = notOnOrAfter;
  }

  return best ? { notOnOrAfter: best } : null;
}
````

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/validation/assertionValidator.test.ts
```

Expected: PASS, 44 cases.

- [ ] **Step 5: Prove the rules that a wrong-value test alone would not**

Seven mutations, one at a time, each reverted before the next. Report per case:

1. In `chooseBearerConfirmation`, drop the `NotOnOrAfter` condition — `refuses a confirmation whose own window has closed, though Conditions are open` must go red.
2. In `chooseBearerConfirmation`, gather each attribute across all confirmations instead of requiring one element to satisfy all — `refuses when the right values are spread across two confirmations` must go red.
3. Change the audience loop to "our audience appears in some restriction" — `refuses when a second restriction excludes us` must go red while `accepts our audience among alternatives inside one restriction` stays green. Both matter; report both.
4. Take `expiresAt` from `conditionsExpiry` alone — `takes expiresAt from whichever window closes first` must go red.
5. Pass `expiresAt` rather than `expiresAt + skew` as `retainUntil` — `refuses a replay inside the skew window` must go red.
6. Delete the `assertions.length !== 1` guard from `assertionInside` — `refuses a response carrying a second, forged assertion` must go red. This is the wrapping refusal; if it stays green the fixture is not producing two direct `Assertion` children, and you must say so rather than moving on.
7. Change `directChild` to return `found[0] ?? null` instead of requiring exactly one — nothing in this suite may go green that was red. If nothing changes at all, add a case with two `Conditions` siblings, because "resolve an ambiguity in favour of the first" is how a forged element gets preferred to a real one.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add src/validation/assertionValidator.ts src/__tests__/validation/assertionValidator.test.ts
git commit -m "feat: the shipped assertion validator, assertion fields read only from the signed element"
```

---

### Task 10: The request ID must survive

**Files:**

- Modify: `src/auth/saml2Auth.ts` — `buildSamlAuthorizationUrl`, and delete `parseSamlNotOnOrAfter`
- Modify: `src/providers/saml2Utils.ts` — `Saml2CommonConfig`, `getSamlAssertion`
- Test: `src/__tests__/auth/saml2Auth.test.ts` (existing — update), `src/__tests__/providers/saml2Utils.test.ts`

**Interfaces:**

- Produces:
  - `buildSamlAuthorizationUrl(config): { url: string; requestId?: string }` — `requestId` is present only when this function minted one, which it does not for a pre-built `authorizationUrl`.
  - `getSamlAssertion(config): Promise<{ payload: string; requestId?: string; acsUrl: string }>` — `requestId` is `undefined` exactly when the login is declared `idpInitiated` and none was minted or declared; it throws `ValidationError` when no ID can be established without that declaration, and when `idpInitiated` is combined with a minted or declared ID. `acsUrl` is `outcome.redirectUri`: where the strategy actually listened.
  - `Saml2CommonConfig` gains `idpCertificates?: string[]`, `idpEntityId?: string`, `clockSkewMs?: number`, `authnRequestId?: string`, `idpInitiated?: boolean`, `assertionValidator?: IAssertionValidator`, `assertionReplayStore?: IAssertionReplayStore`. `spEntityId` is **already** there and already required (`src/providers/saml2Utils.ts:12`); it becomes the validator's `audience` and needs no change.

**The rule, from the spec:** the ID must come from somewhere real. Either this package minted it, or the consumer declared it — or, by declaring the login `idpInitiated`, the consumer says there is none, and then `InResponseTo` must be absent. With no ID and no declaration, that is a configuration error naming the remedy — not a validation failure blamed on the assertion.

- [ ] **Step 1: Read what exists**

```bash
sed -n '20,60p' src/auth/saml2Auth.ts
sed -n '1,60p' src/providers/saml2Utils.ts
grep -rn "buildSamlAuthorizationUrl\|parseSamlNotOnOrAfter" src/
```

Note every call site; Step 3 changes all of them.

- [ ] **Step 2: Write the failing tests**

Add to `src/__tests__/providers/saml2Utils.test.ts` (create it if absent):

```ts
import { describe, expect, it } from "@jest/globals";
import { buildSamlAuthorizationUrl } from "../../auth/saml2Auth";

describe("buildSamlAuthorizationUrl", () => {
  it("mints a request ID and reports it", () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: "https://idp.example/sso",
      spEntityId: "urn:sp",
      acsUrl: "http://localhost:61001/acs",
    });
    expect(built.requestId).toMatch(/^_/);
    expect(built.url).toContain("SAMLRequest=");
  });

  it("puts the ID it reports into the request it builds", () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: "https://idp.example/sso",
      spEntityId: "urn:sp",
      acsUrl: "http://localhost:61001/acs",
    });
    const encoded = new URL(built.url).searchParams.get("SAMLRequest") ?? "";
    const xml = require("node:zlib")
      .inflateRawSync(Buffer.from(encoded, "base64"))
      .toString("utf8");
    expect(xml).toContain(`ID="${built.requestId}"`);
  });

  it("mints nothing for a pre-built authorization URL", () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: "https://idp.example/sso",
      spEntityId: "urn:sp",
      acsUrl: "http://localhost:61001/acs",
      authorizationUrl: "https://idp.example/preauthorized?SAMLRequest=xyz",
    });
    expect(built.url).toBe("https://idp.example/preauthorized?SAMLRequest=xyz");
    expect(built.requestId).toBeUndefined();
  });
});
```

The second case is the one that matters: without it, `requestId` could be a fresh UUID unrelated to the request actually sent, and every `InResponseTo` check downstream would be comparing against a number nobody used.

- [ ] **Step 3: Run them to verify they fail**

```bash
npm test -- src/__tests__/providers/saml2Utils.test.ts
```

Expected: FAIL — `built.requestId` is undefined because the function returns a string.

- [ ] **Step 4: Change `buildSamlAuthorizationUrl`**

Return `{ url, requestId }`. Move the ID out of `buildAuthnRequestXml` so the caller mints it and passes it in:

```ts
export interface BuiltAuthorizationUrl {
  readonly url: string;
  /** Present only when this function minted the request. */
  readonly requestId?: string;
}

export function buildSamlAuthorizationUrl(
  config: Saml2AuthConfig,
): BuiltAuthorizationUrl {
  if (config.authorizationUrl) {
    // Somebody else built the request; its ID is not ours to know.
    return { url: config.authorizationUrl };
  }

  const requestId = `_${randomUUID()}`;
  const xml = buildAuthnRequestXml(requestId, config.spEntityId, config.acsUrl);
  const deflated = deflateRawSync(Buffer.from(xml, "utf8"));
  const samlRequest = encodeURIComponent(base64Encode(deflated));
  const relayState = config.relayState
    ? `&RelayState=${encodeURIComponent(config.relayState)}`
    : "";

  return {
    url: `${config.idpSsoUrl}?SAMLRequest=${samlRequest}${relayState}`,
    requestId,
  };
}
```

`buildAuthnRequestXml` takes the ID as its first parameter instead of minting one.

- [ ] **Step 5: Delete `parseSamlNotOnOrAfter`**

Remove the function and its tests. Expiry now comes from validation. Any call site is updated in Task 11.

- [ ] **Step 6: Thread the ID and the real ACS through `getSamlAssertion`**

It returns `{ payload, requestId, acsUrl }`.

**`acsUrl` is `outcome.redirectUri`, never `config.acsUrl`.** The default
strategy binds an ephemeral port, so the configured value is usually absent and
is never authoritative — `outcome.redirectUri` exists precisely because the
provider has no other way to learn where the strategy listened. Validation
compares `Recipient` and `Destination` against it, so taking the configured
value would compare against `undefined`, or against an address nothing was
listening on. The "second net" already reads `outcome.redirectUri`; return it
rather than reading it twice.

**Option B.** `Saml2CommonConfig` also gains `idpInitiated?: boolean`, and
`getSamlAssertion` returns `requestId?: string` — `undefined` exactly when the
login is declared IdP-initiated. The provenance, from the spec's "Where the
expected request ID comes from":

- `idpInitiated: true`, the builder never called, no `authnRequestId` → `requestId` undefined;
- `idpInitiated: true` with the builder called **or** `authnRequestId` set →
  `ValidationError` naming the conflict: an IdP-initiated login sends no
  request, so an ID means the configuration describes two different logins;
- otherwise, as before:

The ID is whichever exists, in this order: the one `buildSamlAuthorizationUrl` minted during this login, then `config.authnRequestId`. When neither:

```ts
throw new ValidationError(
  "Cannot validate InResponseTo: this login did not build its own AuthnRequest, " +
    "so authnRequestId must be configured — or, if the identity provider " +
    "starts this login itself, idpInitiated: true. This happens with a " +
    "pre-built authorizationUrl, or an authorization strategy that supplies an " +
    "assertion without asking for a URL.",
  ["authnRequestId"],
);
```

Match `ValidationError`'s actual constructor signature — check `src/errors/TokenProviderErrors.ts` rather than copying this call shape blindly.

Tests to add for option B, each failing without its rule: `idpInitiated`
with a strategy that never calls the builder yields `requestId` undefined;
with a strategy that does call it, a `ValidationError` naming the conflict;
with `authnRequestId` set, the same; and without `idpInitiated`, a strategy
that never calls the builder still raises the `authnRequestId` error above —
an unsolicited login is never inferred.

- [ ] **Step 7: Run the whole suite**

```bash
npm test
```

Expected: PASS. Existing callers of `buildSamlAuthorizationUrl` now destructure `.url`; if any test asserted on the returned string, update it to `.url` — that is the intended breaking change, not a test to weaken.

- [ ] **Step 8: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add -A
git commit -m "feat!: the AuthnRequest ID survives to validation"
```

---

### Task 11: Wire both providers

**Files:**

- Modify: `src/providers/Saml2PureProvider.ts`, `src/providers/Saml2BearerProvider.ts`, `src/providers/saml2Utils.ts`
- Test: `src/__tests__/sso/SsoProviders.test.ts` (existing — update). The SAML providers have no test file of their own; their cases, including the refresh cases from PR #31, live there.

**Interfaces:**

- Consumes: everything from Tasks 8 and 9.
- Produces: `resolveAssertionValidator(config, provider: "bearer" | "pure"): IAssertionValidator` in `saml2Utils.ts` — the consumer's when supplied, otherwise the provider's default — `createSignedAssertionValidator` for `"bearer"`, `createSignedResponseValidator` for `"pure"` — built from `idpCertificates`, `clockSkewMs` and `assertionReplayStore`, raising `ValidationError` when `idpCertificates` or `idpEntityId` is missing. `Saml2BearerProvider` resolves with `"bearer"`, `Saml2PureProvider` with `"pure"`. A test pins each default: a response signed only at the Response level is accepted by `Saml2PureProvider`'s default and refused, at `signedNode`, by `Saml2BearerProvider`'s.

- [ ] **Step 1: Write the failing tests**

For `Saml2PureProvider`, the change worth pinning is where the expiry comes from:

```ts
it("refuses at construction when the identity provider is not configured", () => {
  expect(
    () => new Saml2PureProvider({ ...baseConfig, idpCertificates: undefined }),
  ).toThrow(/idpCertificates/);
});

it("takes expiresAt from the validated assertion, not from a regex", async () => {
  // A stub validator, to prove the provider uses what validation returned.
  const expiresAt = new Date(Date.now() + 111_000);
  const provider = new Saml2PureProvider({
    ...baseConfig,
    assertionValidator: {
      async validate() {
        return {
          expiresAt,
          assertionId: "_a1",
          issuer: "urn:mock:idp",
          raw: "ignored",
        };
      },
    },
    cookieProvider: async () => "cookie=1",
  });
  const result = await provider.getTokens();
  expect(result.expiresAt).toEqual(expiresAt);
});
```

For `Saml2BearerProvider`, that validation runs **before** the exchange:

```ts
it("does not reach the token endpoint when the assertion is refused", async () => {
  let exchanged = false;
  const provider = new Saml2BearerProvider({
    ...baseConfig,
    assertionValidator: {
      async validate() {
        throw new AssertionValidationError("status", "the IdP declined");
      },
    },
  });
  // Stub the exchange so reaching it is observable.
  jest
    .spyOn(exchangeModule, "exchangeSamlAssertion")
    .mockImplementation(async () => {
      exchanged = true;
      return {} as never;
    });
  await expect(provider.getTokens()).rejects.toMatchObject({ check: "status" });
  expect(exchanged).toBe(false);
});
```

Adapt the stubbing to however the existing provider tests already isolate the network — read them first and follow that, rather than introducing a second mocking style.

- [ ] **Step 2: Run them to verify they fail**

```bash
npm test -- src/__tests__/providers
```

Expected: FAIL — `assertionValidator` is not a config field yet.

- [ ] **Step 3: Implement `resolveAssertionValidator` in `saml2Utils.ts`**

Import both shipped validators, `createSignedAssertionValidator` and `createSignedResponseValidator`, from `../validation/assertionValidator`.

```ts
export function resolveAssertionValidator(
  config: Saml2CommonConfig,
  // Saml2BearerProvider's default is the assertion-only validator: the token
  // endpoint receives the Assertion alone, so its own signature is what
  // counts. Saml2PureProvider's is the signed-Response one. See the spec's
  // "A bare Assertion, and which validator each provider defaults to".
  provider: "bearer" | "pure",
): IAssertionValidator {
  if (config.assertionValidator) return config.assertionValidator;

  const missing: string[] = [];
  if (!config.idpCertificates?.length) missing.push("idpCertificates");
  if (!config.idpEntityId) missing.push("idpEntityId");
  if (missing.length > 0) {
    throw new ValidationError(
      "The default assertion validator needs the identity provider it should " +
        "trust. Supply these, or supply an assertionValidator of your own.",
      missing,
    );
  }

  const options = {
    idpCertificates: config.idpCertificates as string[],
    clockSkewMs: config.clockSkewMs,
    replayStore: config.assertionReplayStore,
  };
  return provider === "bearer"
    ? createSignedAssertionValidator(options)
    : createSignedResponseValidator(options);
}
```

- [ ] **Step 4: Resolve the validator at construction, not at login**

A missing `idpCertificates`, a missing `idpEntityId`, or a `clockSkewMs` that is
not a finite non-negative integer are configuration faults — and a
configuration fault must not surface **after** a human has opened a browser and
completed a login. Both providers already call `validateSamlConfig(config)` in
their constructors for exactly this reason; the comment there reads "throw at
construction rather than half-verify at runtime".

Resolve once, in the constructor, and keep it:

```ts
  private readonly validator: IAssertionValidator;

  constructor(config: Saml2PureProviderConfig) {
    super();
    validateSamlConfig(config);
    // Before anything reaches a browser or a network: a missing certificate is
    // the consumer's mistake, and finding it after a completed login wastes
    // theirs.
    this.validator = resolveAssertionValidator(config, "pure");
    this.config = config;
    // … the rest unchanged
  }
```

`Saml2BearerProvider` does the same, with `resolveAssertionValidator(config, "bearer")`.

- [ ] **Step 5: Wire `Saml2PureProvider.performLogin`**

```ts
protected async performLogin(): Promise<ITokenResult> {
  const { payload, requestId, acsUrl } = await getSamlAssertion(this.config);
  // acsUrl is where the strategy actually listened — with an ephemeral port
  // the configured value is usually absent and never authoritative.
  const validated = await this.validator.validate(payload, {
    expectedInResponseTo: requestId,
    audience: this.config.spEntityId,
    acsUrl,
    expectedIssuer: this.config.idpEntityId,
    logger: this.logger,
  });
  const sessionCookies = await this.config.cookieProvider(payload);

  return {
    authorizationToken: sessionCookies,
    authType: AUTH_TYPE_USER_TOKEN,
    tokenType: 'saml',
    expiresAt: validated.expiresAt,
  };
}
```

- [ ] **Step 6: Wire `Saml2BearerProvider`**

The same validation call, placed **before** `exchangeSamlAssertion`, with
`expectedInResponseTo: requestId` — `undefined` for a login declared
`idpInitiated`. The exchange then sends what 3.0.0 already sends:
`toBearerAssertion(payload)`, the one Assertion out of the response,
base64url (RFC 7522, #40). Validation establishes trust; it does not change
what the token endpoint receives beyond that conversion. Note the consequence
the spec states: if the identity provider signs only the Response, the
extracted Assertion carries no signature of its own and the token endpoint
refuses it even though the signed-Response validator accepted the response.

`performRefresh()` stays as PR #31 left it: a `refresh_token` grant carries no
assertion, so there is nothing to validate, and the validator must not be
consulted there. Pin it — a provider seeded with a refresh token and an
expired access token, whose `assertionValidator` is a stub that fails the test
if called, refreshes without calling it. Without this, a later change routing
refresh through `performLogin()` again would pass every other test.

- [ ] **Step 7: Run the whole suite**

```bash
npm test
```

Expected: PASS. Existing provider tests will need `idpCertificates` and `idpEntityId` in their configs, or an `assertionValidator` stub — that is the breaking change working, not a test to weaken. That includes the four `Saml2BearerProvider refresh` cases from PR #31, whose `seededConfig()` builds a provider with no identity-provider configuration: the validator is now resolved at construction, so they fail there before reaching the refresh they test. Give `seededConfig()` a stub validator; do not weaken what they assert. If a test previously asserted an expiry derived from the regex, it now asserts the validated one.

- [ ] **Step 8: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add -A
git commit -m "feat!: both SAML providers validate the assertion before trusting it"
```

---

### Task 12: End to end against the mocks

**Files:**

- Test: `src/__tests__/integration/samlValidation.test.ts`

**Interfaces:**

- Consumes: `startMockSamlIdp`, `visit`, `generateKeyMaterial`, `signXml` from `@mcp-abap-adt/auth-mocks`; the provider from Task 11.
- Also runs on real servers (option B): the stand's `keycloakSaml.test.ts` and the live `xsuaa.test.ts` — see "Real servers" below.

**This is the task that decides whether the validators are right about real documents rather than about the fixtures their author wrote.** Both are exercised, because they refuse different things and a matrix that ran only one would leave the other's contract unproven.

**Two facts about the mock shape this task, and both were established by reading its source rather than assuming.** Confirm them yourself before writing the matrix.

- `startMockSamlIdp` signs the **assertion** by default; `signWhat: 'response'` (published in 0.3.0) signs the Response, with the `Signature` after the Response's `Issuer`. Without it the signed-Response validator would refuse every response the mock produces, including the valid one, so run every signed-Response case with it.
- `wrongIssuer` writes one `issuerValue` into **both** `Response/Issuer` and `Assertion/Issuer`. The corrupted assertion issuer is inside the signature, so **both** validators refuse it at `issuer`. It is not evidence that the response-level cross-check exists.

- [ ] **Step 1: Write the test**

Drive a real login through `Saml2PureProvider` with `browserCallbackStrategy({ openUrl: visit })` pointed at `startMockSamlIdp`, registering the ACS the strategy binds, and run each variant against **both** validators.

```ts
// Refused by both, for the same check: everything here is inside the
// assertion, or is the signature itself.
const REFUSED_BY_BOTH: Array<[SamlVariant, AssertionCheck]> = [
  ["unsigned", "signature"],
  ["wrongKey", "signature"],
  ["tamperedAfterSign", "signature"],
  ["wrongIssuer", "issuer"],
  ["notYetValid", "notBefore"],
  ["expired", "notOnOrAfter"],
  ["wrongAudience", "audience"],
  ["wrongInResponseTo", "bearerConfirmation"],
  ["wrongRecipient", "bearerConfirmation"],
];

// Refused by the signed-Response validator, accepted by the other, which does
// not read these fields. Both halves are asserted: a check silently dropped
// and a check documented as absent look identical from outside.
const RESPONSE_LEVEL: Array<[SamlVariant, AssertionCheck]> = [
  ["statusFailure", "status"],
  ["wrongDestination", "destination"],
];

for (const [variant, check] of REFUSED_BY_BOTH) {
  it(`refuses ${variant} at ${check}, whichever validator`, async () => {
    await expect(loginWith("response", variant)).rejects.toMatchObject({
      check,
    });
    await expect(loginWith("assertion", variant)).rejects.toMatchObject({
      check,
    });
  });
}

for (const [variant, check] of RESPONSE_LEVEL) {
  it(`refuses ${variant} at ${check} only when the Response is signed`, async () => {
    await expect(loginWith("response", variant)).rejects.toMatchObject({
      check,
    });
    await expect(loginWith("assertion", variant)).resolves.toBeDefined();
  });
}
```

`loginWith(signWhat, variant)` starts the IdP with `{ variant, signWhat, acsUrls: [acs], issuer, audience }` and the provider with the matching validator. Asserting the **check**, not merely that it threw, is what stops a variant being refused for an unrelated reason — the defect that took a whole round to find in `auth-mocks`, where seven of nine variants were rejected by one structural bug.

Then the cases no variant expresses:

- **A successful login, in each mode**: `expiresAt` comes from the assertion and the session cookie is what `cookieProvider` returned. Do **not** try to assert `signedXml` here: the provider returns an `ITokenResult`, not the `ValidatedAssertion`, so the login's result cannot show which element was signed. That property is pinned in Task 9's unit tests, where the validator's return value is in hand. If you want it end to end, the honest way is a spy validator wrapping the real one — say so and write it, rather than asserting on a value this call does not expose.
- **The wrong placement**: a response-signed document refused by the assertion-only validator at `signedNode`, and the reverse. Without these, a validator that ignored its requirement would pass everything above.
- **A response-level cross-check that no variant can show**: corrupt `Response/Issuer` **alone**, leaving the assertion's issuer correct, and expect the signed-Response validator to refuse at `issuer` while the assertion-only one accepts. Build it by re-signing with `generateKeyMaterial`/`signXml`, since `wrongIssuer` corrupts both.
- **Replay**: `idp.repeatLastAssertion()`, run the login twice, expect `check: 'replay'` the second time.
- **Signature wrapping**: take the mock's signed response, insert a forged assertion beside the signed one, expect refusal.

- [ ] **Step 2: Run it**

```bash
npm test -- src/__tests__/integration/samlValidation.test.ts
```

**A variant refused at the wrong check is the finding this task exists for.** Do not change the expected check to match what happened. Establish which side is wrong — the mock producing something other than the table says, or our validator reaching the wrong conclusion — and report it. The mock is published and was reviewed to the same standard; if it is wrong, that is an issue against it, not something to absorb here.

- [ ] **Step 3: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add src/__tests__/integration/samlValidation.test.ts
git commit -m "test: every corruption variant is refused at its own check"
```

---

**Real servers (option B).** After Task 11 the providers resolve a validator at
construction, so the existing suites that build SAML providers without
identity-provider configuration fail before they exchange anything. Update
them rather than stub the validator away, since they are the only evidence
against real servers:

- `src/__tests__/integration/stand/uaaSaml2Bearer.test.ts` — `idpCertificates`
  from `tests/stand/uaa/idp/idp.crt`, `idpEntityId: 'test-idp'`, and
  `idpInitiated: true` (its assertions carry no `InResponseTo`). Its payloads
  are a bare, signed Assertion (base64url) and a Response wrapping one; both
  pass `Saml2BearerProvider`'s default, the assertion-only validator, which
  accepts a bare Assertion — so no scenario changes. It must still reach UAA
  in every case it did before.
- `src/__tests__/integration/stand/keycloakSaml.test.ts` — the certificate
  from Keycloak's published SAML metadata, `idpEntityId` the realm URL. The
  IdP-initiated case sets `idpInitiated: true` and must pass validation **and**
  UAA; the SP-initiated case keeps its minted ID, passes validation, and is
  still refused by UAA — the pair is exactly option B's evidence.
  `Saml2PureProvider`'s case validates the SP-initiated response with its
  minted ID.
- `src/__tests__/integration/xsuaa/xsuaa.test.ts` — the per-run certificate
  from `.local/idp.crt`, `idpEntityId: 'auth-providers-test-idp'`,
  `idpInitiated: true`. The bare-Assertion and wrapped-Response cases pass the
  default validator and reach XSUAA as before; the InResponseTo case now fails
  at our validator before XSUAA sees it, which it must assert.

### Task 13: Public surface, documentation, and the release PR

**Files:**

- Modify: `src/index.ts`, `README.md`, `CHANGELOG.md`, `package.json`

**Interfaces:**

- Produces: the package's public surface for this feature.

- [ ] **Step 1: Export**

From `src/index.ts`: `createSignedResponseValidator`, `createSignedAssertionValidator`, `ShippedValidatorOptions`, `createInMemoryReplayStore`, `defaultReplayStore`, `AssertionValidationError`, `AssertionCheck`. Not the internal modules — `parseXsdDateTime`, `findDuplicateId`, `resolveSignedElements` are implementation.

- [ ] **Step 2: Document**

`README.md` must gain, and this is the part a reader will rely on:

- that SAML assertions are now validated, and that this is a **breaking change**: a consumer must supply `idpCertificates` and `idpEntityId`, or their own `assertionValidator`;
- the twelve checks, as the spec's table;
- that `parseSamlNotOnOrAfter` is gone and expiry now comes from the verified document;
- the request-ID rule: when the package does not build the request, `authnRequestId` is required, with the two flows that trigger it — unless the login is declared `idpInitiated`, which Saml2BearerProvider against UAA or XSUAA needs, since both refuse an assertion carrying `InResponseTo`; say what `idpInitiated` gives up (the login-CSRF defence of a request ID) and that it must never be inferred;
- that the default replay store is **process-wide**, what that does and does not protect, and how to replace it;
- **the choice between the two validators**, which is the first thing a
  consumer must make, and **the defaults differ by provider**:
  `Saml2PureProvider` uses `createSignedResponseValidator`, which requires the
  identity provider to sign the `Response`; `Saml2BearerProvider` uses
  `createSignedAssertionValidator`, which accepts a signature over the
  `Assertion` — bare or inside a Response — and **does not read** `Status`,
  `Response/Issuer` or `Destination` at all. Say why the bearer default is
  the assertion one: the token endpoint receives the Assertion alone, so its
  own signature is what counts, and configuring the signed-Response validator
  there would refuse a bare Assertion and accept responses the endpoint then
  refuses. Say
  which identity providers need the second — those that sign only assertions,
  which is many — and say what is given up. Say plainly why it is still sound:
  a declined login carries no assertion to sign, and addressing rests on
  `Recipient`, inside the signature;
- **`raw` versus `signedXml`**: `raw` is what arrived and is forwarded
  verbatim; `signedXml` is what the signature covered. A consumer reading
  anything this interface does not surface must parse the second. Do not let
  the README imply that holding a `ValidatedAssertion` makes all of `raw`
  trustworthy;
- `clockSkewMs`, its default of `0`, and that retention outlasts it.

Also update the "Package responsibilities" section — this package now validates assertions, which the current text says it does not.

- [ ] **Step 3: Changelog and version**

`4.0.0` — 3.0.0 has shipped without this work. Major: the configuration is required, `buildSamlAuthorizationUrl` changed shape, `parseSamlNotOnOrAfter` is gone, `interfaces-auth` moves to `^2.0.0`, and, under `createSignedResponseValidator` — `Saml2PureProvider`'s default — an identity provider returning a non-`Success` status is now refused where it was previously accepted. `Saml2BearerProvider`'s default, `createSignedAssertionValidator`, does not read `Status`, so a bearer consumer sees no change there; say so, so nobody on the bearer path goes looking for it. Write a migration note saying exactly what a consumer on 3.x must add — including `idpInitiated: true` for `Saml2BearerProvider` against UAA or XSUAA.

- [ ] **Step 4: Verify**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
```

- [ ] **Step 5: Commit, push, open the PR — then stop**

```bash
git add -A
git commit -m "docs: assertion validation, and what a 3.x consumer must change"
git push -u origin <branch>
gh pr create --fill
```

Do not merge, do not tag, do not publish. Report the PR URL and stop.

---

## Release order

1. **`@mcp-abap-adt/interfaces-auth@2.0.0`** — Task 1's change, possibly
   batched with other breaking contract changes; the owner's release. Task 3
   stops if it is not published.
2. **`@mcp-abap-adt/auth-mocks@0.3.0`** — published.
3. **`@mcp-abap-adt/auth-providers@4.0.0`** — this repository, major. The
   current release is 3.0.0.
