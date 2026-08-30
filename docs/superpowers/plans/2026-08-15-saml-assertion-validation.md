# SAML Assertion Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `@mcp-abap-adt/auth-providers` establish that a SAML assertion is genuine, addressed to us, currently valid and not a replay — through a strategy with a shipped default — instead of accepting any non-empty string.

**Architecture:** `IAssertionValidator` and `IAssertionReplayStore` join `@mcp-abap-adt/interfaces`; the shipped default lives in `auth-providers/src/validation/`, built from small pure modules (date parsing, document-ID rules, signature resolution, replay store) that an orchestrator composes. Both SAML providers run the validator and take their expiry from its result.

**Tech Stack:** TypeScript, `xml-crypto` for XML-DSig, `@xmldom/xmldom` for the DOM, Jest, Biome. `@mcp-abap-adt/auth-mocks` as a devDependency for the tests.

**Spec:** `docs/superpowers/specs/2026-08-13-saml-assertion-validation-design.md`. Read it before Task 1 — every rule below is justified there, and the check table is the contract this plan implements.

**Status:** written, awaiting review.

## Global Constraints

- **Interface-only communication.** Anything crossing a package boundary is an interface from `@mcp-abap-adt/interfaces`. A logger is `ILogger`, never a local abstraction.
- **Everything pluggable is a strategy**, shipped with a working default the consumer can replace.
- **Nothing writes to `process.stdout`.** Under an MCP or LSP stdio transport a stray line corrupts the protocol.
- **Absent is refused, not skipped.** A rule phrased "present and not X" is one an attacker satisfies by deleting the field. Every field the check table names refuses when it is missing.
- **Every rule gets a test that fails when the rule is deleted.** For a conjunction, mutate **each half separately** — a whole-block mutation cannot tell you which half is load-bearing.
- **Assert on a message fragment unique to the rule.** A shared prefix kept a test green after the rule it protected was deleted, twice, during the `auth-mocks` cycle.
- Node ≥18, CommonJS, TypeScript `strict: true`.
- `npm run lint:check`, `npm run build`, `npm run test:check` and `npm test` pass before every commit.
- The agent never runs `npm publish`, never merges a PR, and never creates a tag before a merge exists.

## Facts established before this plan was written

Do not re-derive these; do verify anything you depend on that is not listed.

- **This plan names no interfaces version, deliberately.** It went stale three
  times while the plan was being written and reviewed — 17.0.0, then 24.0.0,
  then 25.0.0, the last of those during a single reply. Every version below is
  written as a rule, not a number: Task 1 publishes `<current major>.<current
minor + 1>.0`, and every later reference means _the version Task 1 actually
  published_.
- `auth-providers` is at **2.0.0** and depends on `@mcp-abap-adt/interfaces@^11.6.0`. That gap was six majors when this plan was drafted and fourteen by the time it was reviewed; whatever it is when you start, it is wide. **All 13 names `auth-providers` imports still existed at every version checked — 16.0.0, 17.0.0, 24.0.0 and 25.0.0** — and `IAuthorizationStrategy` still carries `buildAuthorizationUrl`, `AuthorizationOutcome`, `payload` and `redirectUri`. That is four data points for "the bump is safe", not a guarantee; Task 2 proves it by compiling.
- **Check the version before you start.** Run `npm view @mcp-abap-adt/interfaces version` first, and again before Task 2 installs it. The compatibility check in Task 2 matters more the wider the gap, not less.
- `Saml2CommonConfig` lives in `auth-providers/src/providers/saml2Utils.ts:9`, **not** in `interfaces`. The new configuration fields go there.
- `@mcp-abap-adt/auth-mocks@0.1.1` is published. `startMockSamlIdp` requires `acsUrls` — with none registered it refuses every `AuthnRequest`.
- `xml-crypto@6`: `checkSignature` **throws** when the signature value fails, and returns `false` only for a reference-digest mismatch. Both outcomes mean "invalid".
- `@xmldom/xmldom@0.9`: `getAttribute` decodes entities; `parseFromString` throws on input with no root element. `Node` must be imported from the package — this project has no `dom` lib.

---

## File Structure

**`@mcp-abap-adt/interfaces`** (separate repository, `/home/okyslytsia/prj/mcp-abap-adt-interfaces`)

- Create `src/auth/IAssertionValidator.ts` — `AssertionContext`, `ValidatedAssertion`, `IAssertionValidator`, `AssertionReplayKey`, `IAssertionReplayStore`. One file: they are one contract, and a consumer implementing the validator needs all five in view.
- Modify `src/index.ts` — export them.

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
- Modify `src/index.ts` — export the default validator, the store factory and the error.

The pure modules are separate because each is a rule with its own failure modes, and because `assertionValidator.ts` would otherwise be a file nobody can hold in their head — the check table alone is twelve steps.

---

### Task 1: The interfaces

**Repository:** `/home/okyslytsia/prj/mcp-abap-adt-interfaces`

**Files:**

- Create: `src/auth/IAssertionValidator.ts`
- Modify: `src/index.ts`
- Modify: `src/token/TokenProviderErrorCodes.ts` — add one code

**Interfaces:**

- Produces: everything `auth-providers` imports in Tasks 3–11.

**Before you start:** work on a branch off `master`, whatever version it is at. Do not branch off any feature branch you find. This is a **minor**: nothing existing changes.

- [ ] **Step 1: Write `src/auth/IAssertionValidator.ts`**

```ts
/**
 * Establishing that a SAML assertion may be trusted.
 *
 * Validation is a strategy for the same reason everything else here is: a
 * consumer may have a trust model this package cannot anticipate. The shipped
 * default verifies the signature and refuses anything it cannot place; a
 * consumer replacing it takes on that duty entirely.
 */

import type { ILogger } from "../logging/ILogger";

/** What the provider knows about the login the assertion is answering. */
export interface AssertionContext {
  /** The AuthnRequest ID this response must answer. */
  readonly expectedInResponseTo: string;
  /** Our entity ID, which the AudienceRestriction must name. */
  readonly audience: string;
  /** The ACS the response arrived at; Recipient and Destination must match. */
  readonly acsUrl: string;
  /**
   * Trusted issuer; the assertion's `Issuer` must equal it.
   *
   * Optional on the interface because a custom validator may establish trust
   * without it. The shipped default always receives it.
   */
  readonly expectedIssuer?: string;
  /** For progress messages. Absent means silence — never stdout. */
  readonly logger?: ILogger;
}

/** What a validated assertion yields to the flow. */
export interface ValidatedAssertion {
  /**
   * The earlier of `Conditions/@NotOnOrAfter` and the `NotOnOrAfter` of the
   * bearer confirmation that was accepted — never later than either, so a
   * session cannot outlive a window the assertion itself closed.
   */
  readonly expiresAt: Date;
  readonly assertionId: string;
  readonly issuer: string;
  readonly nameId?: string;
  readonly sessionIndex?: string;
  readonly attributes?: Readonly<Record<string, readonly string[]>>;
  /** The response as it arrived, for a flow that must forward it verbatim. */
  readonly raw: string;
}

/**
 * Establishes that an assertion is genuine, addressed to us, currently valid,
 * and answers a request we made. Rejects by throwing, with a reason naming the
 * check that failed.
 */
export interface IAssertionValidator {
  validate(
    samlResponse: string,
    context: AssertionContext,
  ): Promise<ValidatedAssertion>;
}

/**
 * What identifies an assertion for replay purposes.
 *
 * An assertion's `ID` is unique only within the identity provider that minted
 * it, so a store shared by two providers would reject a perfectly good second
 * login the moment two issuers happened to mint the same `_id`. The key is the
 * pair, never the ID alone.
 */
export interface AssertionReplayKey {
  readonly issuer: string;
  readonly assertionId: string;
}

/** Remembers assertions so a replay is refused. */
export interface IAssertionReplayStore {
  /**
   * Records this key if it is not already recorded, and reports which
   * happened: `true` when newly recorded, `false` when already present — a
   * replay.
   *
   * **Must be atomic.** Two validations of the same assertion running at once
   * must not both be told `true`; a check followed by a separate write is a
   * race, and it is precisely the race a replay exploits.
   *
   * `retainUntil` is the last instant a validator would still accept the
   * assertion — its expiry plus any clock skew allowed — not its expiry. An
   * entry dropped earlier reopens the window in which a replay is accepted.
   */
  recordIfUnseen(key: AssertionReplayKey, retainUntil: Date): Promise<boolean>;
}
```

- [ ] **Step 2: Add the error code**

`auth-providers` needs a code for "the assertion was refused", and reusing
`VALIDATION_ERROR` would give an assertion refusal the same code as a
misconfiguration — the two a consumer most needs to tell apart. In
`src/token/TokenProviderErrorCodes.ts`, beside the existing entries
(`VALIDATION_ERROR`, `REFRESH_ERROR`, `SESSION_DATA_ERROR`,
`SERVICE_KEY_ERROR`, `BROWSER_AUTH_ERROR`):

```ts
  ASSERTION_VALIDATION_ERROR: 'ASSERTION_VALIDATION_ERROR',
```

- [ ] **Step 3: Export from `src/index.ts`**

Add beside the existing `IAuthorizationStrategy` export, following the file's own grouping and ordering:

```ts
export type {
  AssertionContext,
  AssertionReplayKey,
  IAssertionReplayStore,
  IAssertionValidator,
  ValidatedAssertion,
} from "./auth/IAssertionValidator";
```

- [ ] **Step 4: Verify**

```bash
npm run build && npm test
```

Expected: PASS. A type-only addition cannot break a test; if something fails, the export block is in the wrong place or the `ILogger` path is wrong.

- [ ] **Step 5: Check the type surface is actually reachable**

```bash
node -e "const t=require('./dist/index.js'); console.log('runtime exports unchanged:', Object.keys(t).length)"
grep -c "IAssertionValidator" dist/index.d.ts
```

Expected: the `grep` prints at least 1. Types are erased at runtime, so the first command only confirms nothing was added to the runtime surface by accident.

- [ ] **Step 6: Bump the version and write the changelog**

`package.json` to `<current major>.<current minor + 1>.0` — read the current value from `master`'s `package.json`, do not assume the minor is 0. Record the number you chose; Task 2 needs exactly it. Add a matching section to `CHANGELOG.md` describing the addition as what a consumer gains, not as a task number.

- [ ] **Step 7: Commit, push, open the PR — then stop**

```bash
git add src/auth/IAssertionValidator.ts src/index.ts src/token/TokenProviderErrorCodes.ts package.json CHANGELOG.md
git commit -m "feat: interfaces for validating a SAML assertion"
git push -u origin <branch>
gh pr create --fill
```

Do not merge. Do not tag. Report the PR URL and stop; the owner reviews, merges and publishes.

---

### Task 2: Dependencies, and proving the interfaces bump is safe

**Repository:** `/home/okyslytsia/prj/mcp-abap-adt-auth-providers` — and every task from here on.

**Files:**

- Modify: `package.json`

**Interfaces:**

- Consumes: the interfaces minor Task 1 published.

**This task exists because the bump is thirteen majors wide.** The names were checked and all survive, but a compile is the only thing that proves it.

- [ ] **Step 1: Record what passes now**

```bash
npm test 2>&1 | grep -E "^Tests:|^Test Suites:"
```

Write the numbers down; Step 4 compares against them.

- [ ] **Step 2: Change the dependencies**

In `package.json`:

- `dependencies`: `"@mcp-abap-adt/interfaces"` set to `^` plus **the version Task 1 published**, replacing `^11.6.0`, and add `"@xmldom/xmldom": "^0.9.10"`, `"xml-crypto": "^6.1.2"`.
- `devDependencies`: add `"@mcp-abap-adt/auth-mocks": "^0.1.1"`.

If that version is not yet published, Task 1's PR has not been merged and released. **Stop and say so** rather than installing the previous major and working around the missing types.

```bash
npm install
```

- [ ] **Step 3: Compile**

```bash
npm run build && npm run test:check
```

Expected: PASS. If a name has moved, this is where you find out — report exactly which, with the error, rather than adapting the code silently. That would be a finding about this plan's central assumption.

- [ ] **Step 4: Run the suite**

```bash
npm test 2>&1 | grep -E "^Tests:|^Test Suites:"
```

Expected: identical to Step 1. Any change is a finding.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add package.json package-lock.json
git commit -m "chore: interfaces <the version Task 1 published>, and the XML libraries validation needs"
```

---

### Task 3: Strict `xsd:dateTime`

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

### Task 4: Document ID rules

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

### Task 5: Which element the signature covers

**Files:**

- Create: `src/validation/signedNode.ts`
- Test: `src/__tests__/validation/signedNode.test.ts`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `resolveSignedElement(xml: string, doc: Document, certificates: readonly string[]): Element` — the element the signature covers, having verified the signature against one of the certificates. Throws `Error` with a message naming the failure otherwise.

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
import { resolveSignedElement } from "../../validation/signedNode";

const parse = (xml: string) =>
  new DOMParser().parseFromString(xml, "text/xml") as unknown as Document;

const ASSERTION = (id = "_a1") =>
  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}">` +
  `<saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>`;

const RESPONSE = (inner: string, id = "_r1") =>
  `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${id}">` +
  `${inner}</samlp:Response>`;

describe("resolveSignedElement", () => {
  it("returns the Assertion when the Assertion is signed", () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const element = resolveSignedElement(wrapped, parse(wrapped), [
      key.certificatePem,
    ]);
    expect(element.localName).toBe("Assertion");
  });

  it("accepts a certificate later in the rotation list", () => {
    const other = generateKeyMaterial();
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const element = resolveSignedElement(wrapped, parse(wrapped), [
      other.certificatePem,
      key.certificatePem,
    ]);
    expect(element.localName).toBe("Assertion");
  });

  it("refuses a document with no signature", () => {
    const wrapped = RESPONSE(ASSERTION());
    expect(() => resolveSignedElement(wrapped, parse(wrapped), ["x"])).toThrow(
      /no signature/i,
    );
  });

  it("refuses a signature made with a key we do not trust", () => {
    const key = generateKeyMaterial();
    const other = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    expect(() =>
      resolveSignedElement(wrapped, parse(wrapped), [other.certificatePem]),
    ).toThrow(/signature does not verify/i);
  });

  it("refuses content altered after signing", () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key).replace("mock-idp", "other-idp");
    const wrapped = RESPONSE(signed);
    expect(() =>
      resolveSignedElement(wrapped, parse(wrapped), [key.certificatePem]),
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
      resolveSignedElement(wrapped, parse(wrapped), [key.certificatePem]),
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

    expect(() =>
      resolveSignedElement(wrapped, parse(wrapped), [key.certificatePem]),
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
      resolveSignedElement(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/exactly one is required/i);
  });

  it("returns the signed assertion, not the forged sibling", () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION("_real"), key);
    const forged = ASSERTION("_forged").replace("mock-idp", "attacker");
    const wrapped = RESPONSE(`${forged}${signed}`);
    const element = resolveSignedElement(wrapped, parse(wrapped), [
      key.certificatePem,
    ]);
    expect(element.getAttribute("ID")).toBe("_real");
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

import { SignedXml } from "xml-crypto";
import type { Document, Element, Node as XmlNode } from "@xmldom/xmldom";

const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

/**
 * Verifies the signature against the certificates and returns the element it
 * references. Throws when there is no signature, when none of the certificates
 * accepts it, or when the reference names nothing.
 */
export function resolveSignedElement(
  xml: string,
  doc: Document,
  certificates: readonly string[],
): Element {
  const signatures = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
  if (signatures.length === 0) {
    throw new Error("the document carries no signature");
  }
  if (signatures.length > 1) {
    // More than one signature means more than one candidate for "the signed
    // element", which is the ambiguity this module exists to remove.
    throw new Error("the document carries more than one signature");
  }
  const signatureNode = signatures[0];

  let verified = false;
  for (const certificate of certificates) {
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

Expected: PASS, nine cases. RSA key generation makes this suite slower than the others; that is expected.

If the detached-signature fixture verifies where you expected refusal, or fails
to verify at all because lifting the element changed the canonicalised bytes,
**say so and reshape the fixture** rather than deleting the case. The rule it
protects is the one the whole design rests on. Moving the `Signature` to a
sibling position inside the same parent is the other shape worth trying.

- [ ] **Step 5: Prove the rules**

Three mutations, one at a time:

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

### Task 6: The replay store

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
} from "@mcp-abap-adt/interfaces";

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

### Task 7: The error

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

import { TOKEN_PROVIDER_ERROR_CODES } from "@mcp-abap-adt/interfaces";
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
    super(message, TOKEN_PROVIDER_ERROR_CODES.ASSERTION_VALIDATION_ERROR);
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

### Task 8: The default validator

**Files:**

- Create: `src/validation/assertionValidator.ts`
- Test: `src/__tests__/validation/assertionValidator.test.ts`

**Interfaces:**

- Consumes: `parseXsdDateTime` (Task 3); `findDuplicateId`, `readRequiredId` (Task 4); `resolveSignedElement` (Task 5); `defaultReplayStore`, `createInMemoryReplayStore` (Task 6); `AssertionValidationError`, `AssertionCheck` (Task 7); `IAssertionValidator`, `AssertionContext`, `ValidatedAssertion`, `IAssertionReplayStore` (Task 1).
- Produces:

```ts
export interface DefaultAssertionValidatorOptions {
  readonly idpCertificates: readonly string[];
  readonly clockSkewMs?: number;
  readonly replayStore?: IAssertionReplayStore;
}
export function createDefaultAssertionValidator(
  options: DefaultAssertionValidatorOptions,
): IAssertionValidator;
```

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

Saying "everything is read from the signed element" would therefore be false,
and the earlier draft of this task said it. The accurate statement:

| Read from                                                                                                           | Signature on `Response` | Signature on `Assertion` only                               |
| ------------------------------------------------------------------------------------------------------------------- | ----------------------- | ----------------------------------------------------------- |
| Everything inside the assertion — `Issuer`, `Conditions`, `Audience`, the bearer confirmation, the assertion's `ID` | protected               | protected                                                   |
| `Status`, `Response/Issuer`, `Destination`                                                                          | protected               | **not protected** — a misconfiguration check, not a control |

The assertion-only flow is not thereby unsafe, and the reason is worth stating
because it is not obvious: **a declined login carries no assertion.** An
identity provider that refuses does not mint one, so an attacker who flips
`Status` from a failure to `Success` still has no validly signed assertion to
put underneath it, and signature resolution fails before `Status` is ever read.
What establishes success in that flow is the signed assertion satisfying every
assertion-level check — not the `Status` element.

The three checks stay, because they cost nothing and catch a real
misconfiguration, and because with a signed `Response` they are genuine
controls. What changes is the claim made for them. A consumer who needs
`Status`, `Destination` and the response issuer to be _protected_ must require
their identity provider to sign the `Response`; the README says so in Task 12.

**This is the largest file in the plan, and its shape is fixed by the spec's check table.** Implement the checks in the table's order, each throwing `AssertionValidationError` with its own `check` value and its own message. No two messages may share a distinguishing fragment: a test asserting `/Destination/` must not be satisfiable by the `Recipient` refusal.

The structure below gives the skeleton and every rule with its exact condition. Write the body from it; the tests in Step 1 pin every branch.

- [ ] **Step 1: Write the failing tests**

`src/__tests__/validation/assertionValidator.test.ts`. The fixtures are built here rather than taken from the mock, because the mock corrupts values and never removes them, and half these rules are about removal:

```ts
import { describe, expect, it } from "@jest/globals";
import { generateKeyMaterial, signXml } from "@mcp-abap-adt/auth-mocks";
import { createInMemoryReplayStore } from "../../validation/inMemoryReplayStore";
import { createDefaultAssertionValidator } from "../../validation/assertionValidator";

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

  if ((o.signWhat ?? "assertion") === "assertion") {
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
  return signXml(response, KEY, {
    referenceXPath: "//*[local-name(.)='Response']",
  });
}

const encode = (xml: string) => Buffer.from(xml, "utf8").toString("base64");

const context = {
  expectedInResponseTo: REQUEST_ID,
  audience: AUDIENCE,
  acsUrl: ACS,
  expectedIssuer: ISSUER,
};

const validator = (over: Partial<{ clockSkewMs: number }> = {}) =>
  createDefaultAssertionValidator({
    idpCertificates: [KEY.certificatePem],
    replayStore: createInMemoryReplayStore(),
    ...over,
  });

describe("the default assertion validator", () => {
  it("accepts a well-formed assertion and reports what the flow needs", async () => {
    const result = await validator().validate(encode(buildResponse()), context);
    expect(result.assertionId).toBe("_a1");
    expect(result.issuer).toBe(ISSUER);
    expect(result.nameId).toBe("mock-user");
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("accepts a response signed as a whole rather than per assertion", async () => {
    const result = await validator().validate(
      encode(buildResponse({ signWhat: "response" })),
      context,
    );
    expect(result.assertionId).toBe("_a1");
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
    const shared = createDefaultAssertionValidator({
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
 * Three fields are read from the Response rather than the assertion: Status,
 * Response/Issuer and Destination. When only the assertion is signed they lie
 * outside the signature, and they are then misconfiguration checks rather than
 * controls. That is safe because a declined login carries no assertion at all,
 * so flipping Status buys an attacker nothing they can sign.
 */

import { DOMParser, type Document, type Element } from '@xmldom/xmldom';
import type {
  AssertionContext,
  IAssertionReplayStore,
  IAssertionValidator,
  ValidatedAssertion,
} from '@mcp-abap-adt/interfaces';
import {
  type AssertionCheck,
  AssertionValidationError,
} from '../errors/AssertionValidationError';
import { findDuplicateId, readRequiredId } from './documentIds';
import { defaultReplayStore } from './inMemoryReplayStore';
import { resolveSignedElement } from './signedNode';
import { parseXsdDateTime } from './xsdDateTime';

const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

export interface DefaultAssertionValidatorOptions {
  readonly idpCertificates: readonly string[];
  readonly clockSkewMs?: number;
  readonly replayStore?: IAssertionReplayStore;
}

export function createDefaultAssertionValidator(
  options: DefaultAssertionValidatorOptions,
): IAssertionValidator {
  const skew = options.clockSkewMs ?? 0;
  if (!Number.isInteger(skew) || skew < 0) {
    throw new Error(
      `clockSkewMs must be a finite non-negative integer, got ${String(options.clockSkewMs)}`,
    );
  }
  if (options.idpCertificates.length === 0) {
    throw new Error('idpCertificates must not be empty: nothing could be verified');
  }
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
      if (root.localName !== 'Response' || root.namespaceURI !== PROTOCOL_NS) {
        return fail(
          'document',
          `expected the document element to be a samlp:Response, got ${root.localName}`,
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

      // 2 + 3. Verify, and learn which element the signature covers.
      let signed: Element;
      try {
        signed = resolveSignedElement(xml, doc, options.idpCertificates);
      } catch (error) {
        return fail('signature', (error as Error).message);
      }

      // The signed element must be the Assertion, or a Response holding exactly
      // one. Everything below is read from `assertion` and nowhere else.
      const assertion = assertionInside(signed, root);
      if (!assertion) {
        return fail(
          'signedNode',
          'the signature does not cover the assertion this response carries',
        );
      }

      // 4. Status — read from the Response, which is the element that carries it.
      const status = directChild(root, PROTOCOL_NS, 'Status');
      const codeValue = status
        ? directChild(status, PROTOCOL_NS, 'StatusCode')?.getAttribute('Value')
        : null;
      if (!codeValue) return fail('status', 'the response carries no samlp:Status');
      if (codeValue !== SUCCESS) {
        return fail('status', `the identity provider declined the login: ${codeValue}`);
      }

      // 4b. The assertion's own ID.
      const assertionId = readRequiredId(assertion);
      if (!assertionId) return fail('assertionId', 'the assertion carries no ID');

      // 5 + 5b. Issuer.
      const issuer = directChild(assertion, SAML_NS, 'Issuer')?.textContent ?? '';
      if (!issuer) return fail('issuer', 'the assertion carries no Issuer');
      if (context.expectedIssuer && issuer !== context.expectedIssuer) {
        return fail('issuer', `the assertion was issued by ${issuer}, not the trusted issuer`);
      }
      const responseIssuer = directChild(root, SAML_NS, 'Issuer')?.textContent;
      if (responseIssuer && responseIssuer !== issuer) {
        return fail(
          'issuer',
          'the response and the assertion name different issuers',
        );
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

      // 11. Destination.
      const destination = root.getAttribute('Destination');
      if (!destination) {
        return fail('destination', 'the response carries no Destination');
      }
      if (destination !== context.acsUrl) {
        return fail('destination', `the response is addressed to ${destination}, not to us`);
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
function assertionInside(signed: Element, root: Element): Element | null {
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
    if (data.getAttribute('InResponseTo') !== context.expectedInResponseTo) continue;
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

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/validation/assertionValidator.test.ts
````

Expected: PASS, 29 cases.

- [ ] **Step 5: Prove the rules that a wrong-value test alone would not**

Six mutations, one at a time, each reverted before the next. Report per case:

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

### Task 9: The request ID must survive

**Files:**

- Modify: `src/auth/saml2Auth.ts` — `buildSamlAuthorizationUrl`, and delete `parseSamlNotOnOrAfter`
- Modify: `src/providers/saml2Utils.ts` — `Saml2CommonConfig`, `getSamlAssertion`
- Test: `src/__tests__/auth/saml2Auth.test.ts` (existing — update), `src/__tests__/providers/saml2Utils.test.ts`

**Interfaces:**

- Produces:
  - `buildSamlAuthorizationUrl(config): { url: string; requestId?: string }` — `requestId` is present only when this function minted one, which it does not for a pre-built `authorizationUrl`.
  - `getSamlAssertion(config): Promise<{ payload: string; requestId: string; acsUrl: string }>` — throws `ValidationError` when no ID can be established. `acsUrl` is `outcome.redirectUri`: where the strategy actually listened.
  - `Saml2CommonConfig` gains `idpCertificates?: string[]`, `idpEntityId?: string`, `clockSkewMs?: number`, `authnRequestId?: string`, `assertionValidator?: IAssertionValidator`, `assertionReplayStore?: IAssertionReplayStore`. `spEntityId` is **already** there and already required (`src/providers/saml2Utils.ts:11`); it becomes the validator's `audience` and needs no change.

**The rule, from the spec:** the ID must come from somewhere real. Either this package minted it, or the consumer declared it. When neither, that is a configuration error naming the remedy — not a validation failure blamed on the assertion.

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

Remove the function and its tests. Expiry now comes from validation. Any call site is updated in Task 10.

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

The ID is whichever exists, in this order: the one `buildSamlAuthorizationUrl` minted during this login, then `config.authnRequestId`. When neither:

```ts
throw new ValidationError(
  "Cannot validate InResponseTo: this login did not build its own AuthnRequest, " +
    "so authnRequestId must be configured. This happens with a pre-built " +
    "authorizationUrl, or an authorization strategy that supplies an assertion " +
    "without asking for a URL.",
  ["authnRequestId"],
);
```

Match `ValidationError`'s actual constructor signature — check `src/errors/TokenProviderErrors.ts` rather than copying this call shape blindly.

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

### Task 10: Wire both providers

**Files:**

- Modify: `src/providers/Saml2PureProvider.ts`, `src/providers/Saml2BearerProvider.ts`, `src/providers/saml2Utils.ts`
- Test: `src/__tests__/providers/Saml2PureProvider.test.ts`, `src/__tests__/providers/Saml2BearerProvider.test.ts` (existing — update)

**Interfaces:**

- Consumes: everything from Tasks 8 and 9.
- Produces: `resolveAssertionValidator(config): IAssertionValidator` in `saml2Utils.ts` — the consumer's when supplied, otherwise a default built from `idpCertificates`, `clockSkewMs` and `assertionReplayStore`, raising `ValidationError` when `idpCertificates` or `idpEntityId` is missing.

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

```ts
export function resolveAssertionValidator(
  config: Saml2CommonConfig,
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

  return createDefaultAssertionValidator({
    idpCertificates: config.idpCertificates as string[],
    clockSkewMs: config.clockSkewMs,
    replayStore: config.assertionReplayStore,
  });
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
    this.validator = resolveAssertionValidator(config);
    this.config = config;
    // … the rest unchanged
  }
```

`Saml2BearerProvider` does the same.

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

The same validation call, placed **before** `exchangeSamlAssertion`. The exchange still forwards `payload`, unchanged — validation establishes trust, it does not rewrite what UAA receives.

- [ ] **Step 7: Run the whole suite**

```bash
npm test
```

Expected: PASS. Existing provider tests will need `idpCertificates` and `idpEntityId` in their configs, or an `assertionValidator` stub — that is the breaking change working, not a test to weaken. If a test previously asserted an expiry derived from the regex, it now asserts the validated one.

- [ ] **Step 8: Commit**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
git add -A
git commit -m "feat!: both SAML providers validate the assertion before trusting it"
```

---

### Task 11: End to end against the mocks

**Files:**

- Test: `src/__tests__/integration/samlValidation.test.ts`

**Interfaces:**

- Consumes: `startMockSamlIdp`, `visit`, `generateKeyMaterial`, `signXml` from `@mcp-abap-adt/auth-mocks`; the provider from Task 10.

**This is the task that decides whether the validator is right about real documents rather than about the fixtures its author wrote.** The mock's eleven corruption variants each target exactly one check, and four of them — `statusFailure`, `wrongIssuer`, `wrongDestination`, `wrongRecipient` — are precisely what `@node-saml/node-saml` does _not_ judge. Our validator must.

- [ ] **Step 1: Write the test**

Drive a real login through `Saml2PureProvider` with `browserCallbackStrategy({ openUrl: visit })` pointed at `startMockSamlIdp`, registering the ACS the strategy binds. Then, per variant:

```ts
const REFUSED: Array<[SamlVariant, AssertionCheck]> = [
  ["unsigned", "signature"],
  ["wrongKey", "signature"],
  ["tamperedAfterSign", "signature"],
  ["statusFailure", "status"],
  ["wrongIssuer", "issuer"],
  ["notYetValid", "notBefore"],
  ["expired", "notOnOrAfter"],
  ["wrongAudience", "audience"],
  ["wrongInResponseTo", "bearerConfirmation"],
  ["wrongRecipient", "bearerConfirmation"],
  ["wrongDestination", "destination"],
];

for (const [variant, check] of REFUSED) {
  it(`refuses ${variant} at the ${check} check`, async () => {
    // start the IdP with { variant, acsUrls: [acs], issuer, audience },
    // run the login, and:
    await expect(login()).rejects.toMatchObject({ check });
  });
}
```

Asserting the **check**, not merely that it threw, is what stops a variant from being refused for an unrelated reason — the exact defect that took a whole round to find in `auth-mocks`, where seven of nine variants were rejected by one structural bug.

Then the valid case, and the two the mock cannot express:

- **A successful login**: `expiresAt` comes from the assertion, the session cookie is what `cookieProvider` returned.
- **Replay**: `idp.repeatLastAssertion()`, run the login twice, expect `check: 'replay'` the second time.
- **Signature wrapping**: take the mock's signed response, insert a forged assertion beside the signed one, and expect refusal. Build this with `generateKeyMaterial`/`signXml` rather than a variant.

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

### Task 12: Public surface, documentation, and the release PR

**Files:**

- Modify: `src/index.ts`, `README.md`, `CHANGELOG.md`, `package.json`

**Interfaces:**

- Produces: the package's public surface for this feature.

- [ ] **Step 1: Export**

From `src/index.ts`: `createDefaultAssertionValidator`, `DefaultAssertionValidatorOptions`, `createInMemoryReplayStore`, `defaultReplayStore`, `AssertionValidationError`, `AssertionCheck`. Not the internal modules — `parseXsdDateTime`, `findDuplicateId`, `resolveSignedElement` are implementation.

- [ ] **Step 2: Document**

`README.md` must gain, and this is the part a reader will rely on:

- that SAML assertions are now validated, and that this is a **breaking change**: a consumer must supply `idpCertificates` and `idpEntityId`, or their own `assertionValidator`;
- the twelve checks, as the spec's table;
- that `parseSamlNotOnOrAfter` is gone and expiry now comes from the verified document;
- the request-ID rule: when the package does not build the request, `authnRequestId` is required, with the two flows that trigger it;
- that the default replay store is **process-wide**, what that does and does not protect, and how to replace it;
- **which fields the signature protects under each placement**: with the
  signature on the `Assertion` alone, `Status`, `Destination` and the response
  issuer are outside it and are checked as misconfiguration rather than as
  controls. A consumer who needs them protected must require their identity
  provider to sign the `Response`. State plainly why the assertion-only flow is
  still sound — a declined login carries no assertion to sign;
- `clockSkewMs`, its default of `0`, and that retention outlasts it.

Also update the "Package responsibilities" section — this package now validates assertions, which the current text says it does not.

- [ ] **Step 3: Changelog and version**

`3.0.0`. Major: the configuration is required, `buildSamlAuthorizationUrl` changed shape, `parseSamlNotOnOrAfter` is gone, and an identity provider returning a non-`Success` status is now refused where it was previously accepted. Write a migration note saying exactly what a consumer on 2.x must add.

- [ ] **Step 4: Verify**

```bash
npm run lint:check && npm run build && npm run test:check && npm test
```

- [ ] **Step 5: Commit, push, open the PR — then stop**

```bash
git add -A
git commit -m "docs: assertion validation, and what a 2.x consumer must change"
git push -u origin <branch>
gh pr create --fill
```

Do not merge, do not tag, do not publish. Report the PR URL and stop.

---

## Release order

The interfaces minor Task 1 published must be merged and published before Task 2 can install it. If it is not, Task 2 stops rather than working around it. `auth-providers@3.0.0` follows, and the owner publishes both.
