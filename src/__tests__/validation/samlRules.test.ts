/**
 * The SAML rule set as a whole: every one of the 56 rules has a test at its site
 * (through `validate()`, `resolveSignedElements` or `toBearerAssertion`)
 * asserting its `rule`, its fixed `check`, its own words and its diagnostic
 * or the absence of one — `expectSamlRefusal` in `helpers/samlRefusal.ts`.
 * This file checks the set: the fragments are unique within a check, and
 * every rule is asserted by some test.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import {
  authError,
  classify,
  isAssertionCheck,
  isAssertionRule,
} from '@mcp-abap-adt/auth-errors';
import type { AssertionRule } from '@mcp-abap-adt/interfaces-auth';
import { refuse } from '../../validation/samlRefusal';
import {
  expectSamlRefusal,
  RULE_CHECK,
  RULE_WORDS,
  thrownBy,
} from '../helpers/samlRefusal';

const RULES = Object.keys(RULE_CHECK).filter(isAssertionRule);

/**
 * The words auth-errors renders for a rule, with no optional fact: the
 * structural rebuild of `classify` takes the rule as data, so one function
 * reads all 56 without naming each literal.
 */
const wordsOf = (rule: AssertionRule): string =>
  classify(
    { kind: 'saml-assertion', facts: { rule, check: RULE_CHECK[rule] } },
    'unfamiliar-error',
  ).reason;

describe('the SAML rule set', () => {
  it('names 56 rules, each with a check of the allowlist', () => {
    expect(RULES).toHaveLength(56);
    expect(Object.keys(RULE_CHECK)).toHaveLength(56);
    for (const rule of RULES)
      expect(isAssertionCheck(RULE_CHECK[rule])).toBe(true);
  });

  it.each(RULES)(
    '%s: its fragment is in its words and in no neighbour’s',
    (rule) => {
      expect(wordsOf(rule)).toContain(RULE_WORDS[rule]);
      for (const other of RULES) {
        if (other === rule || RULE_CHECK[other] !== RULE_CHECK[rule]) continue;
        expect(wordsOf(other)).not.toContain(RULE_WORDS[rule]);
      }
    },
  );
});

/**
 * Every rule is asserted through `expectSamlRefusal` / `expectSamlRejection`
 * in the suites at the rule's site. Read from their source, so a rule whose
 * only test is deleted turns this red.
 */
describe('every SAML rule has a test at its site', () => {
  const SUITES = [
    'validation/assertionValidator.test.ts',
    'validation/signedNode.test.ts',
    'auth/samlBearerAssertion.test.ts',
  ];
  const asserted = new Set<string>();
  for (const suite of SUITES) {
    const source = readFileSync(join(__dirname, '..', suite), 'utf8');
    for (const call of ['expectSamlRefusal(', 'expectSamlRejection(']) {
      let at = source.indexOf(call);
      while (at >= 0) {
        // The rule is the nearest quoted rule id after the call: its
        // second argument (the first is a promise or a thrown value).
        let nearest: string | undefined;
        let nearestAt = Number.POSITIVE_INFINITY;
        for (const rule of RULES) {
          const found = source.indexOf(`'${rule}'`, at);
          if (found >= 0 && found < nearestAt) {
            nearest = rule;
            nearestAt = found;
          }
        }
        if (nearest !== undefined) asserted.add(nearest);
        at = source.indexOf(call, at + call.length);
      }
    }
  }

  it.each(RULES)('%s', (rule) => {
    expect(asserted.has(rule)).toBe(true);
  });
});

/**
 * Load-bearing: the one diagnostic a rule may carry is
 * decided twice — by the type at a TypeScript site
 * (`samlDiagnostics.typecheck.ts`), and at run time by the admission table
 * (interfaces-auth's `SAML_RULE_DIAGNOSTIC`, read by auth-errors' builder)
 * for a JavaScript-typed call, which the type cannot see.
 */
describe('the admission table, through a JavaScript-typed call', () => {
  /**
   * The builder called as JavaScript would: `Reflect.apply` types neither
   * the arguments nor the result, so nothing is checked at compile time.
   */
  const untyped = (facts: unknown, diagnostics: unknown) =>
    Reflect.apply(authError['saml-assertion'], undefined, [facts, diagnostics]);
  const DESTINATION_NOT_US = {
    rule: 'destination-not-us',
    check: 'destination',
  };

  it('drops the issuer diagnostic passed at the destination-not-us site', () => {
    const error = expectSamlRefusal(
      thrownBy(() =>
        refuse(untyped(DESTINATION_NOT_US, { issuer: 'urn:attacker' })),
      ),
      'destination-not-us',
    );
    expect(JSON.stringify(error)).not.toContain('urn:attacker');
  });

  it('keeps the destination diagnostic the rule permits (the positive control)', () => {
    expectSamlRefusal(
      thrownBy(() =>
        refuse(
          untyped(DESTINATION_NOT_US, {
            destination: 'https://elsewhere/acs',
            issuer: 'urn:attacker',
          }),
        ),
      ),
      'destination-not-us',
      { diagnostics: { destination: 'https://elsewhere/acs' } },
    );
  });
});
