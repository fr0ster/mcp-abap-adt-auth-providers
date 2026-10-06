/**
 * How a SAML refusal leaves its site (spec Appendix B, A.6): an
 * `AuthProviderFailure` holding one minted `saml-assertion` error. The
 * builder call — `authError['saml-assertion']({ rule, check, … }, { … })` —
 * stays at each site, so the compiler checks that the rule fixes its check
 * and that the one diagnostic it may carry is the one passed; this module
 * only throws what the site built.
 *
 * No document value reaches `reason` / `hint`: a value a rule may show is a
 * diagnostic, admitted (or dropped) by the builder (spec §5.3). No message of
 * a parser, of xml-crypto or of OpenSSL reaches the error at all (L7).
 */

import {
  AuthProviderFailure,
  classify,
  count,
  isMinted,
} from '@mcp-abap-adt/auth-errors';
import type {
  AssertionContext,
  IAssertionValidator,
  ValidatedAssertion,
} from '@mcp-abap-adt/interfaces-auth';
import { answered } from '../auth/handled';

/**
 * What a site hands `refuse`: the builder's result, typed by its kind alone.
 * Deliberately not the union of every rule's error — a union as the
 * contextual type of the builder call would be inferred as its rule, widening
 * the rule to all 56 (the builder's `One<R>` then refuses it). With a
 * contextual type that names no rule, the rule is inferred from the literal
 * at the site, and so is the one diagnostic it may carry.
 */
export interface SamlRefusal {
  readonly kind: 'saml-assertion';
}

/**
 * Throws the refusal a site built, as an `AuthProviderFailure`. Every caller
 * passes a builder's result, which this copy minted; anything else (never, by
 * construction) is classified rather than trusted.
 */
export function refuse(error: SamlRefusal): never {
  throw new AuthProviderFailure(
    isMinted(error) ? error : classify(error, 'validating-assertion'),
  );
}

/** A "carries N" count, branded by auth-errors' maker. */
type Count = NonNullable<ReturnType<typeof count>>;

/**
 * The `count` fact of a "carries N" rule: present when `n` is a count of two
 * or more (every caller passes the length of a list longer than one).
 */
export function several(n: number): { readonly count: Count } | object {
  const made = count(n);
  return made === undefined || made < 2 ? {} : { count: made };
}

/**
 * The validator's answer, or its throw classified with `validating-assertion`
 * (spec A.8): a shipped validator's refusal is this copy's minted error and
 * passes as it is, diagnostics included; anything a custom validator throws
 * becomes what `classify` makes of it — never its message.
 */
export async function validateAssertion(
  validator: IAssertionValidator,
  payload: string,
  context: AssertionContext,
): Promise<ValidatedAssertion> {
  try {
    return (await answered(validator.validate(payload, context))).value;
  } catch (error) {
    throw new AuthProviderFailure(classify(error, 'validating-assertion'));
  }
}
