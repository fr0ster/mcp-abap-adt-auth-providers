/**
 * Type test, compiled by `test:check` and run by nothing (plan Task 24,
 * load-bearing): at a SAML site the builder call is made inside `refuse`,
 * and the rule fixes both its check and the one diagnostic it may carry
 * (`SamlDiagnosticOf<R>`, spec §3.3, Appendix B). `refuse` takes a type that
 * names no rule, so the rule is inferred from the literal at the site — were
 * it the union of every rule's error, the rule would widen and the compiler
 * would check nothing (each `@ts-expect-error` below would then be unused,
 * which fails the build).
 */
import { authError } from '@mcp-abap-adt/auth-errors';
import { refuse } from '../../validation/samlRefusal';

declare const value: unknown;

// The site as written: destination-not-us carries `destination`.
export const site = () =>
  refuse(
    authError['saml-assertion'](
      { rule: 'destination-not-us', check: 'destination' },
      { destination: value },
    ),
  );

export const issuerAtDestinationSite = () =>
  refuse(
    authError['saml-assertion'](
      { rule: 'destination-not-us', check: 'destination' },
      // @ts-expect-error `issuer` is untrusted-issuer's diagnostic, not this rule's.
      { issuer: value },
    ),
  );

export const diagnosticOnARuleWithout = () =>
  refuse(
    authError['saml-assertion'](
      { rule: 'expired', check: 'notOnOrAfter' },
      // @ts-expect-error `expired` carries no diagnostic.
      { notOnOrAfter: value },
    ),
  );

export const misfiledCheck = () =>
  refuse(
    // @ts-expect-error a rule fixes its check: `expired` is `notOnOrAfter`.
    authError['saml-assertion']({ rule: 'expired', check: 'issuer' }),
  );
