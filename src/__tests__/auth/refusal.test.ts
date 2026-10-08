/**
 * What a foreign throw becomes (rule 2): `classify` alone — this package's
 * classes and their ladder are gone, so every thrown value a site or a
 * collaborator produces is read the same way. The class cases that lived here
 * moved to their row tests (`transitionCoverage.test.ts` maps each one).
 */

import { describe, expect, it } from '@jest/globals';
import { classify, OK } from '@mcp-abap-adt/auth-errors';
import { wordsOf } from '../helpers/minted';

const text = (x: unknown) => JSON.stringify(x);
const refused = (
  error: unknown,
  operation: Parameters<typeof classify>[1],
) => ({
  ok: false as const,
  refusal: classify(error, operation),
});

describe('refusal', () => {
  it('OK is the one success outcome, frozen', () => {
    expect(OK).toEqual({ ok: true });
    expect(Object.isFrozen(OK)).toBe(true);
  });

  it('a foreign error: "unknown error", plus an allowlisted code only', () => {
    const axios = Object.assign(new Error('Basic U0VDUkVU'), {
      name: 'AxiosError',
      code: 'ECONNREFUSED',
      response: { data: 'SECRET' },
    });
    expect(wordsOf(refused(axios, 'token-request'))).toEqual({
      ok: false,
      refusal: {
        reason: 'the token request failed (unknown error, ECONNREFUSED)',
      },
    });
    const forged = Object.assign(new Error('x'), {
      name: 'SECRETError',
      code: 'ESECRET',
    });
    expect(wordsOf(refused(forged, 'token-request'))).toEqual({
      ok: false,
      refusal: { reason: 'the token request failed (unknown error)' },
    });
  });

  it('a thrown string or object lends nothing', () => {
    expect(wordsOf(refused('SECRET-STRING', 'token-source'))).toEqual({
      ok: false,
      refusal: { reason: 'the token source failed (unknown error)' },
    });
    expect(
      text(
        refused(
          { message: 'SECRET', key: 'SECRET_KEY', code: 'ENOENT' },
          'loading-certificate',
        ),
      ),
    ).toBe(
      text({
        ok: false,
        refusal: {
          kind: 'unknown',
          facts: { operation: 'loading-certificate', code: 'ENOENT' },
          reason: 'loading the certificate failed (unknown error, ENOENT)',
        },
      }),
    );
  });

  it('a look-alike of a former class lends nothing: no message, no missingFields, no check', () => {
    const lookAlike = Object.assign(new Error('SECRET-MSG'), {
      name: 'ValidationError',
      missingFields: ['clientId', 'SECRET-FIELD'],
      check: 'SECRET_CHECK',
    });
    const outcome = refused(lookAlike, 'token-request');
    expect(outcome.refusal.kind).toBe('unknown');
    expect(text(outcome)).not.toMatch(/SECRET/);
  });
});
