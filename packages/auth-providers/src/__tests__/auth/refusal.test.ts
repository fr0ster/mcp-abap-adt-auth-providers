/**
 * What a foreign throw becomes (rule 2): `classify` alone — this package's
 * classes and their ladder are gone, so every thrown value a site or a
 * collaborator produces is read the same way. The class cases that lived here
 * moved to the row tests of the producers and sites.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
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
    assert.deepEqual(OK, { ok: true });
    assert.equal(Object.isFrozen(OK), true);
  });

  it('a foreign error: "unknown error", plus an allowlisted code only', () => {
    const axios = Object.assign(new Error('Basic U0VDUkVU'), {
      name: 'AxiosError',
      code: 'ECONNREFUSED',
      response: { data: 'SECRET' },
    });
    assert.deepEqual(wordsOf(refused(axios, 'token-request')), {
      ok: false,
      refusal: {
        reason: 'the token request failed (unknown error, ECONNREFUSED)',
      },
    });
    const forged = Object.assign(new Error('x'), {
      name: 'SECRETError',
      code: 'ESECRET',
    });
    assert.deepEqual(wordsOf(refused(forged, 'token-request')), {
      ok: false,
      refusal: { reason: 'the token request failed (unknown error)' },
    });
  });

  it('a thrown string or object lends nothing', () => {
    assert.deepEqual(wordsOf(refused('SECRET-STRING', 'token-source')), {
      ok: false,
      refusal: { reason: 'the token source failed (unknown error)' },
    });
    assert.equal(
      text(
        refused(
          { message: 'SECRET', key: 'SECRET_KEY', code: 'ENOENT' },
          'loading-certificate',
        ),
      ),
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
    assert.equal(outcome.refusal.kind, 'unknown');
    assert.doesNotMatch(text(outcome), /SECRET/);
  });
});
