import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { IAuthRejection } from '@mcp-abap-adt/interfaces-auth';
import { readRejection } from '../../auth/rejection';
import { cases, caseTitle, contains, matchText } from '../helpers/expectations';

const at = (
  status: number | undefined,
  error: unknown = new Error('SECRET'),
): IAuthRejection =>
  // As a consumer builds it: `status: undefined` present when there is none.
  ({ at: 'request', status, error }) as IAuthRejection;

describe('readRejection — only a refused credential is the credential', () => {
  it('401 is the credential', () => {
    assert.deepEqual(readRejection(at(401)), { verdict: 'credential' });
  });

  it('RFC_LOGON_FAILURE is the credential', () => {
    assert.deepEqual(
      readRejection({ at: 'logon', error: { key: 'RFC_LOGON_FAILURE' } }),
      { verdict: 'credential' },
    );
  });

  for (const [caseIndex, caseRow] of cases([
    [403, /accepted, but the user is not authorized \(403\)/, /authorizations/],
    [
      302,
      /redirected instead of accepting the credential \(302\)/,
      /logon procedure/,
    ],
    [503, /the system failed \(503\), not the credential/, /try again later/],
    [
      404,
      /the system answered 404, which is not a credential refusal/,
      undefined,
    ],
  ]).entries()) {
    const [status, reason, hint] = caseRow;
    it(caseTitle('%i is not the credential', caseRow, caseIndex), () => {
      const read = readRejection(at(status));
      assert.equal(read.verdict, 'not-credential');
      if (read.verdict !== 'not-credential') return;
      matchText(read.refusal.reason, reason);
      if (hint) matchText(read.refusal.hint, hint);
      else assert.equal(read.refusal.hint, undefined);
    });
  }

  it('another allowlisted RFC key is not the credential, and is named', () => {
    const read = readRejection({
      at: 'logon',
      error: { key: 'RFC_COMMUNICATION_FAILURE', message: 'SECRET' },
    });
    assert.deepEqual(read, {
      verdict: 'not-credential',
      refusal: {
        kind: 'system-refused',
        facts: {
          verdict: 'rfc-failure',
          rfcKey: 'RFC_COMMUNICATION_FAILURE',
          at: 'logon',
        },
        reason:
          'the RFC logon failed (RFC_COMMUNICATION_FAILURE), not as a credential refusal',
      },
    });
  });

  it('an RFC key at a request says call, not logon', () => {
    const read = readRejection({
      at: 'request',
      error: { key: 'RFC_ABAP_RUNTIME_FAILURE' },
    });
    assert.equal(
      read.verdict === 'not-credential' && read.refusal.reason,
      'the RFC call failed (RFC_ABAP_RUNTIME_FAILURE), not as a credential refusal',
    );
  });

  for (const [caseIndex, caseRow] of cases([
    ['no status, no key', at(undefined)],
    ['a key off the allowlist', { at: 'logon', error: { key: 'SECRET_KEY' } }],
    ['a status that is not an HTTP status', at(99)],
    ['a fractional status', at(401.5)],
    ['no rejection at all', undefined],
  ]).entries()) {
    const [_, rejection] = caseRow;
    it(caseTitle('%s cannot be told', caseRow, caseIndex), () => {
      assert.deepEqual(readRejection(rejection as IAuthRejection), {
        verdict: 'unknown',
      });
    });
  }

  it('nothing from the error reaches a refusal', () => {
    for (const status of [302, 403, 404, 503]) {
      assert.doesNotMatch(JSON.stringify(readRejection(at(status))), /SECRET/);
    }
  });
});
