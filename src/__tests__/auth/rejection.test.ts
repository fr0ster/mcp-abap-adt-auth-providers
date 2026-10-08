import { describe, expect, it } from '@jest/globals';
import type { IAuthRejection } from '@mcp-abap-adt/interfaces-auth';
import { readRejection } from '../../auth/rejection';

const at = (
  status: number | undefined,
  error: unknown = new Error('SECRET'),
): IAuthRejection =>
  // As a consumer builds it: `status: undefined` present when there is none.
  ({ at: 'request', status, error }) as IAuthRejection;

describe('readRejection — only a refused credential is the credential', () => {
  it('401 is the credential', () => {
    expect(readRejection(at(401))).toEqual({ verdict: 'credential' });
  });

  it('RFC_LOGON_FAILURE is the credential', () => {
    expect(
      readRejection({ at: 'logon', error: { key: 'RFC_LOGON_FAILURE' } }),
    ).toEqual({ verdict: 'credential' });
  });

  it.each([
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
  ])('%i is not the credential', (status, reason, hint) => {
    const read = readRejection(at(status));
    expect(read.verdict).toBe('not-credential');
    if (read.verdict !== 'not-credential') return;
    expect(read.refusal.reason).toMatch(reason);
    if (hint) expect(read.refusal.hint).toMatch(hint);
    else expect(read.refusal.hint).toBeUndefined();
  });

  it('another allowlisted RFC key is not the credential, and is named', () => {
    const read = readRejection({
      at: 'logon',
      error: { key: 'RFC_COMMUNICATION_FAILURE', message: 'SECRET' },
    });
    expect(read).toEqual({
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
    expect(read.verdict === 'not-credential' && read.refusal.reason).toBe(
      'the RFC call failed (RFC_ABAP_RUNTIME_FAILURE), not as a credential refusal',
    );
  });

  it.each([
    ['no status, no key', at(undefined)],
    ['a key off the allowlist', { at: 'logon', error: { key: 'SECRET_KEY' } }],
    ['a status that is not an HTTP status', at(99)],
    ['a fractional status', at(401.5)],
    ['no rejection at all', undefined],
  ])('%s cannot be told', (_, rejection) => {
    expect(readRejection(rejection as IAuthRejection)).toEqual({
      verdict: 'unknown',
    });
  });

  it('nothing from the error reaches a refusal', () => {
    for (const status of [302, 403, 404, 503]) {
      expect(JSON.stringify(readRejection(at(status)))).not.toMatch(/SECRET/);
    }
  });
});
