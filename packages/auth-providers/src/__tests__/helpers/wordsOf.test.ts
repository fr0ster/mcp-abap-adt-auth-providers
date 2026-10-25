import { describe, expect, it } from '@jest/globals';
import { authError } from '@mcp-abap-adt/auth-errors';
import type { AuthOutcome } from '@mcp-abap-adt/interfaces-auth';
import { wordsOf } from './minted';

describe('wordsOf still checks the whole outcome', () => {
  it('a minted refusal reads as its words', () => {
    const outcome: AuthOutcome = {
      ok: false,
      refusal: authError['client-certificate']({ problem: 'expired' }),
    };
    expect(wordsOf(outcome)).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate has expired',
        hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
      },
    });
    expect(wordsOf({ ok: true })).toEqual({ ok: true });
  });

  it('a stray key on the refusal fails', () => {
    const stray = {
      ok: false,
      refusal: { reason: 'r', code: 'SECRET' },
    } as unknown as AuthOutcome;
    expect(() => wordsOf(stray)).toThrow();
  });

  it('a stray key on the outcome fails', () => {
    expect(() =>
      wordsOf({ ok: true, refusal: { reason: 'r' } } as unknown as AuthOutcome),
    ).toThrow();
    expect(() =>
      wordsOf({
        ok: false,
        refusal: { reason: 'r' },
        cause: 'SECRET',
      } as unknown as AuthOutcome),
    ).toThrow();
  });
});
