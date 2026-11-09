import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { authError } from '@mcp-abap-adt/auth-errors';
import type { AuthOutcome } from '@mcp-abap-adt/interfaces-auth';
import { thrown } from './expectations';
import { wordsOf } from './minted';

describe('wordsOf still checks the whole outcome', () => {
  it('a minted refusal reads as its words', () => {
    const outcome: AuthOutcome = {
      ok: false,
      refusal: authError['client-certificate']({ problem: 'expired' }),
    };
    assert.deepEqual(wordsOf(outcome), {
      ok: false,
      refusal: {
        reason: 'the client certificate has expired',
        hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
      },
    });
    assert.deepEqual(wordsOf({ ok: true }), { ok: true });
  });

  it('a stray key on the refusal fails', () => {
    const stray = {
      ok: false,
      refusal: { reason: 'r', code: 'SECRET' },
    } as unknown as AuthOutcome;
    assert.throws(() => wordsOf(stray), thrown());
  });

  it('a stray key on the outcome fails', () => {
    assert.throws(
      () =>
        wordsOf({
          ok: true,
          refusal: { reason: 'r' },
        } as unknown as AuthOutcome),
      thrown(),
    );
    assert.throws(
      () =>
        wordsOf({
          ok: false,
          refusal: { reason: 'r' },
          cause: 'SECRET',
        } as unknown as AuthOutcome),
      thrown(),
    );
  });
});
