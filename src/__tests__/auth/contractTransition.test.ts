import { authError, isMinted } from '@mcp-abap-adt/auth-errors';
import {
  toLegacyOutcome,
  toLegacyRefusal,
} from '../../auth/contractTransition';

describe('contractTransition (temporary, removed in Task 27)', () => {
  const withHint = authError['client-certificate']({ problem: 'expired' });
  const withoutHint = authError.unknown({ operation: 'token-refresh' });

  it('the fixtures are what the cases need: one minted error with a hint, one without', () => {
    expect(typeof withHint.hint).toBe('string');
    expect(Object.hasOwn(withoutHint, 'hint')).toBe(false);
  });

  it('toLegacyRefusal returns the minted error itself when it carries a hint', () => {
    const refusal = toLegacyRefusal(withHint);
    expect(refusal).toBe(withHint);
    expect(isMinted(refusal)).toBe(true);
  });

  it('toLegacyRefusal returns the minted error itself when it carries no hint, and adds no hint key', () => {
    const refusal = toLegacyRefusal(withoutHint);
    expect(refusal).toBe(withoutHint);
    expect(Object.hasOwn(refusal, 'hint')).toBe(false);
  });

  it('toLegacyRefusal never yields a hint: undefined key', () => {
    // Not something a builder makes (it omits absent keys): the fallback arm,
    // reached only by a value that breaks the minted shape.
    const odd = {
      ...withoutHint,
      hint: undefined,
    } as unknown as typeof withoutHint;
    const refusal = toLegacyRefusal(odd);
    expect(refusal).not.toBe(odd);
    expect(refusal).toEqual({ reason: withoutHint.reason });
    expect(Object.hasOwn(refusal, 'hint')).toBe(false);
  });

  it('toLegacyOutcome passes Ok through and carries the same refusal object', () => {
    expect(toLegacyOutcome({ ok: true })).toEqual({ ok: true });
    const outcome = toLegacyOutcome({ ok: false, refusal: withHint });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal).toBe(withHint);
    const hintless = toLegacyOutcome({ ok: false, refusal: withoutHint });
    if (hintless.ok) throw new Error('expected a refusal');
    expect(hintless.refusal).toBe(withoutHint);
    expect(Object.hasOwn(hintless.refusal, 'hint')).toBe(false);
  });
});
