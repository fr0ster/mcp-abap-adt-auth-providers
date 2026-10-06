/**
 * Type test, compiled by `test:check` and run by nothing (temporary, removed
 * in Task 27 with `contractTransition.ts`). C1: a minted error's
 * `hint?: string | undefined` does not assign to the 4.x refusal's
 * `hint?: string` under `exactOptionalPropertyTypes` (TS2375), so a 5.x
 * outcome reaches a 4.x-typed return only through `toLegacyOutcome`.
 */
import { authError } from '@mcp-abap-adt/auth-errors';
import type { AuthOutcome } from '@mcp-abap-adt/interfaces-auth';
import { toLegacyOutcome } from '../../auth/contractTransition';

const minted = authError['client-certificate']({ problem: 'expired' });

// @ts-expect-error TS2375: a minted error is not directly a 4.x refusal.
export const direct: Extract<AuthOutcome, { ok: false }>['refusal'] = minted;

export const bridged: AuthOutcome = toLegacyOutcome({
  ok: false,
  refusal: minted,
});
