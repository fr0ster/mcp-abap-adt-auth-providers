// Rule 7: guard calls that evaluate provider metadata before the boundary —
// a grant that is not a function expression, a provider property read in the
// argument list. Must be found, both.
import { guard, OK } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  OAuth2GrantType,
  Operation,
} from '@mcp-abap-adt/interfaces-auth';

const grantOf = (): OAuth2GrantType | undefined => undefined;

export class Moments {
  readonly operation: Operation = 'preparing';

  byReference(): Promise<AuthOutcome> {
    return guard('preparing', () => OK, grantOf);
  }

  byProperty(): Promise<AuthOutcome> {
    return guard(this.operation, () => OK);
  }
}
