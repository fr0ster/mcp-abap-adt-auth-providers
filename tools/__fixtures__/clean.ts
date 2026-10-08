// None of rules 1–8: a provider as this package writes one — it extends the
// base, implements the `on…` hooks, and relays a minted refusal. Must pass.
import { authError, OK } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthProviderBase } from '../../src/auth/AuthProviderBase';

export class Obeys extends AuthProviderBase {
  readonly kind = 'obeys';

  constructor() {
    super({
      prepare: 'preparing',
      establish: 'establishing',
      authorize: 'authorizing',
      rejected: 'reading-rejection',
    });
  }

  protected onPrepare(): AuthOutcome {
    return OK;
  }

  protected onEstablish(_logon: ILogonTarget): AuthOutcome {
    return OK;
  }

  protected onAuthorize(_request: IRequestTarget): AuthOutcome {
    return OK;
  }

  protected onRejected(_rejection: IAuthRejection): AuthOutcome {
    const refusal = authError['credential-refused']({ credential: 'token' });
    return { ok: false, refusal };
  }
}
