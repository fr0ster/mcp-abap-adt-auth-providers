// Rule 2: a class reaching AuthProviderBase that declares a moment — directly,
// and through a shipped provider (any chain of `extends`). Must be found.
import { OK } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthProviderBase } from '../../src/auth/AuthProviderBase';
import { BasicAuthProvider } from '../../src/credentials/BasicAuthProvider';

export class Overrides extends AuthProviderBase {
  readonly kind = 'overrides';

  constructor() {
    super({
      prepare: 'preparing',
      establish: 'establishing',
      authorize: 'authorizing',
      rejected: 'reading-rejection',
    });
  }

  override async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
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
    return OK;
  }
}

export class Chained extends BasicAuthProvider {
  override async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return OK;
  }
}
