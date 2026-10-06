import { relayOutcome } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import type { AnyOutcome } from '../auth/contractTransition';
import { OK } from '../auth/refusal';
import { refuseFor } from '../auth/rejection';

/** A user and a password: a header over HTTP, logon parameters over RFC. */
export class BasicAuthProvider extends AuthProviderBase {
  readonly kind = 'basic';

  constructor(
    private readonly username: string,
    private readonly password: string,
  ) {
    super({
      prepare: 'preparing',
      establish: 'offering-logon-parameters',
      authorize: 'writing-authorization-header',
      rejected: 'reading-rejection',
    });
  }

  protected onPrepare(): AnyOutcome {
    return OK;
  }

  /**
   * Offered; a wire without parameter logon says no, and the header carries
   * it — another way in (rule 4). Only a target that throws is broken.
   */
  protected onEstablish(logon: ILogonTarget): AnyOutcome {
    const relayed = relayOutcome(
      () =>
        logon.logonParameters({ user: this.username, passwd: this.password }),
      'logon-parameters',
      'offering-logon-parameters',
    );
    return relayed.thrown ? relayed.outcome : OK;
  }

  protected onAuthorize(request: IRequestTarget): AnyOutcome {
    request.header(
      'Authorization',
      `Basic ${Buffer.from(`${this.username ?? ''}:${this.password ?? ''}`).toString('base64')}`,
    );
    return OK;
  }

  /** Blames the password only when the system refused the credential. */
  protected onRejected(rejection: IAuthRejection): AnyOutcome {
    return refuseFor(rejection, 'user-password');
  }
}
