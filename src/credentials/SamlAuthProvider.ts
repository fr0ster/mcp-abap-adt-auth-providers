import { OK } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthRejection,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import { markHandled } from '../auth/handled';
import { refuseFor } from '../auth/rejection';

/** A SAML session negotiated elsewhere and handed over as cookies. */
export class SamlAuthProvider extends AuthProviderBase {
  readonly kind = 'saml';

  constructor(private readonly sessionCookies: string) {
    super({
      prepare: 'preparing',
      establish: 'establishing',
      authorize: 'writing-session-cookies',
      rejected: 'reading-rejection',
    });
  }

  protected onPrepare(): AuthOutcome {
    return OK;
  }

  protected onEstablish(): AuthOutcome {
    return OK;
  }

  protected onAuthorize(request: IRequestTarget): AuthOutcome {
    // A target answering a rejecting promise raises nothing (rule 1).
    markHandled(request.cookies(this.sessionCookies));
    return OK;
  }

  /** Blames the session only when the system refused the credential. */
  protected onRejected(rejection: IAuthRejection): AuthOutcome {
    return refuseFor(rejection, 'saml-session');
  }
}
