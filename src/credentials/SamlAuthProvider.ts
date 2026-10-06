import type {
  IAuthRejection,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import type { AnyOutcome } from '../auth/contractTransition';
import { OK } from '../auth/refusal';
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

  protected onPrepare(): AnyOutcome {
    return OK;
  }

  protected onEstablish(): AnyOutcome {
    return OK;
  }

  protected onAuthorize(request: IRequestTarget): AnyOutcome {
    request.cookies(this.sessionCookies);
    return OK;
  }

  /** Blames the session only when the system refused the credential. */
  protected onRejected(rejection: IAuthRejection): AnyOutcome {
    return refuseFor(rejection, 'saml-session');
  }
}
