import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { OK, safely } from '../auth/refusal';
import { refuseFor } from '../auth/rejection';

/** A SAML session negotiated elsewhere and handed over as cookies. */
export class SamlAuthProvider implements IAuthProvider {
  readonly kind = 'saml';

  constructor(private readonly sessionCookies: string) {}

  async prepare(): Promise<AuthOutcome> {
    return OK;
  }

  async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
  }

  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely('writing the session cookies', () => {
      request.cookies(this.sessionCookies);
      return OK;
    });
  }

  /** Blames the session only when the system refused the credential. */
  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely('reading the rejection', () =>
      refuseFor(rejection, {
        reason: 'the SAML session was refused or has expired',
        hint: 'obtain a new SAML session',
      }),
    );
  }
}
