import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { OK, oops, safely } from '../auth/refusal';

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

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return oops(
      'the SAML session was refused or has expired',
      'obtain a new SAML session',
    );
  }
}
