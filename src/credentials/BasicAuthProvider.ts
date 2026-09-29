import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { OK, oops, safely } from '../auth/refusal';

/** A user and a password: a header over HTTP, logon parameters over RFC. */
export class BasicAuthProvider implements IAuthProvider {
  readonly kind = 'basic';

  constructor(
    private readonly username: string,
    private readonly password: string,
  ) {}

  async prepare(): Promise<AuthOutcome> {
    return OK;
  }

  /** Offered; a wire without parameter logon says no, and the header carries it. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    return safely('offering the logon parameters', () => {
      logon.logonParameters({ user: this.username, passwd: this.password });
      return OK;
    });
  }

  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely('writing the Authorization header', () => {
      request.header(
        'Authorization',
        `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`,
      );
      return OK;
    });
  }

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return oops(
      'the user or password was refused',
      'check the user and password',
    );
  }
}
