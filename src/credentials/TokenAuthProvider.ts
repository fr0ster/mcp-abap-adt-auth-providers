import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
  ITokenRefresher,
} from '@mcp-abap-adt/interfaces-auth';
import { OK, oops, safely } from '../auth/refusal';
import { readRejection, unknownRefusal } from '../auth/rejection';

/**
 * A token that comes from outside this package — a fixed string, or the
 * broker's refresher. A token provider from this package needs no wrapper: it
 * is an IAuthProvider itself.
 */
export class TokenAuthProvider implements IAuthProvider {
  readonly kind = 'token';
  /** The token last put on a request, so rejected() can tell a renewal from a repeat. */
  private presented?: string;

  private constructor(
    private readonly current: () => Promise<string>,
    private readonly renew: (() => Promise<string>) | undefined,
  ) {}

  static fixed(token: string): TokenAuthProvider {
    return new TokenAuthProvider(async () => token, undefined);
  }

  static from(refresher: ITokenRefresher): TokenAuthProvider {
    return new TokenAuthProvider(
      () => refresher.getToken(),
      () => refresher.refreshToken(),
    );
  }

  async prepare(): Promise<AuthOutcome> {
    return OK;
  }

  async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
  }

  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely('the token source', async () => {
      const token = await this.current();
      request.header('Authorization', `Bearer ${token}`);
      this.presented = token;
      return OK;
    });
  }

  /** Renews only a refused credential, or one the rejection cannot tell. */
  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely('the token source', async () => {
      const read = readRejection(rejection);
      if (read.verdict === 'not-credential') {
        return { ok: false, refusal: read.refusal };
      }
      const renew = this.renew;
      if (!renew) {
        return read.verdict === 'credential'
          ? oops('the token was refused', 'obtain a new token')
          : { ok: false, refusal: unknownRefusal(rejection) };
      }
      const renewed = await renew();
      if (this.presented !== undefined && renewed === this.presented) {
        return oops(
          'the renewal returned the credential that was refused',
          'the token source must issue a new token',
        );
      }
      return OK;
    });
  }
}
