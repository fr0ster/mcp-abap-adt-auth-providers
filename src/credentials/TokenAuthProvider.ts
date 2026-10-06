import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthRejection,
  IRequestTarget,
  ITokenRefresher,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import type { AnyOutcome } from '../auth/contractTransition';
import { OK } from '../auth/refusal';
import { momentOf, readRejection, unknownRefusal } from '../auth/rejection';

/**
 * A token that comes from outside this package — a fixed string, or the
 * broker's refresher. A token provider from this package needs no wrapper: it
 * is an IAuthProvider itself.
 */
export class TokenAuthProvider extends AuthProviderBase {
  readonly kind = 'token';
  /** The token last put on a request, so rejected() can tell a renewal from a repeat. */
  private presented?: string;

  private constructor(
    private readonly current: () => Promise<string>,
    private readonly renew: (() => Promise<string>) | undefined,
  ) {
    super({
      prepare: 'preparing',
      establish: 'establishing',
      authorize: 'token-source',
      rejected: 'token-source',
    });
  }

  static fixed(token: string): TokenAuthProvider {
    return new TokenAuthProvider(async () => token, undefined);
  }

  static from(refresher: ITokenRefresher): TokenAuthProvider {
    return new TokenAuthProvider(
      () => refresher.getToken(),
      () => refresher.refreshToken(),
    );
  }

  protected onPrepare(): AnyOutcome {
    return OK;
  }

  protected onEstablish(): AnyOutcome {
    return OK;
  }

  protected async onAuthorize(request: IRequestTarget): Promise<AnyOutcome> {
    const token = await this.current();
    request.header('Authorization', `Bearer ${token}`);
    this.presented = token;
    return OK;
  }

  /** Renews only a refused credential, or one the rejection cannot tell. */
  protected async onRejected(rejection: IAuthRejection): Promise<AnyOutcome> {
    const read = readRejection(rejection);
    if (read.verdict === 'not-credential') {
      return { ok: false, refusal: read.refusal };
    }
    const renew = this.renew;
    if (!renew) {
      return read.verdict === 'credential'
        ? {
            ok: false,
            refusal: authError['credential-refused']({
              credential: 'token',
              at: momentOf(rejection),
            }),
          }
        : { ok: false, refusal: unknownRefusal(rejection) };
    }
    const renewed = await renew();
    if (this.presented !== undefined && renewed === this.presented) {
      return {
        ok: false,
        refusal: authError['renewal-unchanged']({ source: 'token-source' }),
      };
    }
    return OK;
  }
}
