/**
 * A token provider whose every login and refresh is a promise the test
 * settles (spec §6b's races): the base class's renewal, commit queue,
 * quarantine and persistence reports run as shipped; only the two grant calls are
 * scripted.
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  IClientAuthentication,
  IRenewalStrategy,
  ITokenPersistence,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { BaseTokenProvider } from '../../providers/BaseTokenProvider';
import { refreshThenLogin } from '../../renewal';
import { Arrivals, type Deferred, deferred } from './attemptHarness';

export interface ScriptedLogin {
  readonly attempt: AttemptContext;
  readonly result: Deferred<ITokenResult>;
}

export interface ScriptedRefresh {
  readonly refreshToken: string;
  readonly result: Deferred<ITokenResult>;
  /** The site's `dispatched()`: already called unless `holdDispatch`. */
  readonly dispatch: () => void;
}

export interface ScriptedConfig {
  /** Required, as on every token provider (rule 7). */
  renewal: IRenewalStrategy;
  persistence?: ITokenPersistence;
  accessToken?: string;
  refreshToken?: string;
  /** The held token's expiry; default: from the JWT, else expired. */
  expiresAt?: number;
  clientAuthentication?: IClientAuthentication;
  logger?: ILogger;
  signal?: AbortSignal;
}

export function tokens(access: string, refresh?: string): ITokenResult {
  return {
    authorizationToken: access,
    refreshToken: refresh,
    authType: 'authorization_code',
    expiresIn: 3600,
  };
}

export class ScriptedProvider extends BaseTokenProvider {
  readonly logins = new Arrivals<ScriptedLogin>();
  readonly refreshes = new Arrivals<ScriptedRefresh>();
  /** True: a refresh waits for the test's `dispatch()` before it is sent. */
  holdDispatch = false;
  /** The access token the provider was seeded with, if any. */
  readonly seededToken: string | undefined;

  constructor(config: ScriptedConfig) {
    super(config);
    this.logger = config.logger;
    this.seededToken = config.accessToken;
    if (config.accessToken !== undefined) {
      this.authorizationToken = config.accessToken;
      this.expiresAt = this.seededExpiry(config.accessToken, config.expiresAt);
    }
    if (config.refreshToken !== undefined) {
      this.refreshToken = config.refreshToken;
    }
  }

  protected performLogin(attempt: AttemptContext): Promise<ITokenResult> {
    const result = deferred<ITokenResult>();
    this.logins.push({ attempt, result });
    return result.promise;
  }

  /**
   * The refresh request leaves at once: `dispatched()` is called on entry,
   * as a site calls it right before the request (an aborted attempt's gate
   * throws, and nothing is sent). With `holdDispatch`, the test dispatches
   * it itself (`ScriptedRefresh.dispatch()`).
   */
  protected performRefresh(
    refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult> {
    const result = deferred<ITokenResult>();
    if (!this.holdDispatch) {
      try {
        dispatched();
      } catch (error) {
        return Promise.reject(error);
      }
    }
    this.refreshes.push({ refreshToken, result, dispatch: dispatched });
    return result.promise;
  }

  protected getAuthType(): OAuth2GrantType {
    return 'authorization_code';
  }

  /** What the provider holds now. */
  held(): {
    access: string | undefined;
    refresh: string | undefined;
    pinned: string | undefined;
  } {
    return {
      access: this.authorizationToken,
      refresh: this.refreshToken,
      pinned: this.pinned?.thumbprint,
    };
  }

  /** Makes the held access token expired, so the next need renews. */
  expire(): void {
    this.expiresAt = Date.now() - 1;
  }
}
