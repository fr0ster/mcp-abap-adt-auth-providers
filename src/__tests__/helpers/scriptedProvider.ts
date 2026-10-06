/**
 * A token provider whose every login and refresh is a promise the test
 * settles (spec §6b's races): the base class's renewal, commit queue,
 * quarantine and dispositions run as shipped; only the two grant calls are
 * scripted.
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  IClientAuthentication,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { BaseTokenProvider } from '../../providers/BaseTokenProvider';
import { Arrivals, type Deferred, deferred } from './attemptHarness';

export interface ScriptedLogin {
  readonly attempt: AttemptContext;
  readonly result: Deferred<ITokenResult>;
}

export interface ScriptedRefresh {
  readonly refreshToken: string;
  readonly result: Deferred<ITokenResult>;
}

export interface ScriptedConfig {
  onTokens?: (result: ITokenResult) => Promise<void>;
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

  constructor(config: ScriptedConfig = {}) {
    super(config);
    this.logger = config.logger;
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

  protected performRefresh(refreshToken: string): Promise<ITokenResult> {
    const result = deferred<ITokenResult>();
    this.refreshes.push({ refreshToken, result });
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
