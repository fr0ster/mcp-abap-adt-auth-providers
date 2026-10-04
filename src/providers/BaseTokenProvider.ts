/**
 * Base Token Provider
 *
 * Abstract base class for all token providers.
 * Implements common token lifecycle management:
 * - Token caching
 * - Expiration checking
 * - Automatic refresh/relogin
 */

import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ICertificateMaterial,
  IClientAuthentication,
  ILogonTarget,
  IRefreshableTokenProvider,
  IRequestTarget,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  assertCertificateMaterial,
  assertNotExpired,
  certificateNotAfter,
  certificateThumbprint,
} from '../auth/certificateMaterial';
import {
  OK,
  oops,
  ownLabel,
  refusalFrom,
  safely,
  TOKEN_BOUND_ELSEWHERE,
  TOKEN_RENEWED_BOUND_ELSEWHERE,
} from '../auth/refusal';
import { readRejection } from '../auth/rejection';
import { readBinding, type TokenBinding } from '../auth/tokenBinding';
import type { TokenRequestAuth } from '../auth/tokenRequest';
import { CertificateMaterialError } from '../errors/CertificateMaterialError';
import { ValidationError } from '../errors/TokenProviderErrors';

/** What every token provider's config may carry beside its own fields. */
export interface TokenProviderHooks {
  /**
   * Called after every NEW token — a login or a refresh, never a cache hit —
   * and awaited before the provider answers. The broker persists through it.
   * Best effort: a failure is logged by class name and does not fail the
   * authentication.
   */
  onTokens?: (result: ITokenResult) => Promise<void>;
}

/**
 * How the client authenticates to the authorization server (spec §3). Taken by
 * every provider that sends a request to one; never beside a `clientSecret` —
 * two ways of authenticating one client is a `ValidationError`.
 */
export interface ClientAuthenticationConfig {
  clientAuthentication?: IClientAuthentication;
}

/** The certificate a provider presents for its lifetime, and its `x5t#S256`. */
export interface PinnedCertificate {
  readonly material: ICertificateMaterial;
  readonly thumbprint: string;
  /** The leaf's `notAfter`, epoch ms: checked before every request that presents it. */
  readonly notAfter: number;
}

/** What the base constructor reads of a provider's configuration. */
type BaseConfig = TokenProviderHooks &
  ClientAuthenticationConfig & { clientSecret?: unknown };

/**
 * The four material fields, copied — each Buffer into a new one: an object or
 * a Buffer the strategy still holds, and changes later, never changes what is
 * pinned.
 */
function copyMaterial(material: ICertificateMaterial): ICertificateMaterial {
  const own = <T>(value: T): T =>
    (Buffer.isBuffer(value) ? Buffer.from(value) : value) as T;
  const cert = own(material.cert);
  const key = own(material.key);
  const pfx = own(material.pfx);
  const { passphrase } = material;
  return {
    ...(cert === undefined ? {} : { cert }),
    ...(key === undefined ? {} : { key }),
    ...(pfx === undefined ? {} : { pfx }),
    ...(passphrase === undefined ? {} : { passphrase }),
  };
}

/**
 * A stored `expiresAt` as an expiry: a finite, non-negative number of epoch
 * milliseconds. Anything else — `Infinity`, `NaN`, a string from an unparsed
 * file — states no expiry, so the stored credential is taken as expired.
 */
export function storedExpiry(expiresAt: unknown): number | undefined {
  return typeof expiresAt === 'number' &&
    Number.isFinite(expiresAt) &&
    expiresAt >= 0
    ? expiresAt
    : undefined;
}

/**
 * Abstract base class for token providers
 *
 * Provides common functionality for token lifecycle management:
 * - Caches tokens internally
 * - Checks expiration before returning tokens
 * - Automatically refreshes expired tokens
 * - Falls back to one login if refresh fails — the base decides it, never
 *   a provider's own performRefresh
 * - Shares one in-flight renewal among concurrent callers
 */
export abstract class BaseTokenProvider
  implements IRefreshableTokenProvider, IAuthProvider
{
  protected authorizationToken?: string;
  protected refreshToken?: string;
  protected expiresAt?: number; // timestamp in milliseconds
  protected tokenType?: 'jwt' | 'saml' | 'opaque';
  protected logger?: ILogger;
  private readonly onTokens?: TokenProviderHooks['onTokens'];
  /** The token last put on a request, so rejected() can tell a renewal from a repeat. */
  private presented?: string;
  /** The renewal in flight; concurrent callers share it (one refresh, at most one login). */
  private renewal?: Promise<ITokenResult>;
  /** How the client authenticates to the authorization server, when configured. */
  protected readonly clientAuthentication?: IClientAuthentication;
  /**
   * The strategy's TLS material and its thumbprint: set on first need, never
   * replaced (spec §4). A certificate that rotates is a new provider.
   */
  protected pinned?: PinnedCertificate;
  /** The pin attempt in flight; concurrent first needs share it. */
  private pinning?: Promise<PinnedCertificate>;
  /**
   * A token a renewal obtained that is still bound elsewhere than the pinned
   * certificate. Held, it is refused, never renewed again on its own —
   * otherwise every request attempt would cost a token request, or a login.
   * Cleared whenever the token changes, and by prepare().
   */
  private renewedElsewhere?: string;

  constructor(config: BaseConfig = {}) {
    this.onTokens = config.onTokens;
    if (config.clientAuthentication && config.clientSecret !== undefined) {
      // Two ways of authenticating one client is a mistake, not a preference.
      throw new ValidationError(
        'clientSecret cannot be given beside clientAuthentication',
        ['clientSecret'],
      );
    }
    this.clientAuthentication = config.clientAuthentication;
  }

  /**
   * The certificate this provider presents, read from the strategy once.
   * Undefined for no strategy, or one that presents none. A failed read pins
   * nothing and throws — the moment that needed it is refused, and the next
   * moment reads again. After a success `tlsMaterial()` is never called again.
   */
  protected async pin(): Promise<PinnedCertificate | undefined> {
    if (this.pinned) return this.pinned;
    const strategy = this.clientAuthentication;
    if (!strategy?.tlsMaterial) return undefined;
    if (!this.pinning) {
      const attempt = (async () => {
        const loaded = await strategy.tlsMaterial?.();
        // Nothing, or not an object: no certificate to present at all.
        if (!loaded || typeof loaded !== 'object') {
          throw new CertificateMaterialError(true);
        }
        const material = copyMaterial(loaded);
        assertCertificateMaterial(material);
        const pinned = {
          material,
          thumbprint: certificateThumbprint(material),
          notAfter: certificateNotAfter(material),
        };
        this.pinned = pinned;
        return pinned;
      })();
      this.pinning = attempt;
      attempt.then(
        () => {
          this.pinning = undefined;
        },
        () => {
          this.pinning = undefined;
        },
      );
    }
    return this.pinning;
  }

  /**
   * The pinned certificate, about to be presented: pinned if it is not yet,
   * and refused — a CertificateMaterialError, "has expired" — once past its
   * `notAfter`. Valid at pin time is not valid for life.
   */
  private async presentable(): Promise<PinnedCertificate | undefined> {
    const pinned = await this.pin();
    if (pinned) assertNotExpired(pinned.notAfter);
    return pinned;
  }

  /**
   * What a token-request site is given for one request: the strategy, the
   * pinned material, and the server's mTLS alias of that request's endpoint.
   * Undefined without a strategy — the site then sends today's request.
   */
  protected async requestAuth(
    mtlsEndpoint?: string,
  ): Promise<TokenRequestAuth | undefined> {
    const strategy = this.clientAuthentication;
    if (!strategy) return undefined;
    const pinned = await this.presentable();
    return {
      strategy,
      ...(pinned ? { material: pinned.material } : {}),
      ...(mtlsEndpoint === undefined ? {} : { mtlsEndpoint }),
    };
  }

  /**
   * True for a held token this provider cannot present: bound — or binding
   * unreadably — to another certificate than the pinned one. It is then
   * renewed like an expired token, through the pinned material. Without a
   * pinned certificate there is nothing to renew it for: false, and the
   * binding check refuses it where it would be presented.
   */
  private async boundToAnother(token: string): Promise<boolean> {
    // A renewal already obtained this one: renewing again would not help.
    if (token === this.renewedElsewhere) return false;
    const binding = readBinding(token);
    if (binding.state !== 'bound') return false;
    const pinned = await this.pin();
    return pinned !== undefined && !this.presents(binding, pinned);
  }

  /** Remembers a renewed token bound elsewhere than the pinned certificate. */
  private markIfElsewhere(token: string): void {
    const binding = readBinding(token);
    if (
      this.pinned !== undefined &&
      binding.state === 'bound' &&
      !this.presents(binding, this.pinned)
    ) {
      this.renewedElsewhere = token;
    }
  }

  /**
   * Format timestamp to readable date/time string
   * @param timestamp Timestamp in milliseconds
   * @returns Formatted date string (e.g., "2025-12-25 19:21:27 UTC")
   */
  protected formatExpirationDate(timestamp: number): string {
    const date = new Date(timestamp);
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    const hours = String(date.getUTCHours()).padStart(2, '0');
    const minutes = String(date.getUTCMinutes()).padStart(2, '0');
    const seconds = String(date.getUTCSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
  }

  /**
   * What a log line may say about a token: that it is there, and its length.
   * Never any of its characters — a UAA refresh token is about 34 characters,
   * so even "the first and last 25" is the whole secret.
   */
  protected formatToken(token?: string): string | undefined {
    if (!token) return undefined;
    return `<redacted, ${token.length} chars>`;
  }

  /**
   * Check if current token is valid (not expired)
   * @returns true if token exists and is not expired, false otherwise
   */
  protected isTokenValid(): boolean {
    if (!this.authorizationToken || !this.expiresAt) {
      this.logger?.debug(
        '[BaseTokenProvider] Token invalid: missing token or expiration',
        {
          hasToken: !!this.authorizationToken,
          hasExpiresAt: !!this.expiresAt,
        },
      );
      return false;
    }
    // Add 60 second buffer to account for clock skew and network latency
    const bufferMs = 60 * 1000;
    const now = Date.now();
    const isValid = now < this.expiresAt - bufferMs;
    this.logger?.debug('[BaseTokenProvider] Token validation check', {
      now: this.formatExpirationDate(now),
      expiresAt: this.formatExpirationDate(this.expiresAt),
      expiresIn: Math.floor((this.expiresAt - now) / 1000),
      isValid,
      bufferMs,
    });
    return isValid;
  }

  /**
   * Abstract method to perform initial login/authorization
   * Must be implemented by concrete providers
   */
  protected abstract performLogin(): Promise<ITokenResult>;

  /**
   * Abstract method to refresh token
   * Must be implemented by concrete providers. It never logs in: a failed
   * refresh throws, and the base runs the single login.
   */
  protected abstract performRefresh(): Promise<ITokenResult>;

  /** False for a grant with no refresh: the base then skips performRefresh and logs in once. */
  protected hasRefreshGrant(): boolean {
    return true;
  }

  /**
   * Abstract method to get authentication type
   * Must be implemented by concrete providers
   */
  protected abstract getAuthType(): OAuth2GrantType;

  /**
   * Main method - handles token lifecycle
   *
   * 1. If token is valid, return cached token
   * 2. If token expired and refresh token available, try refresh
   * 3. If refresh fails or no refresh token, perform login
   *
   * @returns Promise that resolves to token result
   */
  async getTokens(): Promise<ITokenResult> {
    this.logger?.debug('[BaseTokenProvider] getTokens called', {
      hasToken: !!this.authorizationToken,
      hasExpiresAt: !!this.expiresAt,
      hasRefreshToken: !!this.refreshToken,
      currentToken: this.formatToken(this.authorizationToken),
    });
    // A renewal in flight is replacing the cache: wait for it, not the old token
    if (this.renewal) return this.renewal;
    // If token is valid, return cached — unless it is bound to another
    // certificate than the pinned one (a restored token after a rotation):
    // that one is renewed like an expired one.
    const isValid =
      this.isTokenValid() &&
      !(await this.boundToAnother(this.authorizationToken ?? ''));
    if (this.renewal) return this.renewal;
    if (isValid) {
      const authorizationToken = this.authorizationToken;
      if (!authorizationToken) {
        throw new Error('Authorization token is missing.');
      }
      this.logger?.info('[BaseTokenProvider] Returning cached valid token', {
        token: this.formatToken(authorizationToken),
        expiresIn: this.expiresAt
          ? Math.floor((this.expiresAt - Date.now()) / 1000)
          : undefined,
      });
      return {
        authorizationToken,
        refreshToken: this.refreshToken,
        authType: this.getAuthType(),
        tokenType: this.tokenType ?? 'jwt',
        expiresAt: this.expiresAt,
        expiresIn: this.expiresAt
          ? Math.floor((this.expiresAt - Date.now()) / 1000)
          : undefined,
      };
    }

    return this.refreshTokens();
  }

  /**
   * A new token, never the cached one: the refresh token when there is one,
   * the login flow when there is none or the refresh is refused.
   *
   * `getTokens()` answers the cache while the token looks valid, so a caller
   * holding a 401 — the server refused a token the clock still accepts — has
   * no other way to get a different one. What this obtains replaces the cache.
   */
  async refreshTokens(): Promise<ITokenResult> {
    if (!this.renewal) {
      this.renewal = this.renew().finally(() => {
        this.renewal = undefined;
      });
    }
    return this.renewal;
  }

  /** One renewal: one refresh, then — only if it is refused or impossible — one login. */
  private async renew(): Promise<ITokenResult> {
    // Before anything is sent or started: material that cannot be loaded, or
    // has expired, refuses the renewal whole — the refresh token is neither
    // sent nor dropped, and no login begins.
    await this.presentable();
    const spent = this.refreshToken;
    if (spent && this.hasRefreshGrant()) {
      this.logger?.info(
        '[BaseTokenProvider] Obtaining a new token by refresh',
        {
          oldToken: this.formatToken(this.authorizationToken),
          refreshToken: this.formatToken(spent),
        },
      );
      try {
        const result = await this.performRefresh();
        this.updateTokens(result);
        this.markIfElsewhere(result.authorizationToken);
        await this.obtained(result);
        this.logger?.info('[BaseTokenProvider] Token refreshed successfully', {
          newToken: this.formatToken(result.authorizationToken),
          newRefreshToken: this.formatToken(result.refreshToken),
        });
        return result;
      } catch (error) {
        this.logger?.warn('[BaseTokenProvider] Refresh failed', {
          error: error instanceof Error ? error.message : String(error),
        });
        // The refresh token was refused: it is spent, so a login follows.
        // Only that one — never a token something else stored meanwhile.
        if (this.refreshToken === spent) this.refreshToken = undefined;
      }
    }

    this.logger?.info(
      '[BaseTokenProvider] No usable refresh token, performing login',
    );
    const result = await this.performLogin();
    this.updateTokens(result);
    this.markIfElsewhere(result.authorizationToken);
    await this.obtained(result);
    this.logger?.info('[BaseTokenProvider] Login completed', {
      newToken: this.formatToken(result.authorizationToken),
      newRefreshToken: this.formatToken(result.refreshToken),
    });
    return result;
  }

  async validateToken(_token: string, _serviceUrl?: string): Promise<boolean> {
    this.logger?.debug('[BaseTokenProvider] Validating token');
    if (this.tokenType && this.tokenType !== 'jwt') {
      if (!this.expiresAt) {
        this.logger?.warn(
          '[BaseTokenProvider] Token validation failed: missing expiresAt for non-JWT token',
        );
        return false;
      }
      const bufferMs = 60 * 1000;
      const isValid = Date.now() < this.expiresAt - bufferMs;
      this.logger?.info('[BaseTokenProvider] Token validation result', {
        isValid,
        tokenType: this.tokenType,
        expiresAt: this.formatExpirationDate(this.expiresAt),
        expiresIn: Math.floor((this.expiresAt - Date.now()) / 1000),
      });
      return isValid;
    }
    const expiresAt = this.parseExpirationFromJWT(_token);
    if (!expiresAt) {
      this.logger?.warn(
        '[BaseTokenProvider] Token validation failed: cannot parse expiration',
      );
      return false;
    }
    const bufferMs = 60 * 1000;
    const isValid = Date.now() < expiresAt - bufferMs;
    this.logger?.info('[BaseTokenProvider] Token validation result', {
      isValid,
      expiresAt: this.formatExpirationDate(expiresAt),
      expiresIn: Math.floor((expiresAt - Date.now()) / 1000),
    });
    return isValid;
  }

  /**
   * Update internal token cache from result
   * @param result Token result to cache
   */
  protected updateTokens(result: ITokenResult): void {
    this.renewedElsewhere = undefined;
    const oldToken = this.formatToken(this.authorizationToken);
    this.authorizationToken = result.authorizationToken;
    this.refreshToken = result.refreshToken;
    this.tokenType = result.tokenType ?? 'jwt';
    if (result.expiresAt) {
      this.expiresAt = result.expiresAt;
    } else if (result.expiresIn) {
      this.expiresAt = Date.now() + result.expiresIn * 1000;
    } else if (this.tokenType === 'jwt') {
      // Try to parse expiration from JWT if expiresIn not provided
      this.expiresAt = this.parseExpirationFromJWT(result.authorizationToken);
    } else {
      this.expiresAt = undefined;
    }
    this.logger?.info('[BaseTokenProvider] Tokens updated', {
      oldToken,
      newToken: this.formatToken(result.authorizationToken),
      newRefreshToken: this.formatToken(result.refreshToken),
      tokenType: this.tokenType,
      expiresAt: this.expiresAt
        ? this.formatExpirationDate(this.expiresAt)
        : undefined,
    });
  }

  /**
   * Parse expiration time from JWT token
   * @param token JWT token string
   * @returns Expiration timestamp in milliseconds, or undefined if cannot parse
   */
  protected parseExpirationFromJWT(token: string): number | undefined {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return undefined;
      }

      const payload = parts[1];
      // Convert base64url to base64
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      // Add padding if needed
      const padded = base64 + '=='.substring(0, (4 - (base64.length % 4)) % 4);

      const decoded = Buffer.from(padded, 'base64').toString('utf8');
      const claims = JSON.parse(decoded);

      // A numeric exp is the token's own expiry, 0 included; anything else
      // is no expiry stated.
      if (typeof claims.exp === 'number' && Number.isFinite(claims.exp)) {
        return claims.exp * 1000;
      }
    } catch {
      // Failed to parse - return undefined
    }
    return undefined;
  }

  /**
   * When a seeded token expires: the JWT's own `exp` when it carries one —
   * the token's claim wins over anything stated beside it — else the
   * `expiresAt` the consumer stored with it (an opaque token). Neither: the
   * seed is taken as expired, and the first getTokens() renews it.
   */
  protected seededExpiry(
    token: string,
    expiresAt?: number,
  ): number | undefined {
    return this.parseExpirationFromJWT(token) ?? storedExpiry(expiresAt);
  }

  /**
   * Calculate expiresIn from JWT token
   * @param token JWT token string
   * @returns Expiration time in seconds, or undefined if cannot parse
   */
  protected calculateExpiresIn(token: string): number | undefined {
    const expiresAt = this.parseExpirationFromJWT(token);
    if (!expiresAt) {
      return undefined;
    }
    const now = Date.now();
    const expiresIn = Math.floor((expiresAt - now) / 1000);
    return expiresIn > 0 ? expiresIn : undefined;
  }

  private async obtained(result: ITokenResult): Promise<void> {
    if (!this.onTokens) return;
    try {
      await this.onTokens(result);
    } catch (error) {
      // Class name only: the hook holds the tokens, its message is foreign text.
      this.logger?.warn(
        '[BaseTokenProvider] onTokens failed; the token stands',
        {
          error: ownLabel(error),
        },
      );
    }
  }

  // ---- IAuthProvider: the process calls these, the same for every provider.

  /** The grant type, so a log line says which way in ran. */
  get kind(): string {
    return this.getAuthType();
  }

  /** The subject of a fixed refusal: "<grant type> token request failed". */
  private get obtaining(): string {
    return `${this.kind} token request`;
  }

  async prepare(): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      // Once per connect, a token renewed bound elsewhere gets one more try.
      this.renewedElsewhere = undefined;
      await this.getTokens();
      return OK;
    });
  }

  /**
   * The token is presented per request; the logon carries the pinned
   * certificate when the token may need it (spec §4's table). Decided on the
   * token this provider HOLDS — a logon never obtains, refreshes or logs in.
   * No token, an expired one, or one being renewed reads as unknown: the
   * token presented will be the one authorize() obtains through the same
   * strategy and pinned material, and authorize() checks that one.
   */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      const pinned = await this.presentable();
      const held =
        !this.renewal && this.isTokenValid()
          ? this.authorizationToken
          : undefined;
      let binding: TokenBinding =
        held === undefined ? { state: 'unknown' } : readBinding(held);
      // Bound to another certificate than the pinned one: authorize() renews
      // it through the pinned material, as it would an expired one — so it
      // reads as unknown here, like an expired token.
      if (pinned && !this.presents(binding, pinned)) {
        binding = { state: 'unknown' };
      }
      if (!this.presents(binding, pinned)) return boundElsewhere();
      if (!pinned) return OK;
      // A copy: a target that changes what it is given never changes what
      // later requests present.
      const presented = atTarget('presenting the certificate', () =>
        logon.tlsMaterial(copyMaterial(pinned.material)),
      );
      // Unbound: the Bearer carries the token, the certificate is a courtesy
      // — but a target that throws is broken (rule 1), and that is an Oops.
      // Bound or unknown: the token is not sent on a connection without it.
      return binding.state === 'unbound' && !presented.thrown
        ? OK
        : presented.outcome;
    });
  }

  /**
   * Per attempt: getTokens() renews an expired token here — and one bound to
   * another certificate than the pinned one — and the token actually sent is
   * the one checked.
   */
  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      // Pinned here too, so a token served from cache (seeded, restored) is
      // checked against the certificate like an obtained one.
      const pinned = await this.pin();
      const result = await this.getTokens();
      if (!this.presents(readBinding(result.authorizationToken), pinned)) {
        // Pinned: getTokens() already renewed a token bound elsewhere, so
        // this one is the renewal's.
        return pinned ? renewedBoundElsewhere() : boundElsewhere();
      }
      const written = atTarget('presenting the token', () => {
        this.applyToken(request, result);
        return OK;
      });
      if (written.thrown) return written.outcome;
      this.presented = result.authorizationToken;
      return OK;
    });
  }

  /**
   * False only for a bound token whose thumbprint is not the pinned one —
   * none pinned, another one, or a binding the token states unreadably.
   * Unbound and unknown tokens may be presented (spec §4).
   */
  private presents(
    binding: TokenBinding,
    pinned: PinnedCertificate | undefined,
  ): boolean {
    if (binding.state !== 'bound') return true;
    return (
      pinned !== undefined &&
      binding.thumbprint !== undefined &&
      binding.thumbprint === pinned.thumbprint
    );
  }

  /**
   * A new token — refresh, else login. Ok only if it differs; retrying is the
   * caller's. A renewal in flight is joined; a presented token already
   * superseded by a renewal answers Ok without renewing again.
   */
  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      // A 403, a redirect, a 5xx: a new token would be refused the same way.
      const read = readRejection(rejection);
      if (read.verdict === 'not-credential') {
        return { ok: false, refusal: read.refusal };
      }
      // Nothing presented yet (a rejection before any authorize): the token
      // held — from a login or from config — is the one taken as refused.
      const refused = this.presented ?? this.authorizationToken;
      if (
        !this.renewal &&
        refused !== undefined &&
        this.authorizationToken !== undefined &&
        this.authorizationToken !== refused
      ) {
        return OK;
      }
      const result = await this.refreshTokens();
      if (refused !== undefined && result.authorizationToken === refused) {
        return oops(
          'the renewal returned the credential that was refused',
          'the token source must issue a new token; log in again',
        );
      }
      return OK;
    });
  }

  /** How this provider's token rides on a request. Bearer by default. */
  protected applyToken(request: IRequestTarget, result: ITokenResult): void {
    request.header('Authorization', `Bearer ${result.authorizationToken}`);
  }
}

/** The refusal for a held token bound to a certificate while none is pinned. */
function boundElsewhere(): AuthOutcome {
  return oops(TOKEN_BOUND_ELSEWHERE.reason, TOKEN_BOUND_ELSEWHERE.hint);
}

/** The refusal for a renewed token still bound to another certificate. */
function renewedBoundElsewhere(): AuthOutcome {
  return oops(
    TOKEN_RENEWED_BOUND_ELSEWHERE.reason,
    TOKEN_RENEWED_BOUND_ELSEWHERE.hint,
  );
}

/**
 * One write to a consumer's target. A target that throws is the target's
 * failure, not the token request's: it is refused under `what`, through the
 * same refusalFrom as every other thrown value (rule 2).
 */
function atTarget(
  what: string,
  write: () => AuthOutcome,
): { outcome: AuthOutcome; thrown: boolean } {
  try {
    return { outcome: write(), thrown: false };
  } catch (error) {
    return { outcome: refusalFrom(error, what), thrown: true };
  }
}
