/**
 * Base Token Provider
 *
 * Abstract base class for all token providers.
 * Implements common token lifecycle management:
 * - Token caching
 * - Expiration checking
 * - Automatic refresh/relogin
 */

import {
  type AttemptContext,
  AuthProviderFailure,
  authError,
  classify,
  createParties,
  logFields,
  OK,
  relayOutcome,
  sharedAttempt,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProviderError,
  IAuthRejection,
  ICertificateMaterial,
  IClientAuthentication,
  ILogonTarget,
  IRefreshableTokenProvider,
  IRenewalStrategy,
  IRequestTarget,
  ITokenPersistence,
  ITokenRequestOptions,
  ITokenResult,
  OAuth2GrantType,
  Operation,
  PersistenceReport,
  RenewalAbortObservation,
  RenewalCause,
  RenewalDecision,
  RenewalMoment,
  RenewalSituation,
  RenewalStep,
  RenewalStepOutcome,
  ReportedCredential,
  SentRefreshToken,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import { abortedFailure, throwIfAborted, untilAborted } from '../auth/attempt';
import {
  assertCertificateMaterial,
  assertNotExpired,
  certificateFailure,
  certificateNotAfter,
  certificateThumbprint,
} from '../auth/certificateMaterial';
import {
  misconfigured,
  ownOptions,
  requiredFieldsMissing,
} from '../auth/configuration';
import { isGrant } from '../auth/grants';
import {
  isPlainPromise,
  markHandled,
  onAnswerRejection,
} from '../auth/handled';
import { readSafely } from '../auth/knownCodes';
import { rejectionCause } from '../auth/rejection';
import { readBinding, type TokenBinding } from '../auth/tokenBinding';
import {
  logQuietly,
  type TokenRequestAuth,
  type TokenSiteOptions,
} from '../auth/tokenRequest';
import { needsSentDecision, readDecision } from '../renewal/decision';

/**
 * The consumer's opt-in to naming the request's secrets in its debug line
 * (spec §6): with `authDebug: true` — `true` itself, nothing else — a failed
 * token request, or an answer without a token, writes its one line with the
 * safe facts plus `sent`, each secret the request carried by name, at most
 * its first and last 4 characters (`abcd…wxyz <redacted, N chars>`; under 16
 * characters its length only). Without it the line carries the safe facts
 * only. The server's own text (`error_description`, `error_uri`) is never
 * read, logged or kept, either way. Never read from the environment, never
 * defaulted on.
 */
export interface TokenProviderDebug {
  readonly authDebug?: boolean | undefined;
}

/**
 * The operation a failure names, with this provider's grant when it has one
 * (`classify`'s second and third arguments).
 */
interface OperationOf {
  readonly operation: Operation;
  readonly grant?: OAuth2GrantType;
}

/** What every token provider's config may carry beside its own fields. */
export interface TokenProviderHooks extends TokenProviderDebug {
  /**
   * What this provider tells persistence (spec §6c.3, §6c.6): one report per
   * change of its credentials, made from inside the commit queue in commit
   * order — `credential` for every new token a refresh or a login committed
   * (never a cache hit), `refresh-token-discarded` when the renewal
   * strategy's decision discarded the refresh token held. A report is
   * `awaited` while the attempt that made the commit still has a live
   * waiter: the commit awaits it, and its failure is the renewal's
   * (`unknown`, `persisting-tokens`), the credentials staying committed. A
   * detached report is called and not awaited; its failure is logged in
   * fixed words and attributed to nothing. Nothing is reported twice.
   * Absent: nothing is persisted — a choice, not a default; the provider
   * builds none (rule 7). Given, it must be an object whose `report` is a
   * function, else it is refused at construction (`configuration`
   * `invalid-value`, `persistence`). `refreshStatePersistence(write,
   * options)` is the behaviour of `onTokens` before 6.0.0.
   */
  persistence?: ITokenPersistence | undefined;
  /**
   * The first attached party (spec §6b), attached at construction — the same
   * as `attach(signal)` right after it. A login a moment starts (`prepare`,
   * `authorize`, `rejected`, …) is aborted when every attached party has
   * aborted; with none live it runs unbounded, as an unsignalled consumer
   * chose.
   */
  signal?: AbortSignal | undefined;
  /**
   * How every renewal of this provider proceeds — whether to refresh,
   * whether to log in, when to stop, what becomes of a refresh token that
   * was sent (spec §6c). Required, no default (rule 7): `refreshThenLogin()`
   * is the behaviour before 6.0.0, `refreshOnly()` never logs in. A missing
   * one, or one whose `next` is not a function, is refused at construction
   * (`configuration` `required-fields-missing`, `renewal`) — the provider
   * builds none of its own.
   */
  renewal: IRenewalStrategy;
}

/** Why a renewal started, and where — fixed for the whole renewal. */
interface RenewalStart {
  readonly cause: RenewalCause;
  readonly moment: RenewalMoment;
  /** For a rejection: the token taken as refused (`unchanged`). */
  readonly refused?: string | undefined;
}

/**
 * How one step ended: a usable credential, which ends the renewal; or an
 * outcome the strategy is told, with what a `stop` would answer for it and
 * the refresh token it sent when it failed after sending.
 */
type StepEnd =
  | { readonly usable: ITokenResult }
  | {
      readonly outcome: RenewalStepOutcome;
      readonly refusal: IAuthProviderError;
      readonly sentToken?: string | undefined;
    };

/**
 * A step's result could not be installed (a subclass's `updateTokens`
 * threw): carried out of the commit so that a refresh step can tell it from
 * a failure after the install — the awaited persistence report (spec
 * §6c.6), which ends the renewal instead. Never thrown out of the provider: the step
 * unwraps `thrown`.
 */
class InstallFailed {
  constructor(readonly thrown: unknown) {}
}

/**
 * What a shared attempt answers its waiters: its value, or what it threw —
 * handed on as it is, so a failure the renewal built is the one thrown. A
 * plain object, never thenable (sharedAttempt's rule).
 */
type Settled<T> = { readonly value: T } | { readonly thrown: unknown };

/** How a credential commit's result was obtained. */
type Obtained = 'refresh' | 'login';

/**
 * D8 / A10: a provider with no refresh grant, or no refresh token to send —
 * the refresh token is the credential refused (`credential-refused`
 * `refresh-token`). The base never reaches it for a grant without refresh;
 * thrown before anything is sent, it is a refresh that failed unsent, and
 * the renewal strategy decides what follows.
 */
export function refreshTokenRefused(): AuthProviderFailure {
  return new AuthProviderFailure(
    authError['credential-refused']({ credential: 'refresh-token' }),
  );
}

/**
 * How the client authenticates to the authorization server (spec §3). Taken by
 * every provider that sends a request to one; never beside a `clientSecret` —
 * two ways of authenticating one client is a configuration error (E2).
 */
export interface ClientAuthenticationConfig {
  clientAuthentication?: IClientAuthentication | undefined;
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
  TokenProviderDebug &
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
  extends AuthProviderBase
  implements IRefreshableTokenProvider
{
  protected authorizationToken?: string | undefined;
  protected refreshToken?: string | undefined;
  protected expiresAt?: number | undefined; // timestamp in milliseconds
  protected tokenType?: 'jwt' | 'saml' | 'opaque';
  protected logger?: ILogger | undefined;
  /** The consumer's persistence strategy; absent, nothing is persisted. */
  private readonly persistence?: ITokenPersistence | undefined;
  /** The token last put on a request, so rejected() can tell a renewal from a repeat. */
  private presented?: string | undefined;
  /**
   * The renewal slot (spec §6b): concurrent callers are waiters of one
   * attempt — one refresh, at most one login; one waiter's abort releases
   * only that waiter, and every waiter's abort aborts the attempt.
   */
  private readonly renewals =
    sharedAttempt<Settled<ITokenResult>>('token-request');
  /**
   * The renewal attempt in the slot, while it is there: set when it starts,
   * cleared when it settles or is aborted (it leaves the slot at once).
   */
  private renewing?: AttemptContext | undefined;
  /** The parties attached to this provider: a moment's login waits on them. */
  private readonly parties = createParties();
  /** How the client authenticates to the authorization server, when configured. */
  protected readonly clientAuthentication?: IClientAuthentication | undefined;
  /**
   * `config.authDebug === true`, read once: what every token site of this
   * provider is told (`TokenRequestSite.authDebug`, through `siteOptions()`).
   */
  protected readonly authDebug: boolean;
  /**
   * The strategy's TLS material and its thumbprint: set on first need, never
   * replaced (spec §4). A certificate that rotates is a new provider.
   */
  protected pinned?: PinnedCertificate;
  /** The pin slot; concurrent first needs are waiters of one attempt. */
  private readonly pins =
    sharedAttempt<Settled<PinnedCertificate>>('token-request');
  /**
   * The commit queue (spec §6b): every effect of an attempt — the pinned
   * material, the tokens, `remembered`, the persistence reports — runs here,
   * one commit after another, never two at once, in arrival order.
   */
  private commits: Promise<void> = Promise.resolve();
  /**
   * Two kinds of commit, two watermarks: a pin commit carries a pin
   * generation and is checked against the pin watermark only; a credential
   * commit carries a credential generation and is checked against the
   * credential watermark only. Neither advances the other's. A generation is
   * taken when its attempt begins; a commit applies only if it is newer than
   * its kind's watermark, else it is discarded whole.
   */
  private pinGeneration = 0;
  private pinWatermark = 0;
  private credentialGeneration = 0;
  private credentialWatermark = 0;
  /**
   * Every refresh token discarded by the renewal strategy — its
   * `sentRefreshToken: 'discard'`, or `ifCut: 'discard'` applied at the
   * abort of a dispatched refresh (spec §6c.5): a tombstone for the
   * provider's lifetime — no entry ever leaves, never persisted. A dispatch
   * never sends one (`canRefresh` is false while the held one is here), and
   * a commit never installs one.
   */
  private readonly discarded = new Set<string>();
  /** How every renewal proceeds: the consumer's strategy, never one of ours. */
  private readonly renewal: IRenewalStrategy;
  /** Steps ended by an abort, not yet handed to the strategy's `aborted`. */
  private readonly observations: RenewalAbortObservation[] = [];
  /**
   * The login step running under each attempt's signal, told by every site
   * that login sends through (`siteOptions(signal)`) right before a request
   * leaves — the step's `sent`.
   */
  private readonly loginDispatch = new WeakMap<AbortSignal, () => void>();
  /**
   * A held token bound elsewhere than the pinned certificate that a renewal
   * did not make usable, with the refusal that renewal produced: a renewal
   * that obtained it still bound elsewhere ("the new token is bound to …"),
   * or a renewal that threw while it was held (its own refusal — an expired
   * client certificate, a refused login). It is not renewed again on its own
   * — otherwise every request attempt would cost a token request, or a login,
   * interactive for a browser or device strategy — and `authorize()` answers
   * that same refusal, so the cause stays visible. Cleared whenever the token
   * changes. It reaches the renewal strategy as `lastRenewal` (spec §6c.4):
   * `refreshThenLogin()` renews it again only at `prepare` and on a
   * rejection, and the latest renewal's refusal is the one kept.
   */
  private remembered?:
    | { readonly token: string; readonly error: IAuthProviderError }
    | undefined;
  /** `getAuthType()`, read once (`readGrant`). */
  private grantRead?: { readonly grant: OAuth2GrantType | undefined };

  constructor(options: BaseConfig) {
    // Read once as own data: a hostile object throws nothing of its own.
    const config = ownOptions<BaseConfig>(options);
    // Every moment of a token provider is its token request (spec A.8).
    super({
      prepare: 'token-request',
      establish: 'token-request',
      authorize: 'token-request',
      rejected: 'token-request',
    });
    // Absent is a choice: nothing is persisted (spec §6c.3). Given, it must
    // be an object whose `report` is a function, read without running a
    // getter; anything else — `null` included — is refused here.
    const persistence: unknown = config.persistence;
    if (
      persistence !== undefined &&
      (persistence === null ||
        typeof persistence !== 'object' ||
        typeof readSafely(persistence, 'report') !== 'function')
    ) {
      throw misconfigured(
        authError.configuration({
          case: 'invalid-value',
          fields: ['persistence'],
        }),
      );
    }
    this.persistence = persistence as ITokenPersistence | undefined;
    // Required, no default (rule 7, spec §6c.3): an object whose `next` is a
    // function, read without running a getter; anything else is refused here.
    const renewal: unknown = config.renewal;
    if (
      renewal === null ||
      typeof renewal !== 'object' ||
      typeof readSafely(renewal, 'next') !== 'function'
    ) {
      throw requiredFieldsMissing(['renewal']);
    }
    this.renewal = renewal as IRenewalStrategy;
    // `true` itself: `'true'`, `1` or an environment variable never opt in.
    this.authDebug = config.authDebug === true;
    if (config.clientAuthentication && config.clientSecret !== undefined) {
      // Two ways of authenticating one client is a mistake, not a preference
      // (E2).
      throw misconfigured(
        authError.configuration({
          case: 'client-secret-beside-client-authentication',
          fields: ['clientSecret'],
        }),
      );
    }
    this.clientAuthentication = config.clientAuthentication;
    // The config's signal is the first party; an aborted one adds nothing.
    if (config.signal !== undefined) this.parties.attach(config.signal);
  }

  /**
   * Attaches a party sharing this provider (spec §6b): a login a moment
   * starts waits on the parties live at its start and any attached while it
   * runs, and is aborted when all of them have aborted. The same signal
   * twice is one party; an aborted one is not added. A party is released
   * when its signal aborts or by the returned `detach()`. With no live party
   * a moment's login runs unbounded.
   */
  attach(signal: AbortSignal): () => void {
    return this.parties.attach(signal);
  }

  /**
   * Runs one moment's work with the attached parties as its waiter: their
   * signal, or none when no party is live. Released when the work settles.
   */
  private async asMoment<T>(
    work: (signal: AbortSignal | undefined) => Promise<T>,
  ): Promise<T> {
    const waiter = this.parties.waiterSignal();
    try {
      return await work(waiter?.signal);
    } finally {
      waiter?.release();
    }
  }

  /**
   * Queues one commit step: it starts once every earlier step — its
   * awaited persistence report included — has settled.
   */
  private commit<T>(step: () => T | Promise<T>): Promise<T> {
    const run = this.commits.then(step);
    this.commits = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * The certificate this provider presents, read from the strategy once.
   * Undefined for no strategy, or one that presents none. A failed read pins
   * nothing and throws — the moment that needed it is refused, and the next
   * moment reads again. After a success `tlsMaterial()` is never called again.
   */
  protected async pin(
    signal?: AbortSignal,
  ): Promise<PinnedCertificate | undefined> {
    if (this.pinned) return this.pinned;
    const strategy = this.clientAuthentication;
    if (!strategy?.tlsMaterial) return undefined;
    const settled = await this.pins.join(
      (attempt) => this.pinAttempt(strategy, attempt),
      signal,
    );
    if ('thrown' in settled) throw settled.thrown;
    return settled.value;
  }

  /**
   * One pin attempt: the loader read, the checks, then the pin commit — the
   * material set only if the attempt was not aborted and nothing newer was
   * pinned. A loader read that completes after the abort changes nothing.
   */
  private async pinAttempt(
    strategy: IClientAuthentication,
    attempt: AttemptContext,
  ): Promise<Settled<PinnedCertificate>> {
    const generation = ++this.pinGeneration;
    try {
      const loaded = await strategy.tlsMaterial?.();
      // Nothing, or not an object: no certificate to present at all.
      if (!loaded || typeof loaded !== 'object') {
        throw certificateFailure('incomplete');
      }
      const material = copyMaterial(loaded);
      assertCertificateMaterial(material);
      const pinned: PinnedCertificate = {
        material,
        thumbprint: certificateThumbprint(material),
        notAfter: certificateNotAfter(material),
      };
      const applied = await this.commit(() => {
        if (attempt.signal.aborted || generation <= this.pinWatermark) {
          return undefined;
        }
        this.pinWatermark = generation;
        this.pinned = pinned;
        return pinned;
      });
      // Discarded: aborted (nobody waits), or a newer pin is in place.
      return { value: applied ?? this.pinned ?? pinned };
    } catch (thrown) {
      return { thrown };
    }
  }

  /**
   * The pinned certificate, about to be presented: pinned if it is not yet,
   * and refused — `client-certificate` `expired` — once past its
   * `notAfter`. Valid at pin time is not valid for life.
   */
  private async presentable(
    signal?: AbortSignal,
  ): Promise<PinnedCertificate | undefined> {
    const pinned = await this.pin(signal);
    if (pinned) assertNotExpired(pinned.notAfter);
    return pinned;
  }

  /**
   * What a token-request site is given for one request: the strategy, the
   * pinned material, the server's mTLS alias of that request's endpoint, and
   * — for a request that goes elsewhere than the token endpoint (the device
   * initiation) — the plain token endpoint. Undefined without a strategy —
   * the site then sends today's request.
   */
  protected async requestAuth(
    mtlsEndpoint?: string,
    tokenEndpoint?: string,
  ): Promise<TokenRequestAuth | undefined> {
    const strategy = this.clientAuthentication;
    if (!strategy) return undefined;
    const pinned = await this.presentable();
    return {
      strategy,
      ...(pinned
        ? { material: pinned.material, notAfter: pinned.notAfter }
        : {}),
      ...(mtlsEndpoint === undefined ? {} : { mtlsEndpoint }),
      ...(tokenEndpoint === undefined ? {} : { tokenEndpoint }),
    };
  }

  /**
   * What every token site this provider calls is told (spec §6): the
   * consumer's `authDebug`, read once at construction, and the grant its
   * failures name (`getAuthType()`).
   */
  protected siteOptions(signal?: AbortSignal): TokenSiteOptions {
    // A login step running under this signal is told of each dispatch.
    const dispatched =
      signal === undefined ? undefined : this.loginDispatch.get(signal);
    return {
      authDebug: this.authDebug,
      grant: this.getAuthType(),
      // The attempt's signal, read only by an attempt's own sites — a
      // refresh site never reads it (spec §6b).
      ...(signal === undefined ? {} : { signal }),
      ...(dispatched === undefined ? {} : { dispatched }),
    };
  }

  /**
   * What a refresh site is told: `siteOptions()` without the attempt's
   * signal (a dispatched refresh runs on), with the step's `dispatched`,
   * which the site calls synchronously right before the request leaves.
   */
  protected refreshSiteOptions(dispatched: () => void): TokenSiteOptions {
    return { ...this.siteOptions(), dispatched };
  }

  /**
   * True for a held token this provider cannot present: bound — or binding
   * unreadably — to another certificate than the pinned one. It is then
   * renewed like an expired token, through the pinned material — its cause
   * `bound-elsewhere`, with the `lastRenewal` remembered for it. Without a
   * pinned certificate there is nothing to renew it for: false, and the
   * binding check refuses it where it would be presented.
   */
  private async boundToAnother(
    token: string,
    signal: AbortSignal | undefined,
  ): Promise<boolean> {
    const binding = readBinding(token);
    if (binding.state !== 'bound') return false;
    const pinned = await this.pin(signal);
    return pinned !== undefined && !this.presents(binding, pinned);
  }

  /** True for a token bound — or binding unreadably — elsewhere than the pinned certificate. */
  private elsewhereThanPinned(token: string): boolean {
    const binding = readBinding(token);
    return (
      this.pinned !== undefined &&
      binding.state === 'bound' &&
      !this.presents(binding, this.pinned)
    );
  }

  /** Remembers a renewed token bound elsewhere than the pinned certificate. */
  private markIfElsewhere(token: string): void {
    if (this.elsewhereThanPinned(token)) {
      this.remembered = { token, error: renewedBoundElsewhere() };
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
      logQuietly(() =>
        this.logger?.debug(
          '[BaseTokenProvider] Token invalid: missing token or expiration',
          {
            hasToken: !!this.authorizationToken,
            hasExpiresAt: !!this.expiresAt,
          },
        ),
      );
      return false;
    }
    // Add 60 second buffer to account for clock skew and network latency
    const bufferMs = 60 * 1000;
    const now = Date.now();
    const expiresAt = this.expiresAt;
    const isValid = now < expiresAt - bufferMs;
    logQuietly(() =>
      this.logger?.debug('[BaseTokenProvider] Token validation check', {
        now: this.formatExpirationDate(now),
        expiresAt: this.formatExpirationDate(expiresAt),
        expiresIn: Math.floor((expiresAt - now) / 1000),
        isValid,
        bufferMs,
      }),
    );
    return isValid;
  }

  /**
   * One login of a renewal, when the renewal strategy asks for it. `attempt`
   * is the renewal's: its `signal` aborts when every waiter has gone — hand
   * it on to the strategy (`AuthorizationRequest.signal`) and to every
   * request the login sends (`siteOptions(attempt.signal)`) — and
   * `exclusive(work)` runs work holding an exclusive local resource (the
   * strategy's `authorize`, a device-code flow) once the previous attempt
   * has released its own (the drain, spec §6b). It returns the result; the
   * base commits it.
   */
  protected abstract performLogin(
    attempt: AttemptContext,
  ): Promise<ITokenResult>;

  /**
   * Spends `refreshToken` — the one the base read and checked, never
   * re-read from the provider. It never logs in: a failed refresh throws,
   * and the renewal strategy decides what follows. `signal` is the
   * attempt's: what the refresh does before it sends (OIDC discovery)
   * carries it, and nothing is sent once it has aborted — but the refresh
   * request itself never carries it: once sent it runs on, and its answer
   * is offered to the commit queue (spec §6b). `dispatched` goes to the
   * refresh site (`refreshSiteOptions(dispatched)`), which calls it
   * synchronously right before the request leaves (spec §6c.5): it throws
   * `aborted` instead when the attempt has aborted, so nothing is sent.
   */
  protected abstract performRefresh(
    refreshToken: string,
    signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult>;

  /** False for a grant with no refresh: `canRefresh` is then always false. */
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
   * The cached token while it is valid; otherwise a renewal, whose steps
   * the renewal strategy decides (spec §6c.4).
   *
   * @returns Promise that resolves to token result
   * @throws AuthProviderFailure — and nothing else: whatever the renewal, a
   *   strategy, a loader or a presenter threw, classified (spec §6, L3)
   */
  async getTokens(options?: ITokenRequestOptions): Promise<ITokenResult> {
    return this.tokensFor(options?.signal, 'get-tokens');
  }

  /** getTokens() for a moment: the same, naming the moment it runs in. */
  private async tokensFor(
    signal: AbortSignal | undefined,
    moment: RenewalMoment,
  ): Promise<ITokenResult> {
    try {
      return await this.cachedOrRenewed(signal, moment);
    } catch (error) {
      throw this.thrownFor(error);
    }
  }

  /** getTokens()'s body: the cache, else the renewal, joined with `signal`. */
  private async cachedOrRenewed(
    signal: AbortSignal | undefined,
    moment: RenewalMoment,
  ): Promise<ITokenResult> {
    logQuietly(() =>
      this.logger?.debug('[BaseTokenProvider] getTokens called', {
        hasToken: !!this.authorizationToken,
        hasExpiresAt: !!this.expiresAt,
        hasRefreshToken: !!this.refreshToken,
        currentToken: this.formatToken(this.authorizationToken),
      }),
    );
    // A renewal in flight is replacing the cache: wait for it, not the old
    // token. Joining starts nothing, so the cause is read only if the slot
    // emptied meanwhile.
    const now = () => ({ cause: this.causeNow(), moment });
    if (this.renewing) return this.renewed(signal, now);
    // If token is valid, return cached — unless it is bound to another
    // certificate than the pinned one (a restored token after a rotation):
    // that one is renewed like an expired one.
    const held = this.authorizationToken;
    const valid = this.isTokenValid();
    const elsewhere = valid && (await this.boundToAnother(held ?? '', signal));
    if (this.renewing) return this.renewed(signal, now);
    if (elsewhere) {
      const remembered = this.remembered;
      const lastRenewal =
        remembered !== undefined && remembered.token === held
          ? remembered.error
          : undefined;
      return this.renewed(signal, () => ({
        cause: { trigger: 'bound-elsewhere', lastRenewal },
        moment,
      }));
    }
    if (valid) {
      const authorizationToken = this.authorizationToken;
      if (!authorizationToken) {
        // D7: unreachable — isTokenValid() checked the token.
        throw new AuthProviderFailure(
          authError.unknown(this.operationOf('token-request')),
        );
      }
      logQuietly(() =>
        this.logger?.info('[BaseTokenProvider] Returning cached valid token', {
          token: this.formatToken(authorizationToken),
          expiresIn: this.expiresAt
            ? Math.floor((this.expiresAt - Date.now()) / 1000)
            : undefined,
        }),
      );
      return {
        authorizationToken,
        refreshToken: this.heldRefresh(),
        authType: this.heldGrant(),
        tokenType: this.tokenType ?? 'jwt',
        expiresAt: this.expiresAt,
        expiresIn: this.expiresAt
          ? Math.floor((this.expiresAt - Date.now()) / 1000)
          : undefined,
      };
    }
    return this.renewed(signal, () => ({
      cause: { trigger: held ? 'expired' : 'no-token' },
      moment,
    }));
  }

  /**
   * Why a renewal starts when nothing more is known (a slot that emptied
   * between the check and the join): no token, a token bound elsewhere than
   * the pinned certificate, else an expired one.
   */
  private causeNow(): RenewalCause {
    const held = this.authorizationToken;
    if (!held) return { trigger: 'no-token' };
    if (this.elsewhereThanPinned(held)) {
      const remembered = this.remembered;
      return {
        trigger: 'bound-elsewhere',
        lastRenewal:
          remembered !== undefined && remembered.token === held
            ? remembered.error
            : undefined,
      };
    }
    return { trigger: 'expired' };
  }

  /**
   * A new token, never the cached one: a renewal whose steps the renewal
   * strategy decides, its cause `explicit` (spec §6c.4).
   *
   * `getTokens()` answers the cache while the token looks valid, so a caller
   * holding a 401 — the server refused a token the clock still accepts — has
   * no other way to get a different one. What this obtains replaces the cache.
   *
   * With `options.signal`, this call is one waiter of the shared renewal
   * (spec §6b): its abort rejects this call only, `interactive-login`
   * `aborted`.
   *
   * @throws AuthProviderFailure — and nothing else (spec §6, L3)
   */
  async refreshTokens(options?: ITokenRequestOptions): Promise<ITokenResult> {
    try {
      return await this.renewed(options?.signal, () => ({
        cause: { trigger: 'explicit' },
        moment: 'refresh-tokens',
      }));
    } catch (error) {
      throw this.thrownFor(error);
    }
  }

  /**
   * Joins the renewal slot with `signal` — the active renewal, or a new one
   * started for `start()`'s cause and moment. The attempt is where a
   * renewal's failure is built: the one remembered and the one thrown hold
   * the same error (C15).
   */
  private async renewed(
    signal: AbortSignal | undefined,
    start: () => RenewalStart,
  ): Promise<ITokenResult> {
    const settled = await this.renewals.join(
      (attempt) => this.renewAttempt(attempt, start()),
      signal,
    );
    if ('thrown' in settled) throw settled.thrown;
    return settled.value;
  }

  /**
   * This provider's grant, read once for its lifetime: `getAuthType()` is a
   * subclass's and may throw, or answer anything — a rejecting native
   * promise included, whose rejection is marked handled here, once; any
   * other thenable is never called (fail closed). Only a grant on the list
   * is kept.
   */
  private readGrant(): OAuth2GrantType | undefined {
    if (!this.grantRead) {
      let grant: OAuth2GrantType | undefined;
      try {
        const value: unknown = this.getAuthType();
        if (isGrant(value)) grant = value;
        // A plain native promise is marked handled; any other thenable is an
        // unusable grant whose `then` is never called (fail closed).
        else markHandled(value);
      } catch {
        // No grant: the failure names the operation alone.
      }
      this.grantRead = { grant };
    }
    return this.grantRead.grant;
  }

  /** The operation a failure names, with this provider's grant when it has one. */
  private operationOf(operation: Operation): OperationOf {
    const grant = this.readGrant();
    return grant === undefined ? { operation } : { operation, grant };
  }

  /**
   * What getTokens() / refreshTokens() throw for anything caught (spec §6):
   * an AuthProviderFailure holding the classified error — the error a site
   * or a renewal already minted, as it is; never the value caught, nor its
   * message (L3). Every throw is one: nothing passes as it is.
   */
  private thrownFor(error: unknown): AuthProviderFailure {
    return new AuthProviderFailure(
      this.classified(error, this.operationOf('token-request')),
    );
  }

  /** `classify` with an operation and its grant. Total. */
  private classified(error: unknown, of: OperationOf): IAuthProviderError {
    return classify(error, of.operation, of.grant);
  }

  /**
   * One renewal attempt; when it fails while a token bound elsewhere than
   * the pinned certificate is held — the one it started with, or one a step
   * committed — that token is remembered with the renewal's error, the
   * words the attempt that ran it got, through the commit queue; never for
   * an aborted renewal (rule 8: an abort is the consumer's decision, not
   * the token's). An expired token bound to the pinned one (or unbound) is
   * not remembered.
   */
  private async renewAttempt(
    attempt: AttemptContext,
    start: RenewalStart,
  ): Promise<Settled<ITokenResult>> {
    this.renewing = attempt;
    // Aborted, the attempt has left its slot: no longer the one in flight.
    const left = () => {
      if (this.renewing === attempt) this.renewing = undefined;
    };
    attempt.signal.addEventListener('abort', left, { once: true });
    try {
      return { value: await this.renewOnce(attempt, start) };
    } catch (thrown) {
      // The error the renewal produced, minted once: the one thrown and the
      // one remembered are the same object (C15).
      const error = this.classified(thrown, this.operationOf('token-request'));
      await this.commit(() => {
        const held = this.authorizationToken;
        if (
          !attempt.signal.aborted &&
          held !== undefined &&
          this.elsewhereThanPinned(held)
        ) {
          this.remembered = { token: held, error };
        }
      });
      return {
        thrown: new AuthProviderFailure(error),
      };
    } finally {
      attempt.signal.removeEventListener('abort', left);
      left();
    }
  }

  /** A refresh is possible now: a refresh grant, and a usable refresh token held. */
  private canRefresh(): boolean {
    const held = this.refreshToken;
    return (
      this.hasRefreshGrant() &&
      typeof held === 'string' &&
      held !== '' &&
      !this.discarded.has(held)
    );
  }

  /**
   * The renewal (spec §6c.5): pin, then — step by step — deliver the
   * pending abort observations, ask the renewal strategy, read its answer,
   * apply its `sentRefreshToken`, take the step's credential generation,
   * run the step, record how it ended, and ask again. It ends with a usable
   * credential, a `stop`, an invalid answer, or the abort. No step runs that
   * the strategy did not ask for (G3).
   */
  private async renewOnce(
    attempt: AttemptContext,
    start: RenewalStart,
  ): Promise<ITokenResult> {
    const { signal } = attempt;
    // Before anything is asked or sent: material that cannot be loaded, or
    // has expired, refuses the renewal whole — the refresh token is neither
    // sent nor dropped, and no login begins. The pin commit is applied, not
    // merely queued, before anything is sent.
    await this.presentable(signal);
    throwIfAborted(signal);
    const steps: RenewalStepOutcome[] = [];
    // What a stop answers after a step: its error, or its outcome's refusal.
    let lastRefusal: IAuthProviderError | undefined;
    // The refresh token the last step sent before it failed, if it did.
    let sentToken: string | undefined;
    for (;;) {
      // The strategy gets frozen copies; the provider decides from its own
      // `start` and `steps`, never from what it handed out.
      const canRefresh = this.canRefresh();
      const situation: RenewalSituation = Object.freeze({
        cause: frozenCause(start.cause),
        moment: start.moment,
        canRefresh,
        steps: Object.freeze(steps.map(frozenOutcome)),
      });
      const decision = await this.decide(situation, {
        canRefresh,
        sentRequired: needsSentDecision(steps),
        sentToken,
        trigger: start.cause.trigger,
        moment: start.moment,
        signal,
      });
      // Apply `sentRefreshToken` first, through the commit queue.
      if (decision.sentRefreshToken === 'discard' && sentToken !== undefined) {
        const spent = sentToken;
        this.discarded.add(spent);
        await this.commit(() => this.discard(spent, attempt));
      }
      sentToken = undefined;
      if (decision.next === 'stop') {
        throw new AuthProviderFailure(this.stopped(start, lastRefusal));
      }
      // Nothing is dispatched for an attempt already aborted.
      throwIfAborted(signal);
      // One generation per step: a step's commit would otherwise make every
      // later step of the same attempt look old.
      const generation = ++this.credentialGeneration;
      const ended =
        decision.next === 'refresh'
          ? await this.refreshStep(decision.ifCut, attempt, generation, start)
          : await this.loginStep(attempt, generation, start);
      if ('usable' in ended) return ended.usable;
      steps.push(ended.outcome);
      lastRefusal = ended.refusal;
      sentToken = ended.sentToken;
      // Ended by the abort: nobody waits, and the strategy is not asked again.
      throwIfAborted(signal);
    }
  }

  /**
   * Asks the renewal strategy for the next step (spec §6c.5, steps 2–3):
   * the pending abort observations first, then `next(situation)`, raced
   * against the attempt's signal — an abort ends the renewal `aborted` at
   * once, a late answer is ignored. A throw, a foreign thenable (its `then`
   * never called) or an invalid answer ends it `unknown` `renewal-strategy`.
   */
  private async decide(
    situation: RenewalSituation,
    own: {
      readonly canRefresh: boolean;
      readonly sentRequired: boolean;
      readonly sentToken: string | undefined;
      readonly trigger: RenewalCause['trigger'];
      readonly moment: RenewalMoment;
      readonly signal: AbortSignal;
    },
  ): Promise<RenewalDecision> {
    const { sentToken, signal } = own;
    this.deliverObservations();
    throwIfAborted(signal);
    let answer: unknown;
    try {
      const strategy = this.renewal;
      const next = readSafely(strategy, 'next');
      if (typeof next !== 'function') throw this.strategyFailure();
      answer = Reflect.apply(next, strategy, [situation]);
    } catch {
      throw this.strategyFailure();
    }
    if (isPlainPromise(answer)) {
      try {
        answer = await untilAborted(answer, signal);
      } catch {
        throwIfAborted(signal);
        throw this.strategyFailure();
      }
    } else if (typeof readSafely(answer, 'then') === 'function') {
      // A foreign thenable: its `then` is never called.
      throw this.strategyFailure();
    }
    const decision = readDecision(answer, {
      canRefresh: own.canRefresh,
      sentRequired: own.sentRequired,
    });
    // A refresh of the very token this decision discards cannot run.
    if (
      decision === undefined ||
      (decision.next === 'refresh' &&
        decision.sentRefreshToken === 'discard' &&
        sentToken === this.refreshToken)
    ) {
      throw this.strategyFailure();
    }
    // Allowlisted values only (spec §6c.9).
    const trigger = own.trigger;
    const moment = own.moment;
    const next = decision.next;
    logQuietly(() =>
      this.logger?.debug('[BaseTokenProvider] Renewal step', {
        trigger,
        moment,
        next,
      }),
    );
    return decision;
  }

  /**
   * The renewal strategy failed (G6, G7): `unknown`, operation
   * `renewal-strategy`, logged in fixed words. Nothing it threw or answered
   * is relayed.
   */
  private strategyFailure(): AuthProviderFailure {
    const error = authError.unknown(this.operationOf('renewal-strategy'));
    logQuietly(() =>
      this.logger?.warn(
        '[BaseTokenProvider] Renewal strategy refused',
        logFields(error),
      ),
    );
    return new AuthProviderFailure(error);
  }

  /**
   * What a `stop` ends the renewal with (spec §6c.5, step 8): the last
   * step's error or its outcome's refusal; else rule 5's refusal of a
   * `not-credential` rejection; else the `lastRenewal` of a token bound
   * elsewhere; else `renewal-declined`.
   */
  private stopped(
    start: RenewalStart,
    lastRefusal: IAuthProviderError | undefined,
  ): IAuthProviderError {
    if (lastRefusal !== undefined) return lastRefusal;
    const { cause } = start;
    if (cause.trigger === 'rejected' && cause.refusal !== undefined) {
      return cause.refusal;
    }
    if (
      cause.trigger === 'bound-elsewhere' &&
      cause.lastRenewal !== undefined
    ) {
      return cause.lastRenewal;
    }
    return authError['renewal-declined']({ trigger: cause.trigger });
  }

  /**
   * Records a step that ended by the abort (spec §6c.5): synchronously, in
   * the abort handler, calling no foreign code; delivered once, at the
   * first of a queued microtask or the start of the next `next()`.
   */
  private observe(observation: RenewalAbortObservation): void {
    this.observations.push(
      Object.freeze({
        ...observation,
        cause: frozenCause(observation.cause),
      }),
    );
    queueMicrotask(() => this.deliverObservations());
  }

  /**
   * Hands every pending observation to the strategy's `aborted`, once each.
   * Guarded: a throw is logged and ignored, a native promise answered has
   * its rejection marked handled, a foreign thenable's `then` is never
   * called. Nothing waits on it.
   */
  private deliverObservations(): void {
    const pending = this.observations.splice(0);
    for (const observation of pending) {
      try {
        const strategy = this.renewal;
        const aborted = readSafely(strategy, 'aborted');
        if (typeof aborted !== 'function') continue;
        markHandled(Reflect.apply(aborted, strategy, [observation]));
      } catch (error) {
        logQuietly(() =>
          this.logger?.warn(
            '[BaseTokenProvider] Renewal strategy failed to take an aborted step',
            logFields(classify(error, 'renewal-strategy')),
          ),
        );
      }
    }
  }

  /**
   * One refresh step. Once dispatched it runs on whatever its waiters do
   * (spec §6b): the abort handler acts only after `dispatched()` — it
   * records the observation, then applies `ifCut` (`discard` adds the token
   * to `discarded` synchronously and queues its clearing step and report; `keep` does
   * nothing). An abort before dispatch touches no refresh token. The answer,
   * when it comes, is still offered to the commit queue under this step's
   * generation.
   */
  private async refreshStep(
    ifCut: SentRefreshToken,
    attempt: AttemptContext,
    generation: number,
    start: RenewalStart,
  ): Promise<StepEnd> {
    const { signal } = attempt;
    const spent = this.refreshToken;
    // The provider's own correctness, checked here whatever led to the step
    // (G4): an empty or discarded refresh token is never dispatched.
    if (
      typeof spent !== 'string' ||
      spent === '' ||
      this.discarded.has(spent)
    ) {
      // Unreachable: the decision was read against canRefresh.
      throw new AuthProviderFailure(
        authError.unknown(this.operationOf('token-request')),
      );
    }
    logQuietly(() =>
      this.logger?.info(
        '[BaseTokenProvider] Obtaining a new token by refresh',
        {
          oldToken: this.formatToken(this.authorizationToken),
          refreshToken: this.formatToken(spent),
        },
      ),
    );
    let sent = false;
    const dispatched = () => {
      // The gate: an aborted attempt sends nothing.
      if (signal.aborted) throw abortedFailure();
      sent = true;
    };
    const cut = () => {
      if (sent && ifCut === 'discard') {
        this.discarded.add(spent);
        // Detached (the attempt has aborted): it never rejects; marked
        // handled all the same.
        markHandled(this.commit(() => this.discard(spent, attempt)));
      }
      this.observe({
        cause: start.cause,
        moment: start.moment,
        step: 'refresh',
        sent,
        ...(sent
          ? { refreshToken: ifCut === 'discard' ? 'discarded' : 'kept' }
          : {}),
      });
    };
    signal.addEventListener('abort', cut, { once: true });
    try {
      let result: ITokenResult;
      try {
        result = await this.performRefresh(spent, signal, dispatched);
      } catch (thrown) {
        // Cut: `ifCut` decided, and nobody waits for another step. An abort
        // is the consumer's decision, not a failed refresh.
        if (signal.aborted) {
          logQuietly(() =>
            this.logger?.info('[BaseTokenProvider] Refresh ended by the abort'),
          );
          throw abortedFailure();
        }
        // H1: the failure's fixed words and kind, never its message.
        logQuietly(() =>
          this.logger?.warn(
            '[BaseTokenProvider] Refresh failed',
            logFields(classify(thrown, 'refresh')),
          ),
        );
        const error = this.classified(
          thrown,
          this.operationOf('token-request'),
        );
        return {
          outcome: { step: 'refresh', outcome: 'failed', sent, error },
          refusal: error,
          ...(sent ? { sentToken: spent } : {}),
        };
      }
      // Committed even when the attempt was aborted meanwhile, if nothing
      // newer was (spec §6b, rule 2): losing R2 would strand the family.
      let committed: ITokenResult;
      try {
        committed = await this.commitCredentials(
          result,
          generation,
          attempt,
          'refresh',
        );
      } catch (failure) {
        // Only the install's own failure is the step's: the server answered,
        // so `spent` was sent and may be rotated away — a refresh that failed
        // after it was sent, and the strategy decides. Anything after the
        // install (the awaited persistence report) ends the renewal (§6c.6).
        if (!(failure instanceof InstallFailed)) throw failure;
        throwIfAborted(signal);
        const error = this.classified(
          failure.thrown,
          this.operationOf('token-request'),
        );
        return {
          outcome: { step: 'refresh', outcome: 'failed', sent, error },
          refusal: error,
          ...(sent ? { sentToken: spent } : {}),
        };
      }
      return this.judged(committed, 'refresh', start);
    } finally {
      signal.removeEventListener('abort', cut);
    }
  }

  /**
   * One login step: `performLogin(attempt)` and its commit. Whether a
   * request of it was dispatched is known from the sites it calls
   * (`siteOptions(attempt.signal)`), for the step's `sent`.
   */
  private async loginStep(
    attempt: AttemptContext,
    generation: number,
    start: RenewalStart,
  ): Promise<StepEnd> {
    const { signal } = attempt;
    logQuietly(() => this.logger?.info('[BaseTokenProvider] Performing login'));
    let sent = false;
    this.loginDispatch.set(signal, () => {
      if (signal.aborted) throw abortedFailure();
      sent = true;
    });
    const cut = () =>
      this.observe({
        cause: start.cause,
        moment: start.moment,
        step: 'login',
        sent,
      });
    signal.addEventListener('abort', cut, { once: true });
    try {
      let result: ITokenResult;
      try {
        result = await this.performLogin(attempt);
      } catch (thrown) {
        throwIfAborted(signal);
        const error = this.classified(
          thrown,
          this.operationOf('token-request'),
        );
        return {
          outcome: { step: 'login', outcome: 'failed', sent, error },
          refusal: error,
        };
      }
      // A login's install failure ends the renewal, as any commit failure
      // does: unlike a refresh, no refresh token is left in doubt, so there
      // is nothing for the strategy to decide.
      let committed: ITokenResult;
      try {
        committed = await this.commitCredentials(
          result,
          generation,
          attempt,
          'login',
        );
      } catch (failure) {
        throw failure instanceof InstallFailed ? failure.thrown : failure;
      }
      return this.judged(committed, 'login', start);
    } finally {
      signal.removeEventListener('abort', cut);
      this.loginDispatch.delete(signal);
    }
  }

  /**
   * How a committed step ended (spec §6c.5, step 7): usable — the renewal
   * ends with it; `unchanged` — a rejection's renewal obtained the token
   * refused; `bound-elsewhere` — still bound elsewhere than the pinned
   * certificate. Either of the last two stays committed: it is the
   * server's state.
   */
  private judged(
    committed: ITokenResult,
    step: RenewalStep,
    start: RenewalStart,
  ): StepEnd {
    const token = committed.authorizationToken;
    if (start.refused !== undefined && token === start.refused) {
      return {
        outcome: { step, outcome: 'unchanged' },
        refusal: authError['renewal-unchanged']({ source: 'token-provider' }),
      };
    }
    if (this.elsewhereThanPinned(token)) {
      const remembered = this.remembered;
      return {
        outcome: { step, outcome: 'bound-elsewhere' },
        refusal:
          remembered !== undefined && remembered.token === token
            ? remembered.error
            : renewedBoundElsewhere(),
      };
    }
    return { usable: committed };
  }

  /**
   * The queued step that discards a refresh token — by the renewal
   * strategy's `sentRefreshToken` or `ifCut`: it clears `refreshToken` only
   * if it still holds that one (never a token something else stored
   * meanwhile) and reports `refresh-token-discarded` with the credential
   * still held. A token no longer held reports nothing: the store already
   * holds the newer state the replacing commit reported (spec §6c.6). It
   * advances no watermark, so the same attempt's late answer can still be
   * committed after it.
   */
  private async discard(spent: string, attempt: AttemptContext): Promise<void> {
    if (this.refreshToken !== spent) return;
    this.refreshToken = undefined;
    await this.reportChange(
      (awaited) => ({
        event: 'refresh-token-discarded',
        credential: this.reportedCredential(),
        awaited,
      }),
      attempt,
    );
  }

  /**
   * The credential commit of a step's result (spec §6b, §6c.5): applied
   * only if the step's generation is newer than the credential watermark,
   * and — for a login — only if the attempt was not aborted (a refresh's
   * answer is the server's state, rule 2). The result's refresh token is
   * installed only when it is usable — non-empty and not discarded;
   * otherwise the one held stays. Then, in order: the tokens,
   * `markIfElsewhere` against the pinned thumbprint current now, the
   * progress line, and the `credential` report. A commit discarded by the
   * watermark reports nothing.
   */
  private async commitCredentials(
    result: ITokenResult,
    generation: number,
    attempt: AttemptContext,
    obtained: Obtained,
  ): Promise<ITokenResult> {
    const applied = await this.commit(async () => {
      if (obtained === 'login' && attempt.signal.aborted) return undefined;
      if (generation <= this.credentialWatermark) return undefined;
      this.credentialWatermark = generation;
      const fresh = result.refreshToken;
      // A discarded refresh token in a result is read as none, nothing more.
      const usable =
        typeof fresh === 'string' && fresh !== '' && !this.discarded.has(fresh)
          ? fresh
          : undefined;
      const accepted: ITokenResult = { ...result, refreshToken: usable };
      try {
        this.updateTokens(accepted);
      } catch (thrown) {
        throw new InstallFailed(thrown);
      }
      this.markIfElsewhere(accepted.authorizationToken);
      // Written once the commit applied its tokens, before the report (H2).
      logQuietly(() =>
        this.logger?.info(
          obtained === 'refresh'
            ? '[BaseTokenProvider] Token refreshed successfully'
            : '[BaseTokenProvider] Login completed',
          {
            newToken: this.formatToken(accepted.authorizationToken),
            newRefreshToken: this.formatToken(usable),
          },
        ),
      );
      // A failure from here on is not the step's: the credentials are
      // committed, and it ends the renewal (§6c.6).
      await this.reportChange(
        (awaited) => ({
          event: 'credential',
          // The grant the result names, as `onTokens` was told before 6.0.0.
          credential: this.reportedCredential(accepted.authType),
          refreshToken:
            usable === undefined
              ? { change: 'none' }
              : { change: 'new', value: usable },
          awaited,
        }),
        attempt,
      );
      // What it returns carries the refresh token held, or none (G4).
      return { ...accepted, refreshToken: this.heldRefresh() };
    });
    if (applied !== undefined) return applied;
    // Discarded: an aborted attempt has no waiter left to answer. A live
    // attempt is always the newest of its kind, so it is never discarded;
    // were it, the credentials in place are the answer.
    throwIfAborted(attempt.signal);
    return this.heldResult() ?? result;
  }

  /**
   * One report to the persistence strategy, from inside a commit (spec
   * §6c.6). `awaited` is decided now, as the report starts: true while the
   * attempt that made the commit still has a live waiter. An awaited
   * report is awaited — a collaborator's answer, adopted as `await` adopts
   * it — and its throw or rejection is the renewal's failure (`unknown`,
   * `persisting-tokens`), also logged as detached when every waiter left
   * while it ran; never a failed step, so a store write that fails starts
   * no login. A detached one is called and not awaited: its throw or
   * rejection is logged in fixed words and goes no further. `make` builds a
   * fresh report each time — a strategy changing it changes nothing held.
   * Building an awaited report (`getAuthType()` is a subclass's) is the
   * provider's own work: its throw ends the renewal as it is.
   * The provider never reports the same change twice.
   */
  private async reportChange(
    make: (awaited: boolean) => PersistenceReport,
    attempt: AttemptContext,
  ): Promise<void> {
    const persistence = this.persistence;
    if (persistence === undefined) return;
    const awaited = !attempt.signal.aborted;
    if (!awaited) {
      try {
        onAnswerRejection(this.callReport(persistence, make(false)), (error) =>
          this.detachedFailed(error),
        );
      } catch (error) {
        this.detachedFailed(error);
      }
      return;
    }
    // Built before the strategy is called: a fault of this provider (an
    // unusable `getAuthType()`) ends the renewal with its own error, never
    // blamed on persistence (G7).
    const report = make(true);
    try {
      await this.callReport(persistence, report);
    } catch (error) {
      // Every waiter left while the report ran: nobody receives the
      // renewal's failure, so it is logged as a detached one would be.
      if (attempt.signal.aborted) this.detachedFailed(error);
      throw new AuthProviderFailure(this.persistingFailure(error));
    }
  }

  /** `persistence.report(report)`, read without running a getter. */
  private callReport(
    persistence: ITokenPersistence,
    report: PersistenceReport,
  ): unknown {
    const method = readSafely(persistence, 'report');
    if (typeof method !== 'function') {
      throw new AuthProviderFailure(
        authError.unknown(this.operationOf('persisting-tokens')),
      );
    }
    return Reflect.apply(method, persistence, [report]);
  }

  /**
   * What an awaited report's failure ends the renewal with: `unknown`,
   * `persisting-tokens`, with an allowlisted status or code the thrown
   * value carries — never anything the strategy minted, relayed as itself
   * (G6).
   */
  private persistingFailure(error: unknown): IAuthProviderError {
    const of = this.operationOf('persisting-tokens');
    const classified = this.classified(error, of);
    return classified.kind === 'unknown' &&
      classified.facts.operation === 'persisting-tokens'
      ? classified
      : authError.unknown(of);
  }

  /** A detached report failed: logged in fixed words, attributed to nothing. */
  private detachedFailed(error: unknown): void {
    logQuietly(() =>
      this.logger?.warn(
        '[BaseTokenProvider] Persisting the tokens failed',
        logFields(classify(error, 'persisting-tokens')),
      ),
    );
  }

  /**
   * The credential held, as a report carries it: `''` for no access token;
   * the grant `named` when it is one on the list (a committed result's own),
   * else this provider's (`readGrant`).
   */
  private reportedCredential(named?: unknown): ReportedCredential {
    return {
      authorizationToken: this.authorizationToken ?? '',
      tokenType: this.tokenType ?? 'jwt',
      authType: isGrant(named) ? named : this.heldGrant(),
      expiresAt: this.expiresAt,
    };
  }

  /** The credentials held, as a result; undefined without a token. */
  private heldResult(): ITokenResult | undefined {
    const authorizationToken = this.authorizationToken;
    if (authorizationToken === undefined) return undefined;
    return {
      authorizationToken,
      refreshToken: this.heldRefresh(),
      authType: this.heldGrant(),
      tokenType: this.tokenType ?? 'jwt',
      expiresAt: this.expiresAt,
    };
  }

  /**
   * The grant a result built from what is held names: `getAuthType()` read
   * once for the provider's lifetime (`readGrant`), like every other path.
   * Unreadable or off the list: the request fails as `unknown`, naming the
   * operation alone.
   */
  private heldGrant(): OAuth2GrantType {
    const grant = this.readGrant();
    if (grant === undefined) {
      throw new AuthProviderFailure(
        authError.unknown({ operation: 'token-request' }),
      );
    }
    return grant;
  }

  /**
   * The refresh token held, for a result this provider returns (spec
   * §6c.1, G4): a usable one, else none. A discarded one is not handed out
   * — it is never submitted again — even while its clearing step still
   * waits in the queue.
   */
  private heldRefresh(): string | undefined {
    const held = this.refreshToken;
    return typeof held === 'string' && held !== '' && !this.discarded.has(held)
      ? held
      : undefined;
  }

  async validateToken(_token: string, _serviceUrl?: string): Promise<boolean> {
    logQuietly(() =>
      this.logger?.debug('[BaseTokenProvider] Validating token'),
    );
    if (this.tokenType && this.tokenType !== 'jwt') {
      if (!this.expiresAt) {
        logQuietly(() =>
          this.logger?.warn(
            '[BaseTokenProvider] Token validation failed: missing expiresAt for non-JWT token',
          ),
        );
        return false;
      }
      const bufferMs = 60 * 1000;
      const stated = this.expiresAt;
      const isValid = Date.now() < stated - bufferMs;
      logQuietly(() =>
        this.logger?.info('[BaseTokenProvider] Token validation result', {
          isValid,
          tokenType: this.tokenType,
          expiresAt: this.formatExpirationDate(stated),
          expiresIn: Math.floor((stated - Date.now()) / 1000),
        }),
      );
      return isValid;
    }
    const expiresAt = this.parseExpirationFromJWT(_token);
    if (!expiresAt) {
      logQuietly(() =>
        this.logger?.warn(
          '[BaseTokenProvider] Token validation failed: cannot parse expiration',
        ),
      );
      return false;
    }
    const bufferMs = 60 * 1000;
    const isValid = Date.now() < expiresAt - bufferMs;
    logQuietly(() =>
      this.logger?.info('[BaseTokenProvider] Token validation result', {
        isValid,
        expiresAt: this.formatExpirationDate(expiresAt),
        expiresIn: Math.floor((expiresAt - Date.now()) / 1000),
      }),
    );
    return isValid;
  }

  /**
   * Update internal token cache from result
   * @param result Token result to cache
   */
  protected updateTokens(result: ITokenResult): void {
    this.remembered = undefined;
    const oldToken = this.formatToken(this.authorizationToken);
    this.authorizationToken = result.authorizationToken;
    // Only a usable refresh token replaces the one held (spec §6c.5): a
    // result without one leaves it held, and the next refresh sends it
    // (RFC 6749 §6).
    const fresh = result.refreshToken;
    if (typeof fresh === 'string' && fresh !== '') this.refreshToken = fresh;
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
    logQuietly(() =>
      this.logger?.info('[BaseTokenProvider] Tokens updated', {
        oldToken,
        newToken: this.formatToken(result.authorizationToken),
        newRefreshToken: this.formatToken(result.refreshToken),
        tokenType: this.tokenType,
        expiresAt: this.expiresAt
          ? this.formatExpirationDate(this.expiresAt)
          : undefined,
      }),
    );
  }

  /**
   * Parse expiration time from JWT token
   * @param token JWT token string
   * @returns Expiration timestamp in milliseconds, or undefined if cannot parse
   */
  protected parseExpirationFromJWT(token: string): number | undefined {
    try {
      const parts = token.split('.');
      const payload = parts[1];
      if (parts.length !== 3 || payload === undefined) {
        return undefined;
      }

      // Convert base64url to base64
      // Plain code, no regex: the token is foreign input.
      const base64 = payload.split('-').join('+').split('_').join('/');
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

  // ---- IAuthProvider: the process calls these, the same for every provider.

  /** The grant type, so a log line says which way in ran. */
  get kind(): string {
    return this.getAuthType();
  }

  /**
   * The grant a refusal names: `getAuthType()`, read once for the provider's
   * lifetime — the first time inside a boundary or a failure's conversion.
   */
  protected override grant(): OAuth2GrantType | undefined {
    return this.readGrant();
  }

  protected async onPrepare(): Promise<AuthOutcome> {
    // `remembered` stays: `moment: 'prepare'` is the renewal strategy's cue
    // to try a token renewed bound elsewhere once more (spec §6c.4). A login
    // this starts waits on the attached parties (spec §6b).
    await this.asMoment((signal) => this.tokensFor(signal, 'prepare'));
    return OK;
  }

  /**
   * The token is presented per request; the logon carries the pinned
   * certificate when the token may need it (spec §4's table). Decided on the
   * token this provider HOLDS — a logon never obtains, refreshes or logs in.
   * No token, an expired one, or one being renewed reads as unknown: the
   * token presented will be the one authorize() obtains through the same
   * strategy and pinned material, and authorize() checks that one.
   */
  protected async onEstablish(logon: ILogonTarget): Promise<AuthOutcome> {
    const pinned = await this.asMoment((signal) => this.presentable(signal));
    const held =
      !this.renewing && this.isTokenValid()
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
    const presented = relayOutcome(
      () => logon.tlsMaterial(copyMaterial(pinned.material)),
      'tls-material',
      'presenting-certificate',
    );
    // Unbound: the Bearer carries the token, the certificate is a courtesy
    // — but a target that throws is broken (rule 1), and that is an Oops.
    // Bound or unknown: the token is not sent on a connection without it.
    return binding.state === 'unbound' && !presented.thrown
      ? OK
      : presented.outcome;
  }

  /**
   * Per attempt: getTokens() renews an expired token here — and one bound to
   * another certificate than the pinned one — and the token actually sent is
   * the one checked.
   */
  protected async onAuthorize(request: IRequestTarget): Promise<AuthOutcome> {
    // Pinned here too, so a token served from cache (seeded, restored) is
    // checked against the certificate like an obtained one.
    // One moment, one waiter: the attached parties, for the pin and the
    // renewal alike (spec §6b).
    const { pinned, result } = await this.asMoment(async (signal) => ({
      pinned: await this.pin(signal),
      result: await this.tokensFor(signal, 'authorize'),
    }));
    if (!this.presents(readBinding(result.authorizationToken), pinned)) {
      // Pinned: getTokens() already renewed a token bound elsewhere, and
      // this one is remembered with what that renewal answered — still
      // bound elsewhere, or its own refusal when it threw. The minted
      // refusal itself, frozen: no caller can change the next answer.
      if (!pinned) return boundElsewhere();
      const remembered = this.remembered;
      if (remembered && result.authorizationToken === remembered.token) {
        // The very error the renewal produced, minted and frozen (C15).
        return { ok: false, refusal: remembered.error };
      }
      return { ok: false, refusal: renewedBoundElsewhere() };
    }
    // The thunk answers OK or throws: `refused` names no fallback that
    // can apply, a throw is the target's failure (rule 1).
    const written = relayOutcome(
      () => {
        this.applyToken(request, result);
        return OK;
      },
      'logon-parameters',
      'presenting-token',
    );
    if (written.thrown) return written.outcome;
    this.presented = result.authorizationToken;
    return OK;
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
   * A new token, through the renewal strategy (rule 6): its cause
   * `rejected`, with rule 5's reading — a reading, not a guard (G9): whether
   * to renew on a `403` is the strategy's. Ok only if what is presented
   * changed; retrying is the caller's. A renewal in flight is joined; a
   * presented token already superseded by a renewal answers Ok without
   * renewing again.
   */
  protected async onRejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    // Nothing presented yet (a rejection before any authorize): the token
    // held — from a login or from config — is the one taken as refused.
    const refused = this.presented ?? this.authorizationToken;
    if (
      !this.renewing &&
      refused !== undefined &&
      this.authorizationToken !== undefined &&
      this.authorizationToken !== refused
    ) {
      return OK;
    }
    const cause = rejectionCause(rejection);
    const result = await this.asMoment(async (signal) => {
      try {
        return await this.renewed(signal, () => ({
          cause,
          moment: 'rejected',
          refused,
        }));
      } catch (error) {
        throw this.thrownFor(error);
      }
    });
    if (refused !== undefined && result.authorizationToken === refused) {
      return {
        ok: false,
        refusal: authError['renewal-unchanged']({ source: 'token-provider' }),
      };
    }
    return OK;
  }

  /** How this provider's token rides on a request. Bearer by default. */
  protected applyToken(request: IRequestTarget, result: ITokenResult): void {
    // A target answering a rejecting promise raises nothing (rule 1).
    markHandled(
      request.header('Authorization', `Bearer ${result.authorizationToken}`),
    );
  }
}

/**
 * A frozen copy of a cause, to hand to the strategy (review M-1). Its
 * errors are minted, frozen already, and shared as they are.
 */
function frozenCause(cause: RenewalCause): RenewalCause {
  return Object.freeze({ ...cause });
}

/** A frozen copy of a step outcome, to hand to the strategy. */
function frozenOutcome(outcome: RenewalStepOutcome): RenewalStepOutcome {
  return Object.freeze({ ...outcome });
}

/** A17: a held token bound to a certificate while none is pinned. */
function boundElsewhere(): AuthOutcome {
  return {
    ok: false,
    refusal: authError['token-binding']({ problem: 'bound-to-unpinned' }),
  };
}

/** A18: a renewed token still bound to another certificate. */
function renewedBoundElsewhere(): IAuthProviderError {
  return authError['token-binding']({ problem: 'renewed-bound-elsewhere' });
}
