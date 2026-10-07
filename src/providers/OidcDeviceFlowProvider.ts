/**
 * OIDC Device Flow Provider
 */

import {
  type AttemptContext,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { throwIfAborted, untilAborted } from '../auth/attempt';
import {
  oidcEndpointMissing,
  oidcIssuerRequired,
  ownOptions,
} from '../auth/configuration';
import { loginFailure } from '../auth/interactiveLogin';
import { discoverOidc, mtlsAlias } from '../auth/oidcDiscovery';
import {
  initiateDeviceAuthorization,
  pollDeviceTokens,
  refreshOidcToken,
} from '../auth/oidcToken';
import { logQuietly } from '../auth/tokenRequest';
import {
  consoleDeviceCodePresenter,
  type IDeviceCodePresenter,
} from '../deviceCode/DeviceCodePresenter';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  refreshTokenRefused,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface OidcDeviceFlowProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  issuerUrl?: string | undefined;
  clientId: string;
  clientSecret?: string | undefined;
  scopes?: string[] | undefined;
  deviceAuthorizationEndpoint?: string | undefined;
  tokenEndpoint?: string | undefined;
  accessToken?: string | undefined;
  refreshToken?: string | undefined;
  /**
   * When `accessToken` expires (epoch ms), for a token that carries no `exp`
   * of its own. A JWT's `exp` wins; without either the seed counts as expired.
   */
  expiresAt?: number | undefined;
  logger?: ILogger | undefined;
  /**
   * How the user learns the verification URL and code. Required — see the
   * static factories for the usual choice.
   */
  presenter: IDeviceCodePresenter;
}

export class OidcDeviceFlowProvider extends BaseTokenProvider {
  private config: OidcDeviceFlowProviderConfig;

  constructor(options: OidcDeviceFlowProviderConfig) {
    // Read once as own data (a hostile object throws nothing of its own).
    const config = ownOptions<OidcDeviceFlowProviderConfig>(options);
    super(config);
    this.config = config;
    this.logger = config.logger;

    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      this.expiresAt = this.seededExpiry(config.accessToken, config.expiresAt);
    }
    if (config.refreshToken) {
      this.refreshToken = config.refreshToken;
    }
  }

  /** The usual choice: print the prompt to the logger, or stderr. */
  static toConsole(
    config: Omit<OidcDeviceFlowProviderConfig, 'presenter'>,
  ): OidcDeviceFlowProvider {
    const own =
      ownOptions<Omit<OidcDeviceFlowProviderConfig, 'presenter'>>(config);
    return new OidcDeviceFlowProvider({
      ...own,
      presenter: consoleDeviceCodePresenter(own.logger),
    });
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_AUTHORIZATION_CODE;
  }

  protected async performLogin(attempt: AttemptContext): Promise<ITokenResult> {
    // The whole device flow — initiation, presentation, polling — is the
    // attempt's exclusive work: it starts once the previous attempt's has
    // settled (the drain, spec §6b), and its part of the drain settles at the
    // abort itself, never when an outstanding poll answers.
    return attempt.exclusive(() =>
      untilAborted(this.deviceLogin(attempt.signal), attempt.signal),
    );
  }

  /** The device flow under the attempt's signal. */
  private async deviceLogin(signal: AbortSignal): Promise<ITokenResult> {
    // Each endpoint not given ('' included) comes from discovery: one given
    // beside one missing still needs the other.
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    if (
      !this.config.deviceAuthorizationEndpoint ||
      !this.config.tokenEndpoint
    ) {
      if (!this.config.issuerUrl) {
        throw oidcIssuerRequired();
      }
      discovery = await discoverOidc(
        this.config.issuerUrl,
        this.logger,
        signal,
      );
    }
    const deviceAuthorizationEndpoint =
      this.config.deviceAuthorizationEndpoint ||
      discovery?.device_authorization_endpoint;
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;

    if (!deviceAuthorizationEndpoint) {
      throw oidcEndpointMissing('deviceAuthorizationEndpoint');
    }
    if (!tokenEndpoint) {
      throw oidcEndpointMissing('tokenEndpoint');
    }

    const scope = this.config.scopes?.join(' ');
    const deviceFlow = await initiateDeviceAuthorization(
      deviceAuthorizationEndpoint,
      this.config.clientId,
      scope,
      this.logger,
      // Its own alias: the device endpoint's, not the token endpoint's. The
      // plain token endpoint beside it: a client assertion's audience.
      await this.requestAuth(
        this.config.deviceAuthorizationEndpoint
          ? undefined
          : mtlsAlias(discovery, 'device_authorization_endpoint'),
        tokenEndpoint,
      ),
      this.siteOptions(signal),
    );

    throwIfAborted(signal);
    try {
      await this.config.presenter.present({
        verificationUri: deviceFlow.verificationUri,
        verificationUriComplete: deviceFlow.verificationUriComplete,
        userCode: deviceFlow.userCode,
        expiresInSeconds: deviceFlow.expiresIn,
      });
    } catch (error) {
      // H3: the presenter's text may hold the code; the log gets the
      // `logFields` of its failure only.
      logQuietly(() =>
        this.logger?.warn(
          '[OidcDeviceFlowProvider] presenter failed',
          logFields(readFailure(error, 'presenting-device-code')),
        ),
      );
      // K17 / A2.
      throw loginFailure({ outcome: 'device-code-not-shown' });
    }

    const tokens = await pollDeviceTokens(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      deviceFlow.deviceCode,
      deviceFlow.interval || 5,
      this.logger,
      await this.requestAuth(
        this.config.tokenEndpoint
          ? undefined
          : mtlsAlias(discovery, 'token_endpoint'),
      ),
      this.siteOptions(signal),
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  protected async performRefresh(
    refreshToken: string,
    signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult> {
    if (!refreshToken) {
      throw refreshTokenRefused();
    }
    if (!this.config.tokenEndpoint && !this.config.issuerUrl) {
      throw oidcIssuerRequired();
    }
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    // As at login: a token endpoint not given ('' included) is discovered.
    if (!this.config.tokenEndpoint) {
      if (!this.config.issuerUrl) {
        throw oidcIssuerRequired();
      }
      discovery = await discoverOidc(
        this.config.issuerUrl,
        this.logger,
        signal,
      );
    }
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;
    if (!tokenEndpoint) {
      throw oidcEndpointMissing('tokenEndpoint');
    }
    // Nothing is sent once the attempt is aborted; once sent, the refresh
    // runs on (spec §6b).
    throwIfAborted(signal);
    const tokens = await refreshOidcToken(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      refreshToken,
      this.logger,
      // The alias belongs to the discovered endpoint only.
      await this.requestAuth(
        this.config.tokenEndpoint
          ? undefined
          : mtlsAlias(discovery, 'token_endpoint'),
      ),
      this.refreshSiteOptions(dispatched),
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
}
