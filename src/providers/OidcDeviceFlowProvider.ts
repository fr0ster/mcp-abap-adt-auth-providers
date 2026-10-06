/**
 * OIDC Device Flow Provider
 */

import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { asContract } from '../auth/contractShape';
import { discoverOidc, mtlsAlias } from '../auth/oidcDiscovery';
import {
  initiateDeviceAuthorization,
  pollDeviceTokens,
  refreshOidcToken,
} from '../auth/oidcToken';
import { loggedError } from '../auth/refusal';
import { logQuietly } from '../auth/tokenRequest';
import {
  consoleDeviceCodePresenter,
  DeviceCodePresentationError,
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

  constructor(config: OidcDeviceFlowProviderConfig) {
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
    return new OidcDeviceFlowProvider({
      ...config,
      presenter: consoleDeviceCodePresenter(config.logger),
    });
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_AUTHORIZATION_CODE;
  }

  protected async performLogin(): Promise<ITokenResult> {
    // Each endpoint not given ('' included) comes from discovery: one given
    // beside one missing still needs the other.
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    if (
      !this.config.deviceAuthorizationEndpoint ||
      !this.config.tokenEndpoint
    ) {
      if (!this.config.issuerUrl) {
        throw new Error('OIDC issuerUrl is required when discovery is used');
      }
      discovery = await discoverOidc(this.config.issuerUrl, this.logger);
    }
    const deviceAuthorizationEndpoint =
      this.config.deviceAuthorizationEndpoint ||
      discovery?.device_authorization_endpoint;
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;

    if (!deviceAuthorizationEndpoint) {
      throw new Error(
        'OIDC device authorization endpoint is required (deviceAuthorizationEndpoint or discovery)',
      );
    }
    if (!tokenEndpoint) {
      throw new Error(
        'OIDC token endpoint is required (tokenEndpoint or discovery)',
      );
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
      this.siteOptions(),
    );

    try {
      await this.config.presenter.present({
        verificationUri: deviceFlow.verificationUri,
        verificationUriComplete: deviceFlow.verificationUriComplete,
        userCode: deviceFlow.userCode,
        expiresInSeconds: deviceFlow.expiresIn,
      });
    } catch (error) {
      // The presenter's text may hold the code; the log gets fixed words only.
      logQuietly(() =>
        this.logger?.warn(
          '[OidcDeviceFlowProvider] presenter failed',
          loggedError(error, 'the presenter'),
        ),
      );
      throw new DeviceCodePresentationError();
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
      this.siteOptions(),
    );

    return asContract<ITokenResult>({
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    });
  }

  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      throw refreshTokenRefused();
    }
    if (!this.config.tokenEndpoint && !this.config.issuerUrl) {
      throw new Error('OIDC issuerUrl is required when discovery is used');
    }
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    // As at login: a token endpoint not given ('' included) is discovered.
    if (!this.config.tokenEndpoint) {
      if (!this.config.issuerUrl) {
        throw new Error('OIDC issuerUrl is required when discovery is used');
      }
      discovery = await discoverOidc(this.config.issuerUrl, this.logger);
    }
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;
    if (!tokenEndpoint) {
      throw new Error(
        'OIDC token endpoint is required (tokenEndpoint or discovery)',
      );
    }
    const tokens = await refreshOidcToken(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      this.refreshToken,
      this.logger,
      // The alias belongs to the discovered endpoint only.
      await this.requestAuth(
        this.config.tokenEndpoint
          ? undefined
          : mtlsAlias(discovery, 'token_endpoint'),
      ),
      this.siteOptions(),
    );

    return asContract<ITokenResult>({
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || this.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    });
  }
}
