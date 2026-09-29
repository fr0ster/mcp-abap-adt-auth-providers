/**
 * OIDC Device Flow Provider
 */

import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { discoverOidc } from '../auth/oidcDiscovery';
import {
  initiateDeviceAuthorization,
  pollDeviceTokens,
  refreshOidcToken,
} from '../auth/oidcToken';
import {
  consoleDeviceCodePresenter,
  DeviceCodePresentationError,
  type IDeviceCodePresenter,
} from '../deviceCode/DeviceCodePresenter';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface OidcDeviceFlowProviderConfig extends TokenProviderHooks {
  issuerUrl?: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  deviceAuthorizationEndpoint?: string;
  tokenEndpoint?: string;
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
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
      this.expiresAt = this.parseExpirationFromJWT(config.accessToken);
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
    if (
      !this.config.deviceAuthorizationEndpoint &&
      !this.config.tokenEndpoint &&
      !this.config.issuerUrl
    ) {
      throw new Error('OIDC issuerUrl is required when discovery is used');
    }
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    if (
      !this.config.deviceAuthorizationEndpoint &&
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
    );

    try {
      await this.config.presenter.present({
        verificationUri: deviceFlow.verificationUri,
        verificationUriComplete: deviceFlow.verificationUriComplete,
        userCode: deviceFlow.userCode,
        expiresInSeconds: deviceFlow.expiresIn,
      });
    } catch (error) {
      // The presenter's text may hold the code; the log gets its class only.
      this.logger?.warn('[OidcDeviceFlowProvider] presenter failed', {
        error: error instanceof Error ? 'Error' : typeof error,
      });
      throw new DeviceCodePresentationError();
    }

    const tokens = await pollDeviceTokens(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      deviceFlow.deviceCode,
      deviceFlow.interval || 5,
      this.logger,
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      return this.performLogin();
    }
    if (!this.config.tokenEndpoint && !this.config.issuerUrl) {
      throw new Error('OIDC issuerUrl is required when discovery is used');
    }
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    if (this.config.tokenEndpoint === undefined) {
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
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || this.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
}
