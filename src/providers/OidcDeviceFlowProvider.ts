/**
 * OIDC Device Flow Provider
 */

import type {
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import { discoverOidc } from '../auth/oidcDiscovery';
import {
  initiateDeviceAuthorization,
  pollDeviceTokens,
  refreshOidcToken,
} from '../auth/oidcToken';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface OidcDeviceFlowProviderConfig {
  issuerUrl?: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  deviceAuthorizationEndpoint?: string;
  tokenEndpoint?: string;
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
}

export class OidcDeviceFlowProvider extends BaseTokenProvider {
  private config: OidcDeviceFlowProviderConfig;

  constructor(config: OidcDeviceFlowProviderConfig) {
    super();
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

    // Manual user guidance
    console.log('');
    console.log('OIDC device authorization');
    console.log('Go to:', deviceFlow.verificationUri);
    if (deviceFlow.verificationUriComplete) {
      console.log('Or use:', deviceFlow.verificationUriComplete);
    }
    console.log('Enter code:', deviceFlow.userCode);
    console.log('');

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
