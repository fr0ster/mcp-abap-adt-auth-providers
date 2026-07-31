/**
 * Device Flow Token Provider
 *
 * Uses OAuth2 Device Flow for devices without browser or input capabilities.
 * User authorizes on another device by entering a code.
 */

import type {
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import { announcer } from '../auth/announce';
import {
  initiateDeviceFlow,
  pollForDeviceTokens,
} from '../auth/deviceFlowAuth';
import { refreshJwtToken } from '../auth/tokenRefresher';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface DeviceFlowProviderConfig {
  uaaUrl: string;
  clientId: string;
  clientSecret?: string; // Optional for public clients
  scope?: string; // Optional scope (space-separated)
  // Optional: existing token
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
}

/**
 * Device Flow token provider
 *
 * Uses OAuth2 Device Flow - user authorizes on another device.
 * Supports refresh token if provided by server.
 */
export class DeviceFlowProvider extends BaseTokenProvider {
  private config: DeviceFlowProviderConfig;

  constructor(config: DeviceFlowProviderConfig) {
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
    // Device Flow is not a standard grant type in OAuth2 spec
    // We'll use a custom type or map it to authorization_code
    // For now, using authorization_code as it's similar
    return AUTH_TYPE_AUTHORIZATION_CODE;
  }

  protected async performLogin(): Promise<ITokenResult> {
    // Initiate device flow
    const deviceFlow = await initiateDeviceFlow(
      this.config.uaaUrl,
      this.config.clientId,
      this.config.scope,
      this.logger,
    );

    // Display user code and verification URI. This is a prompt the user must
    // see to complete the flow, not a log line — it goes to the logger when
    // there is one and to stderr otherwise, never to stdout.
    const announce = announcer(this.logger);
    announce('Device Flow Authorization');
    announce(`Go to: ${deviceFlow.verificationUri}`);
    if (deviceFlow.verificationUriComplete) {
      announce(`Or use complete URL: ${deviceFlow.verificationUriComplete}`);
    }
    announce(`Enter code: ${deviceFlow.userCode}`);
    announce('Waiting for authorization...');

    // Poll for tokens
    const result = await pollForDeviceTokens(
      this.config.uaaUrl,
      this.config.clientId,
      this.config.clientSecret,
      deviceFlow.deviceCode,
      deviceFlow.interval,
      this.logger,
    );

    const expiresIn = this.calculateExpiresIn(result.accessToken);

    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE, // Device flow maps to authorization_code
      expiresIn,
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      // No refresh token - re-authenticate with device flow
      return await this.performLogin();
    }

    try {
      const result = await refreshJwtToken(
        this.refreshToken,
        this.config.uaaUrl,
        this.config.clientId,
        this.config.clientSecret || '',
      );

      const expiresIn = this.calculateExpiresIn(result.accessToken);

      return {
        authorizationToken: result.accessToken,
        refreshToken: result.refreshToken || this.refreshToken,
        authType: AUTH_TYPE_AUTHORIZATION_CODE,
        expiresIn,
      };
    } catch (_error) {
      // Refresh failed - try device flow login
      return await this.performLogin();
    }
  }
}
