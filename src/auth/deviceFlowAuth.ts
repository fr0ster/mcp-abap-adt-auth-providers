/**
 * Device Flow authentication
 *
 * OAuth2 Device Flow for devices without browser or input capabilities.
 * User authorizes on another device by entering a code.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';

export interface DeviceFlowResult {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
  expiresIn: number;
  interval?: number; // Polling interval in seconds
}

export interface DeviceFlowTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
}

/**
 * Initiate device flow - get device code and user code
 * @param uaaUrl UAA URL
 * @param clientId Client ID
 * @param scope Optional scope (space-separated)
 * @param logger Optional logger
 * @returns Promise that resolves to device flow result
 * @internal - Internal function, not exported from package
 */
export async function initiateDeviceFlow(
  uaaUrl: string,
  clientId: string,
  scope?: string,
  logger?: ILogger,
): Promise<DeviceFlowResult> {
  try {
    const deviceUrl = `${uaaUrl}/oauth/device_authorization`;

    const params = new URLSearchParams();
    params.append('client_id', clientId);
    if (scope) {
      params.append('scope', scope);
    }

    logger?.info(`Initiating device flow: ${deviceUrl}`);

    const response = await axios({
      method: 'post',
      url: deviceUrl,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: params.toString(),
      timeout: 30000,
    });

    if (
      response.data?.device_code &&
      response.data?.user_code &&
      response.data?.verification_uri
    ) {
      return {
        deviceCode: response.data.device_code,
        userCode: response.data.user_code,
        verificationUri: response.data.verification_uri,
        verificationUriComplete: response.data.verification_uri_complete,
        expiresIn: response.data.expires_in || 1800, // Default 30 minutes
        interval: response.data.interval || 5, // Default 5 seconds
      };
    } else {
      throw new Error('Response does not contain required device flow fields');
    }
  } catch (error: unknown) {
    if (
      error &&
      typeof error === 'object' &&
      'response' in error &&
      error.response &&
      typeof error.response === 'object' &&
      'status' in error.response &&
      'data' in error.response
    ) {
      const axiosError = error as {
        response: { status: number; data: unknown };
      };
      throw new Error(
        `Device flow initiation failed (${axiosError.response.status}): ${JSON.stringify(axiosError.response.data)}`,
      );
    } else {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      throw new Error(`Device flow initiation failed: ${errorMessage}`);
    }
  }
}

/**
 * Poll for tokens using device code
 * @param uaaUrl UAA URL
 * @param clientId Client ID
 * @param clientSecret Client secret (optional for public clients)
 * @param deviceCode Device code from initiateDeviceFlow
 * @param interval Polling interval in seconds
 * @param logger Optional logger
 * @returns Promise that resolves to tokens
 * @internal - Internal function, not exported from package
 */
export async function pollForDeviceTokens(
  uaaUrl: string,
  clientId: string,
  clientSecret: string | undefined,
  deviceCode: string,
  interval: number = 5,
  logger?: ILogger,
): Promise<DeviceFlowTokens> {
  const tokenUrl = `${uaaUrl}/oauth/token`;

  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
  params.append('device_code', deviceCode);
  params.append('client_id', clientId);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  // Add client secret if provided (for confidential clients)
  if (clientSecret) {
    const authString = Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64',
    );
    headers.Authorization = `Basic ${authString}`;
  }

  // Poll until authorization is complete or expires
  const maxAttempts = 120; // 10 minutes max (120 * 5 seconds)
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      logger?.debug(`Polling for device tokens (attempt ${attempts + 1})`);

      const response = await axios({
        method: 'post',
        url: tokenUrl,
        headers,
        data: params.toString(),
        timeout: 30000,
      });

      if (response.data?.access_token) {
        logger?.info('Device flow authorization successful');
        return {
          accessToken: response.data.access_token,
          refreshToken: response.data.refresh_token,
          expiresIn: response.data.expires_in,
        };
      } else {
        throw new Error('Response does not contain access_token');
      }
    } catch (error: unknown) {
      // Check if it's an "authorization_pending" error (expected during polling)
      if (
        error &&
        typeof error === 'object' &&
        'response' in error &&
        error.response &&
        typeof error.response === 'object' &&
        'status' in error.response &&
        'data' in error.response
      ) {
        const axiosError = error as {
          response: { status: number; data: { error?: string } };
        };

        if (axiosError.response.data?.error === 'authorization_pending') {
          // Still waiting for user authorization - continue polling
          attempts++;
          if (attempts >= maxAttempts) {
            throw new Error(
              'Device flow authorization timeout - user did not authorize in time',
            );
          }
          // Wait for interval before next poll
          await new Promise((resolve) => setTimeout(resolve, interval * 1000));
          continue;
        } else if (axiosError.response.data?.error === 'slow_down') {
          // Server requests slower polling - increase interval by 5 seconds
          interval += 5;
          attempts++;
          if (attempts >= maxAttempts) {
            throw new Error(
              'Device flow authorization timeout - user did not authorize in time',
            );
          }
          await new Promise((resolve) => setTimeout(resolve, interval * 1000));
          continue;
        } else if (axiosError.response.data?.error === 'expired_token') {
          throw new Error('Device code expired - please restart device flow');
        } else if (axiosError.response.data?.error === 'access_denied') {
          throw new Error('User denied device authorization');
        }
      }

      // Other error - rethrow
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      throw new Error(`Device flow polling failed: ${errorMessage}`);
    }
  }

  throw new Error(
    'Device flow authorization timeout - maximum polling attempts reached',
  );
}
