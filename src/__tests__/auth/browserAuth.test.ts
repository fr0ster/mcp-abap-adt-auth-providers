/**
 * Tests for browserAuth token retrieval
 */

import { jest } from '@jest/globals';
import type { ILogger, IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { createTestLogger } from '../helpers/testLogger';
import { exchangeCodeForToken } from '../../auth/browserAuth';
import axios from 'axios';

jest.mock('axios');
jest.mock('open', () => ({
  __esModule: true,
  default: jest.fn(),
}));

const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('browserAuth token exchange', () => {
  const originalEnv = process.env;
  const authConfig: IAuthorizationConfig = {
    uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
    uaaClientId: 'test-client-id',
    uaaClientSecret: 'test-client-secret',
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('token retrieval', () => {
    it('should return access token and refresh token', async () => {
      const mockTokens = {
        access_token: 'test-access-token-123',
        refresh_token: 'test-refresh-token-456',
      };

      mockedAxios.mockResolvedValue({
        status: 200,
        data: mockTokens,
      });

      const logger: ILogger = createTestLogger('AUTH');
      const result = await exchangeCodeForToken(
        authConfig,
        'test-auth-code',
        3101,
        logger
      );

      expect(result.accessToken).toBe(mockTokens.access_token);
      expect(result.refreshToken).toBe(mockTokens.refresh_token);
      expect(mockedAxios).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'post',
          url: `${authConfig.uaaUrl}/oauth/token`,
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: expect.stringContaining('Basic'),
          }),
        })
      );
    });

    it('should return only access token when refresh token is missing', async () => {
      const mockTokens = {
        access_token: 'test-access-token-only',
      };

      mockedAxios.mockResolvedValue({
        status: 200,
        data: mockTokens,
      });

      const logger: ILogger = createTestLogger('TOKEN-ONLY');
      const result = await exchangeCodeForToken(
        authConfig,
        'test-code',
        3102,
        logger
      );

      expect(result.accessToken).toBe(mockTokens.access_token);
      expect(result.refreshToken).toBeUndefined();
    });

    it('should throw error when token exchange fails', async () => {
      mockedAxios.mockResolvedValue({
        status: 200,
        data: { error: 'invalid_grant' },
      });

      // Mock logger without console output for error test
      const logger: ILogger = {
        info: jest.fn(),
        debug: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(), // Spy but don't output to console
      };

      await expect(
        exchangeCodeForToken(authConfig, 'invalid-code', 3103, logger)
      ).rejects.toThrow('Response does not contain access_token');

      // Verify error was logged (but not to console)
      expect(logger.error).toHaveBeenCalledWith(
        'Token exchange failed: status 200, error: invalid_grant'
      );
    });

    it('should use correct Basic auth header', async () => {
      const mockTokens = {
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      };

      mockedAxios.mockResolvedValue({
        status: 200,
        data: mockTokens,
      });

      await exchangeCodeForToken(authConfig, 'auth-code', 3104, undefined);

      const axiosCall = mockedAxios.mock.calls[0]?.[0] as any;
      const expectedAuth = Buffer.from(
        `${authConfig.uaaClientId}:${authConfig.uaaClientSecret}`
      ).toString('base64');
      
      expect(axiosCall.headers.Authorization).toBe(`Basic ${expectedAuth}`);
    });
  });
});
