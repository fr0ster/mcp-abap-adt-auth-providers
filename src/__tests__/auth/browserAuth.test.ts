/**
 * Tests for browserAuth token retrieval
 */

import http from 'node:http';
import { jest } from '@jest/globals';
import type { IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';
import { exchangeCodeForToken, startBrowserAuth } from '../../auth/browserAuth';
import { createTestLogger } from '../helpers/testLogger';

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
        logger,
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
        }),
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
        logger,
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
        exchangeCodeForToken(authConfig, 'invalid-code', 3103, logger),
      ).rejects.toThrow('Response does not contain access_token');

      // Verify error was logged (but not to console)
      expect(logger.error).toHaveBeenCalledWith(
        'Token exchange failed: status 200, error: invalid_grant',
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
        `${authConfig.uaaClientId}:${authConfig.uaaClientSecret}`,
      ).toString('base64');

      expect(axiosCall.headers.Authorization).toBe(`Basic ${expectedAuth}`);
    });
  });
});

describe('browserAuth browser modes', () => {
  const authConfig: IAuthorizationConfig = {
    uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
    uaaClientId: 'test-client-id',
    uaaClientSecret: 'test-client-secret',
  };

  describe('none mode', () => {
    it('should reject immediately with URL in error message', async () => {
      const logger: ILogger = {
        info: jest.fn(),
        debug: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      const port = 3201;

      await expect(
        startBrowserAuth(authConfig, 'none', logger, port),
      ).rejects.toThrow('Browser authentication required');

      // Should log the URL before rejecting
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Browser authentication URL'),
        expect.any(Object),
      );
    });

    it('should include authorization URL in error message', async () => {
      const port = 3202;

      try {
        await startBrowserAuth(authConfig, 'none', undefined, port);
        fail('Should have thrown an error');
      } catch (error: unknown) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        expect(errorMessage).toContain('oauth/authorize');
        expect(errorMessage).toContain(authConfig.uaaClientId);
      }
    });
  });

  describe('headless mode', () => {
    it('should log URL and wait for callback', async () => {
      const logger: ILogger = {
        info: jest.fn(),
        debug: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      const port = 3203;
      const mockTokens = {
        access_token: 'headless-access-token',
        refresh_token: 'headless-refresh-token',
      };

      mockedAxios.mockResolvedValue({
        status: 200,
        data: mockTokens,
      });

      // Start headless auth (should not reject immediately)
      const authPromise = startBrowserAuth(
        authConfig,
        'headless',
        logger,
        port,
      );

      // Wait for server to start
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Verify headless mode logs were called
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Headless mode'),
      );
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Waiting for callback'),
      );

      // Simulate callback from browser
      const callbackUrl = `http://localhost:${port}/callback?code=test-auth-code`;

      await new Promise<void>((resolve, reject) => {
        const req = http.get(callbackUrl, (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => resolve());
        });
        req.on('error', reject);
      });

      // Wait for auth to complete
      const result = await authPromise;

      expect(result.accessToken).toBe(mockTokens.access_token);
      expect(result.refreshToken).toBe(mockTokens.refresh_token);
    });

    it('should not reject before callback is received', async () => {
      const port = 3204;

      // Start headless auth
      const authPromise = startBrowserAuth(
        authConfig,
        'headless',
        undefined,
        port,
      );

      // Wait briefly - should still be pending (not rejected)
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Check that promise is still pending by racing with a timeout
      const timeoutPromise = new Promise<string>((resolve) =>
        setTimeout(() => resolve('timeout'), 50),
      );

      const raceResult = await Promise.race([
        authPromise.then(() => 'completed').catch(() => 'rejected'),
        timeoutPromise,
      ]);

      // Should timeout because headless mode waits for callback
      expect(raceResult).toBe('timeout');

      // Clean up: simulate callback to complete and close server
      const mockTokens = { access_token: 'cleanup-token' };
      mockedAxios.mockResolvedValue({ status: 200, data: mockTokens });

      await new Promise<void>((resolve) => {
        const req = http.get(
          `http://localhost:${port}/callback?code=cleanup`,
          () => resolve(),
        );
        req.on('error', () => resolve()); // Ignore errors during cleanup
      });

      // Wait for cleanup
      await authPromise.catch(() => {});
    });
  });
});
