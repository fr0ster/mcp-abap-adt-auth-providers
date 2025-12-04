/**
 * Tests for BtpTokenProvider
 * 
 * Real tests (not mocks) - tests actual token provider behavior
 */

import { BtpTokenProvider } from '../../providers/BtpTokenProvider';
import type { IAuthorizationConfig } from '@mcp-abap-adt/auth-broker';
import { defaultLogger } from '@mcp-abap-adt/logger';
import axios from 'axios';
import { jest } from '@jest/globals';

// Mock axios for token validation
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock tokenRefresher and browserAuth
jest.mock('../../auth/tokenRefresher', () => ({
  refreshJwtToken: jest.fn(),
}));

jest.mock('../../auth/browserAuth', () => ({
  startBrowserAuth: jest.fn(),
}));

describe('BtpTokenProvider', () => {
  let provider: BtpTokenProvider;
  const mockRefreshJwtToken = require('../../auth/tokenRefresher').refreshJwtToken;
  const mockStartBrowserAuth = require('../../auth/browserAuth').startBrowserAuth;

  beforeEach(() => {
    provider = new BtpTokenProvider();
    jest.clearAllMocks();
  });

  describe('getConnectionConfig', () => {
    it('should use refresh token if available', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
        refreshToken: 'test-refresh-token',
      };

      mockRefreshJwtToken.mockResolvedValue({
        accessToken: 'test-access-token',
        refreshToken: 'new-refresh-token',
      });

      const result = await provider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBe('test-access-token');
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(mockRefreshJwtToken).toHaveBeenCalledWith(
        authConfig.refreshToken,
        authConfig.uaaUrl,
        authConfig.uaaClientId,
        authConfig.uaaClientSecret
      );
    });

    it('should start browser auth if no refresh token', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      mockStartBrowserAuth.mockResolvedValue({
        accessToken: 'test-access-token',
        refreshToken: 'new-refresh-token',
      });

      const result = await provider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
        browser: 'system',
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBe('test-access-token');
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(mockStartBrowserAuth).toHaveBeenCalledWith(
        authConfig,
        'system',
        defaultLogger
      );
    });
  });

  describe('validateToken', () => {
    it('should return false if token is empty', async () => {
      const result = await provider.validateToken('');
      expect(result).toBe(false);
    });

    it('should return false if serviceUrl is not provided', async () => {
      const result = await provider.validateToken('test-token');
      expect(result).toBe(false);
    });

    it('should return true if token is valid (200-299 status)', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: {},
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledWith('https://test.service.com/sap/bc/adt/discovery', {
        headers: {
          Authorization: 'Bearer test-token',
        },
        timeout: 5000,
        validateStatus: expect.any(Function),
      });
    });

    it('should return false if token is invalid (401 status)', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 401,
        data: {},
      });

      const result = await provider.validateToken('invalid-token', 'https://test.service.com');
      expect(result).toBe(false);
    });

    it('should return false if token is invalid (403 status)', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 403,
        data: {},
      });

      const result = await provider.validateToken('invalid-token', 'https://test.service.com');
      expect(result).toBe(false);
    });

    it('should return false on connection errors (ECONNREFUSED)', async () => {
      mockedAxios.get.mockRejectedValue({
        code: 'ECONNREFUSED',
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(false);
    });

    it('should return false on timeout errors (ETIMEDOUT)', async () => {
      mockedAxios.get.mockRejectedValue({
        code: 'ETIMEDOUT',
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(false);
    });

    it('should return false on DNS errors (ENOTFOUND)', async () => {
      mockedAxios.get.mockRejectedValue({
        code: 'ENOTFOUND',
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(false);
    });
  });
});

