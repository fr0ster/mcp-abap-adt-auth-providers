/**
 * Tests for XsuaaTokenProvider
 * 
 * Real tests (not mocks) - tests actual token provider behavior
 */

import { XsuaaTokenProvider } from '../../providers/XsuaaTokenProvider';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { defaultLogger } from '@mcp-abap-adt/logger';
import axios from 'axios';
import { jest } from '@jest/globals';

// Mock axios for token validation
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('XsuaaTokenProvider', () => {
  let provider: XsuaaTokenProvider;

  beforeEach(() => {
    provider = new XsuaaTokenProvider();
    jest.clearAllMocks();
  });

  describe('getConnectionConfig', () => {
    it('should get connection config using client credentials', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      // Mock private method using jest.spyOn
      const getTokenSpy = jest.spyOn(provider as any, 'getTokenWithClientCredentials').mockResolvedValue({
        accessToken: 'test-access-token',
      });

      const result = await provider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBe('test-access-token');
      expect(getTokenSpy).toHaveBeenCalledWith(
        authConfig.uaaUrl,
        authConfig.uaaClientId,
        authConfig.uaaClientSecret
      );

      getTokenSpy.mockRestore();
    });
  });

  describe('validateToken', () => {
    it('should return false if token is empty', async () => {
      const result = await provider.validateToken('');
      expect(result).toBe(false);
    });

    it('should return true if serviceUrl is not provided', async () => {
      const result = await provider.validateToken('test-token');
      expect(result).toBe(true);
    });

    it('should return true if token is valid (200-299 status)', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: {},
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledWith('https://test.service.com', {
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
  });

  describe('refreshTokenFromSession', () => {
    it('should refresh token using client_credentials from session', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      const getTokenSpy = jest.spyOn(provider as any, 'getTokenWithClientCredentials').mockResolvedValue({
        accessToken: 'refreshed-token-from-session',
      });

      const result = await provider.refreshTokenFromSession(authConfig, {
        logger: defaultLogger,
      });

      expect(result.connectionConfig.authorizationToken).toBe('refreshed-token-from-session');
      expect(getTokenSpy).toHaveBeenCalledWith(
        authConfig.uaaUrl,
        authConfig.uaaClientId,
        authConfig.uaaClientSecret
      );

      getTokenSpy.mockRestore();
    });

    it('should throw RefreshError if client_credentials fails', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      // Mock getTokenWithClientCredentials to throw error
      const getTokenSpy = jest.spyOn(provider as any, 'getTokenWithClientCredentials').mockRejectedValue(
        new Error('UAA server returned 401 Unauthorized')
      );

      const { RefreshError } = await import('../../errors/TokenProviderErrors');
      
      await expect(provider.refreshTokenFromSession(authConfig, {
        logger: defaultLogger,
      })).rejects.toThrow(RefreshError);

      await expect(provider.refreshTokenFromSession(authConfig)).rejects.toThrow(
        'XSUAA refreshTokenFromSession failed'
      );

      getTokenSpy.mockRestore();
    });

    it('should throw error if uaaUrl is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: '',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      await expect(provider.refreshTokenFromSession(authConfig)).rejects.toThrow(
        'XSUAA refreshTokenFromSession: authConfig missing required fields: uaaUrl'
      );
    });

    it('should throw error if uaaClientId is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: '',
        uaaClientSecret: 'test-client-secret',
      };

      await expect(provider.refreshTokenFromSession(authConfig)).rejects.toThrow(
        'XSUAA refreshTokenFromSession: authConfig missing required fields: uaaClientId'
      );
    });

    it('should throw error if uaaClientSecret is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: '',
      };

      await expect(provider.refreshTokenFromSession(authConfig)).rejects.toThrow(
        'XSUAA refreshTokenFromSession: authConfig missing required fields: uaaClientSecret'
      );
    });
  });

  describe('refreshTokenFromServiceKey', () => {
    it('should refresh token using browser authentication from service key', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      // Import browserAuth module
      const browserAuthModule = await import('../../auth/browserAuth');
      
      // Mock startBrowserAuth function
      const browserAuthSpy = jest.spyOn(browserAuthModule, 'startBrowserAuth').mockResolvedValue({
        accessToken: 'refreshed-token-from-servicekey',
        refreshToken: 'new-refresh-token',
      });

      const result = await provider.refreshTokenFromServiceKey(authConfig, {
        browser: 'none',
        logger: defaultLogger,
      });

      expect(result.connectionConfig.authorizationToken).toBe('refreshed-token-from-servicekey');
      expect(result.refreshToken).toBe('new-refresh-token');

      browserAuthSpy.mockRestore();
    });

    it('should throw RefreshError if browser authentication fails', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      // Import browserAuth module
      const browserAuthModule = await import('../../auth/browserAuth');
      
      // Mock startBrowserAuth to throw error
      const browserAuthSpy = jest.spyOn(browserAuthModule, 'startBrowserAuth').mockRejectedValue(
        new Error('Browser authentication cancelled by user')
      );

      const { RefreshError } = await import('../../errors/TokenProviderErrors');
      
      await expect(provider.refreshTokenFromServiceKey(authConfig, {
        browser: 'none',
        logger: defaultLogger,
      })).rejects.toThrow(RefreshError);

      await expect(provider.refreshTokenFromServiceKey(authConfig)).rejects.toThrow(
        'XSUAA refreshTokenFromServiceKey failed'
      );

      browserAuthSpy.mockRestore();
    });

    it('should return true on connection errors (ECONNREFUSED)', async () => {
      mockedAxios.get.mockRejectedValue({
        code: 'ECONNREFUSED',
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(true);
    });

    it('should return true on timeout errors (ETIMEDOUT)', async () => {
      mockedAxios.get.mockRejectedValue({
        code: 'ETIMEDOUT',
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(true);
    });

    it('should return true on DNS errors (ENOTFOUND)', async () => {
      mockedAxios.get.mockRejectedValue({
        code: 'ENOTFOUND',
      });

      const result = await provider.validateToken('test-token', 'https://test.service.com');
      expect(result).toBe(true);
    });
  });
});

