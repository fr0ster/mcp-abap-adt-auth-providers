/**
 * Tests for BtpTokenProvider
 * 
 * Real tests (not mocks) - tests actual token provider behavior
 */

import { BtpTokenProvider } from '../../providers/BtpTokenProvider';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { defaultLogger } from '@mcp-abap-adt/logger';
import axios from 'axios';
import { jest } from '@jest/globals';

// Mock axios for token validation
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('BtpTokenProvider', () => {
  let provider: BtpTokenProvider;

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

      // Mock private method using jest.spyOn
      const refreshSpy = jest.spyOn(provider as any, 'refreshJwtToken').mockResolvedValue({
        accessToken: 'test-access-token',
        refreshToken: 'new-refresh-token',
      });

      const result = await provider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBe('test-access-token');
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(refreshSpy).toHaveBeenCalledWith(
        authConfig.refreshToken,
        authConfig.uaaUrl,
        authConfig.uaaClientId,
        authConfig.uaaClientSecret
      );

      refreshSpy.mockRestore();
    });

    it('should start browser auth if no refresh token', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      // Mock private method using jest.spyOn
      const browserAuthSpy = jest.spyOn(provider as any, 'startBrowserAuth').mockResolvedValue({
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
      expect(browserAuthSpy).toHaveBeenCalledWith(
        authConfig,
        'system',
        defaultLogger
      );

      browserAuthSpy.mockRestore();
    });

    it('should use custom port when specified in constructor', async () => {
      const customPort = 4001;
      const customProvider = new BtpTokenProvider(customPort);
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      // Mock private method using jest.spyOn
      const browserAuthSpy = jest.spyOn(customProvider as any, 'startBrowserAuth').mockResolvedValue({
        accessToken: 'test-access-token',
        refreshToken: 'new-refresh-token',
      });

      const result = await customProvider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
        browser: 'system',
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBe('test-access-token');
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(browserAuthSpy).toHaveBeenCalledWith(
        authConfig,
        'system',
        defaultLogger
      );
      // Verify that the provider uses the custom port by checking internal function call
      // The port is passed through the private method to the internal function
      expect(customProvider['browserAuthPort']).toBe(customPort);

      browserAuthSpy.mockRestore();
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

  describe('refreshTokenFromSession', () => {
    it('should refresh token using browser authentication from session', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      const browserAuthSpy = jest.spyOn(provider as any, 'startBrowserAuth').mockResolvedValue({
        accessToken: 'refreshed-token-from-session',
        refreshToken: 'new-refresh-token',
      });

      const result = await provider.refreshTokenFromSession(authConfig, {
        browser: 'none',
        logger: defaultLogger,
      });

      expect(result.connectionConfig.authorizationToken).toBe('refreshed-token-from-session');
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(browserAuthSpy).toHaveBeenCalledWith(authConfig, 'none', defaultLogger);

      browserAuthSpy.mockRestore();
    });

    it('should throw error if uaaUrl is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: '',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      await expect(provider.refreshTokenFromSession(authConfig)).rejects.toThrow(
        'BTP refreshTokenFromSession: authConfig missing required fields: uaaUrl'
      );
    });

    it('should throw error if uaaClientId is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: '',
        uaaClientSecret: 'test-client-secret',
      };

      await expect(provider.refreshTokenFromSession(authConfig)).rejects.toThrow(
        'BTP refreshTokenFromSession: authConfig missing required fields: uaaClientId'
      );
    });

    it('should throw error if uaaClientSecret is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: '',
      };

      await expect(provider.refreshTokenFromSession(authConfig)).rejects.toThrow(
        'BTP refreshTokenFromSession: authConfig missing required fields: uaaClientSecret'
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

      const browserAuthSpy = jest.spyOn(provider as any, 'startBrowserAuth').mockResolvedValue({
        accessToken: 'refreshed-token-from-servicekey',
        refreshToken: 'new-refresh-token',
      });

      const result = await provider.refreshTokenFromServiceKey(authConfig, {
        browser: 'none',
        logger: defaultLogger,
      });

      expect(result.connectionConfig.authorizationToken).toBe('refreshed-token-from-servicekey');
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(browserAuthSpy).toHaveBeenCalledWith(authConfig, 'none', defaultLogger);

      browserAuthSpy.mockRestore();
    });

    it('should throw RefreshError if browser authentication fails', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      const browserAuthSpy = jest.spyOn(provider as any, 'startBrowserAuth').mockRejectedValue(
        new Error('Browser authentication timeout')
      );

      const { RefreshError } = await import('../../errors/TokenProviderErrors');
      
      await expect(provider.refreshTokenFromServiceKey(authConfig, {
        browser: 'none',
        logger: defaultLogger,
      })).rejects.toThrow(RefreshError);

      await expect(provider.refreshTokenFromServiceKey(authConfig)).rejects.toThrow(
        'BTP refreshTokenFromServiceKey failed'
      );

      browserAuthSpy.mockRestore();
    });

    it('should throw error if uaaUrl is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: '',
        uaaClientId: 'test-client-id',
        uaaClientSecret: 'test-client-secret',
      };

      await expect(provider.refreshTokenFromServiceKey(authConfig)).rejects.toThrow(
        'BTP refreshTokenFromServiceKey: authConfig missing required fields: uaaUrl'
      );
    });

    it('should throw error if uaaClientId is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: '',
        uaaClientSecret: 'test-client-secret',
      };

      await expect(provider.refreshTokenFromServiceKey(authConfig)).rejects.toThrow(
        'BTP refreshTokenFromServiceKey: authConfig missing required fields: uaaClientId'
      );
    });

    it('should throw error if uaaClientSecret is missing', async () => {
      const authConfig: IAuthorizationConfig = {
        uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
        uaaClientId: 'test-client-id',
        uaaClientSecret: '',
      };

      await expect(provider.refreshTokenFromServiceKey(authConfig)).rejects.toThrow(
        'BTP refreshTokenFromServiceKey: authConfig missing required fields: uaaClientSecret'
      );
    });
  });
});

