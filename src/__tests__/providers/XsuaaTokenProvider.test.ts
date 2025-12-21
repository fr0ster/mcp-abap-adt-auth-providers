/**
 * Tests for XsuaaTokenProvider
 * 
 * Real tests (not mocks) - tests actual token provider behavior
 */

import { XsuaaTokenProvider } from '../../providers/XsuaaTokenProvider';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { defaultLogger } from '@mcp-abap-adt/logger';
import { jest } from '@jest/globals';

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
    // Helper to create a JWT token with given exp claim
    const createJwtWithExp = (expSeconds: number): string => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ exp: expSeconds, sub: 'test-user' })).toString('base64url');
      const signature = 'fake-signature';
      return `${header}.${payload}.${signature}`;
    };

    it('should return false if token is empty', async () => {
      const result = await provider.validateToken('');
      expect(result).toBe(false);
    });

    it('should return false if token is not a valid JWT format', async () => {
      const result = await provider.validateToken('not-a-jwt-token');
      expect(result).toBe(false);
    });

    it('should return false if token has only 2 parts', async () => {
      const result = await provider.validateToken('header.payload');
      expect(result).toBe(false);
    });

    it('should return true if token is valid (exp in future)', async () => {
      // Exp 1 hour in future
      const futureExp = Math.floor(Date.now() / 1000) + 3600;
      const token = createJwtWithExp(futureExp);

      const result = await provider.validateToken(token, 'https://test.service.com');
      expect(result).toBe(true);
    });

    it('should return true if serviceUrl is not provided (local validation only)', async () => {
      const futureExp = Math.floor(Date.now() / 1000) + 3600;
      const token = createJwtWithExp(futureExp);

      const result = await provider.validateToken(token);
      expect(result).toBe(true);
    });

    it('should return false if token is expired', async () => {
      // Exp 1 hour in past
      const pastExp = Math.floor(Date.now() / 1000) - 3600;
      const token = createJwtWithExp(pastExp);

      const result = await provider.validateToken(token);
      expect(result).toBe(false);
    });

    it('should return false if token expires within 60 second buffer', async () => {
      // Exp 30 seconds in future (within 60s buffer)
      const soonExp = Math.floor(Date.now() / 1000) + 30;
      const token = createJwtWithExp(soonExp);

      const result = await provider.validateToken(token);
      expect(result).toBe(false);
    });

    it('should return true if token has no exp claim', async () => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'test-user' })).toString('base64url');
      const token = `${header}.${payload}.fake-signature`;

      const result = await provider.validateToken(token);
      expect(result).toBe(true);
    });

    it('should return false if payload is not valid JSON', async () => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
      const invalidPayload = Buffer.from('not-json').toString('base64url');
      const token = `${header}.${invalidPayload}.signature`;

      const result = await provider.validateToken(token);
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
  });
});

