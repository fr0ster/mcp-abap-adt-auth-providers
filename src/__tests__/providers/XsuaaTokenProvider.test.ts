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

// Mock clientCredentialsAuth
jest.mock('../../auth/clientCredentialsAuth', () => ({
  getTokenWithClientCredentials: jest.fn(),
}));

describe('XsuaaTokenProvider', () => {
  let provider: XsuaaTokenProvider;
  const mockGetTokenWithClientCredentials = require('../../auth/clientCredentialsAuth').getTokenWithClientCredentials;

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

      mockGetTokenWithClientCredentials.mockResolvedValue({
        accessToken: 'test-access-token',
      });

      const result = await provider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBe('test-access-token');
      expect(mockGetTokenWithClientCredentials).toHaveBeenCalledWith(
        authConfig.uaaUrl,
        authConfig.uaaClientId,
        authConfig.uaaClientSecret
      );
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

