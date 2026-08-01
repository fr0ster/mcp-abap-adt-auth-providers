/**
 * Tests for browserAuth token retrieval
 */

import { jest } from '@jest/globals';
import type { IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';
import {
  exchangeCodeForToken,
  extractCode,
  getJwtAuthorizationUrl,
} from '../../auth/browserAuth';
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
        'http://localhost:3101/callback',
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
        'http://localhost:3102/callback',
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
        exchangeCodeForToken(
          authConfig,
          'invalid-code',
          'http://localhost:3103/callback',
          logger,
        ),
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

      await exchangeCodeForToken(
        authConfig,
        'auth-code',
        'http://localhost:3104/callback',
        undefined,
      );

      const axiosCall = mockedAxios.mock.calls[0]?.[0] as any;
      const expectedAuth = Buffer.from(
        `${authConfig.uaaClientId}:${authConfig.uaaClientSecret}`,
      ).toString('base64');

      expect(axiosCall.headers.Authorization).toBe(`Basic ${expectedAuth}`);
    });
  });
});

describe('extractCode', () => {
  it('returns a bare code as-is', () => {
    expect(extractCode('abc123')).toBe('abc123');
  });

  it('parses `code=XYZ`', () => {
    expect(extractCode('code=abc123')).toBe('abc123');
  });

  it('parses a code from a full redirected URL', () => {
    expect(
      extractCode('http://localhost:7779/callback?code=abc123&state=s'),
    ).toBe('abc123');
  });

  it('parses a code from a remote-host redirected URL', () => {
    expect(
      extractCode('http://10.0.0.5:7779/callback?state=s&code=abc%2D123'),
    ).toBe('abc-123');
  });

  it('trims surrounding whitespace', () => {
    expect(extractCode('   abc123  ')).toBe('abc123');
  });

  it('returns null for empty / whitespace-only input', () => {
    expect(extractCode('')).toBeNull();
    expect(extractCode('   ')).toBeNull();
  });

  it('returns null when the input is clearly not a single code', () => {
    expect(extractCode('hello world this is not a code')).toBeNull();
  });
});

describe('redirect URI plumbing', () => {
  it('builds the authorization URL around the URI it is given', () => {
    const url = getJwtAuthorizationUrl(
      {
        uaaUrl: 'https://uaa.example',
        uaaClientId: 'cid',
        uaaClientSecret: 's',
      },
      'http://localhost:54321/callback',
    );
    expect(url).toContain(
      `redirect_uri=${encodeURIComponent('http://localhost:54321/callback')}`,
    );
  });
});
