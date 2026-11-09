/**
 * Tests for browserAuth token retrieval
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  exchangeCodeForToken,
  extractCode,
  getJwtAuthorizationUrl,
} from '../../auth/browserAuth';
import { clearAxiosMockCalls, mockedAxios } from '../helpers/axiosModuleMock';
import {
  calledWith,
  contains,
  objectContaining,
  stringContaining,
  thrown,
} from '../helpers/expectations';
import { createTestLogger } from '../helpers/testLogger';

// Automocked, but with axios's own error class: the sites throw it.

describe('browserAuth token exchange', () => {
  const originalEnv = process.env;
  const authConfig: IAuthorizationConfig = {
    uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
    uaaClientId: 'test-client-id',
    uaaClientSecret: 'test-client-secret',
  };

  beforeEach(() => {
    clearAxiosMockCalls();
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

      mockedAxios.mock.mockImplementation(async () => ({
        status: 200,
        data: mockTokens,
      }));

      const logger: ILogger = createTestLogger('AUTH');
      const result = await exchangeCodeForToken(
        authConfig,
        'test-auth-code',
        'http://localhost:3101/callback',
        logger,
      );

      assert.equal(result.accessToken, mockTokens.access_token);
      assert.equal(result.refreshToken, mockTokens.refresh_token);
      calledWith(
        mockedAxios,
        objectContaining({
          method: 'post',
          url: `${authConfig.uaaUrl}/oauth/token`,
          headers: objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: stringContaining('Basic'),
          }),
        }),
      );
    });

    it('should return only access token when refresh token is missing', async () => {
      const mockTokens = {
        access_token: 'test-access-token-only',
      };

      mockedAxios.mock.mockImplementation(async () => ({
        status: 200,
        data: mockTokens,
      }));

      const logger: ILogger = createTestLogger('TOKEN-ONLY');
      const result = await exchangeCodeForToken(
        authConfig,
        'test-code',
        'http://localhost:3102/callback',
        logger,
      );

      assert.equal(result.accessToken, mockTokens.access_token);
      assert.equal(result.refreshToken, undefined);
    });

    it('should throw error when token exchange fails', async () => {
      mockedAxios.mock.mockImplementation(async () => ({
        status: 200,
        data: { error: 'invalid_grant' },
      }));

      // Mock logger without console output for error test
      const error = mock.fn<ILogger['error']>(); // Spy but don't output to console
      const logger: ILogger = {
        info: mock.fn(),
        debug: mock.fn(),
        warn: mock.fn(),
        error,
      };

      await assert.rejects(
        exchangeCodeForToken(
          authConfig,
          'invalid-code',
          'http://localhost:3103/callback',
          logger,
        ),
        thrown('the code exchange returned no access_token'),
      );

      // Verify error was logged (but not to console)
      calledWith(
        error,
        'Token exchange failed: status 200, error: "invalid_grant"',
      );
    });

    it('should use correct Basic auth header', async () => {
      const mockTokens = {
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      };

      mockedAxios.mock.mockImplementation(async () => ({
        status: 200,
        data: mockTokens,
      }));

      await exchangeCodeForToken(
        authConfig,
        'auth-code',
        'http://localhost:3104/callback',
        undefined,
      );

      const axiosCall = mockedAxios.mock.calls.map(
        (call) => call.arguments,
      )[0]?.[0] as any;
      const expectedAuth = Buffer.from(
        `${authConfig.uaaClientId}:${authConfig.uaaClientSecret}`,
      ).toString('base64');

      assert.equal(axiosCall.headers.Authorization, `Basic ${expectedAuth}`);
    });
  });
});

describe('extractCode', () => {
  it('returns a bare code as-is', () => {
    assert.equal(extractCode('abc123'), 'abc123');
  });

  it('parses `code=XYZ`', () => {
    assert.equal(extractCode('code=abc123'), 'abc123');
  });

  it('parses a code from a full redirected URL', () => {
    assert.equal(
      extractCode('http://localhost:7779/callback?code=abc123&state=s'),
      'abc123',
    );
  });

  it('parses a code from a remote-host redirected URL', () => {
    assert.equal(
      extractCode('http://10.0.0.5:7779/callback?state=s&code=abc%2D123'),
      'abc-123',
    );
  });

  it('trims surrounding whitespace', () => {
    assert.equal(extractCode('   abc123  '), 'abc123');
  });

  it('returns null for empty / whitespace-only input', () => {
    assert.equal(extractCode(''), null);
    assert.equal(extractCode('   '), null);
  });

  it('returns null when the input is clearly not a single code', () => {
    assert.equal(extractCode('hello world this is not a code'), null);
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
    contains(
      url,
      `redirect_uri=${encodeURIComponent('http://localhost:54321/callback')}`,
    );
  });
});
