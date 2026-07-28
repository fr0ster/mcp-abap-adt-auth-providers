/**
 * Tests for browserAuth token retrieval
 */

import http from 'node:http';
import netModule from 'node:net';
import { jest } from '@jest/globals';
import type { IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';
import {
  exchangeCodeForToken,
  extractCode,
  startBrowserAuth,
} from '../../auth/browserAuth';
import { canListenOnLocalhost, getAvailablePort } from '../helpers/netHelpers';
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
    it('should log URL and wait for callback (same as headless)', async () => {
      if (!(await canListenOnLocalhost())) {
        console.warn('⚠️  Skipping browserAuth test - cannot bind to localhost');
        return;
      }
      const logger: ILogger = {
        info: jest.fn(),
        debug: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      const port = await getAvailablePort();
      const mockTokens = {
        access_token: 'none-mode-access-token',
        refresh_token: 'none-mode-refresh-token',
      };

      mockedAxios.mockResolvedValue({
        status: 200,
        data: mockTokens,
      });

      // Start auth with 'none' mode - should not reject immediately
      const authPromise = startBrowserAuth(authConfig, 'none', logger, port);

      // Wait for server to start
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Verify URL was logged
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Open this URL'),
      );

      // Simulate callback from browser
      await new Promise<void>((resolve, reject) => {
        const req = http.get(
          `http://localhost:${port}/callback?code=test-auth-code`,
          (res) => {
            res.on('data', () => {});
            res.on('end', () => resolve());
          },
        );
        req.on('error', reject);
      });

      // Wait for auth to complete
      const result = await authPromise;
      expect(result.accessToken).toBe(mockTokens.access_token);
    });

    it('should include authorization URL in log message', async () => {
      if (!(await canListenOnLocalhost())) {
        console.warn('⚠️  Skipping browserAuth test - cannot bind to localhost');
        return;
      }
      const logger: ILogger = {
        info: jest.fn(),
        debug: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      const port = await getAvailablePort();
      const mockTokens = { access_token: 'test-token' };

      mockedAxios.mockResolvedValue({
        status: 200,
        data: mockTokens,
      });

      const authPromise = startBrowserAuth(authConfig, 'none', logger, port);

      // Wait for server to start
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Verify URL contains oauth/authorize and clientId
      const infoCalls = (logger.info as jest.Mock).mock.calls;
      const urlLogCall = infoCalls.find(
        (call: unknown[]) =>
          typeof call[0] === 'string' && call[0].includes('oauth/authorize'),
      );
      expect(urlLogCall).toBeDefined();
      if (urlLogCall) {
        expect(urlLogCall[0]).toContain(authConfig.uaaClientId);
      }

      // Cleanup: simulate callback
      await new Promise<void>((resolve) => {
        const req = http.get(
          `http://localhost:${port}/callback?code=cleanup`,
          () => resolve(),
        );
        req.on('error', () => resolve());
      });

      await authPromise.catch(() => {});
    });
  });

  describe('headless mode', () => {
    it('should log URL and wait for callback', async () => {
      if (!(await canListenOnLocalhost())) {
        console.warn('⚠️  Skipping browserAuth test - cannot bind to localhost');
        return;
      }
      const logger: ILogger = {
        info: jest.fn(),
        debug: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      const port = await getAvailablePort();
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

      // Verify URL and waiting message were logged
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Open this URL'),
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
      if (!(await canListenOnLocalhost())) {
        console.warn('⚠️  Skipping browserAuth test - cannot bind to localhost');
        return;
      }
      const port = await getAvailablePort();

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

describe('browserAuth manual paste (none mode)', () => {
  const authConfig: IAuthorizationConfig = {
    uaaUrl: 'https://test.authentication.sap.hana.ondemand.com',
    uaaClientId: 'test-client-id',
    uaaClientSecret: 'test-client-secret',
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  const httpGet = (url: string): Promise<{ status: number; body: string }> =>
    new Promise((resolve, reject) => {
      const req = http.get(url, (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      });
      req.on('error', reject);
    });

  it('serves a paste form at GET /', async () => {
    if (!(await canListenOnLocalhost())) return;
    const logger: ILogger = createTestLogger('AUTH');
    const port = await getAvailablePort();

    const authPromise = startBrowserAuth(authConfig, 'none', logger, port);
    await new Promise((r) => setTimeout(r, 100));

    const { status, body } = await httpGet(`http://localhost:${port}/`);
    expect(status).toBe(200);
    expect(body).toContain('<form');
    expect(body).toContain('/submit');

    // Cleanup via callback
    mockedAxios.mockResolvedValue({
      status: 200,
      data: { access_token: 'cleanup' },
    });
    await httpGet(`http://localhost:${port}/callback?code=cleanup`).catch(
      () => {},
    );
    await authPromise.catch(() => {});
  });

  it('completes the flow when a code is pasted via GET /submit', async () => {
    if (!(await canListenOnLocalhost())) return;
    const logger: ILogger = createTestLogger('AUTH');
    const port = await getAvailablePort();

    mockedAxios.mockResolvedValue({
      status: 200,
      data: { access_token: 'pasted-token', refresh_token: 'pasted-refresh' },
    });

    const authPromise = startBrowserAuth(authConfig, 'none', logger, port);
    await new Promise((r) => setTimeout(r, 100));

    // Paste a full redirected URL; the code should be extracted and exchanged.
    await httpGet(
      `http://localhost:${port}/submit?input=${encodeURIComponent(
        `http://localhost:${port}/callback?code=pasted-code`,
      )}`,
    );

    const result = await authPromise;
    expect(result.accessToken).toBe('pasted-token');
    expect(result.refreshToken).toBe('pasted-refresh');
  });

  it('re-renders the form (HTTP 400) on an unusable paste, without ending the flow', async () => {
    if (!(await canListenOnLocalhost())) return;
    const logger: ILogger = createTestLogger('AUTH');
    const port = await getAvailablePort();

    const authPromise = startBrowserAuth(authConfig, 'none', logger, port);
    await new Promise((r) => setTimeout(r, 100));

    const { status, body } = await httpGet(
      `http://localhost:${port}/submit?input=${encodeURIComponent('not a code')}`,
    );
    expect(status).toBe(400);
    expect(body).toContain('<form');

    // Flow is still pending — finish it via callback.
    mockedAxios.mockResolvedValue({
      status: 200,
      data: { access_token: 'cleanup' },
    });
    await httpGet(`http://localhost:${port}/callback?code=cleanup`).catch(
      () => {},
    );
    await authPromise.catch(() => {});
  });

  it('prints the authorization URL to stderr even without a logger', async () => {
    if (!(await canListenOnLocalhost())) return;
    const port = await getAvailablePort();

    const writes: string[] = [];
    const spy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        writes.push(String(chunk));
        return true;
      });

    // No logger passed — the URL must still be announced via stderr.
    const authPromise = startBrowserAuth(authConfig, 'none', undefined, port);
    await new Promise((r) => setTimeout(r, 100));

    spy.mockRestore();
    const all = writes.join('');
    expect(all).toContain('Open this URL');
    expect(all).toContain('oauth/authorize');

    // Cleanup
    mockedAxios.mockResolvedValue({
      status: 200,
      data: { access_token: 'cleanup' },
    });
    await httpGet(`http://localhost:${port}/callback?code=cleanup`).catch(
      () => {},
    );
    await authPromise.catch(() => {});
  });
});

/**
 * The defect from issue #11, at the level of the public function: a callback
 * carrying neither `code` nor `error` used to reject through a path that never
 * closed the socket, so the port stayed bound for the life of the process.
 */
describe('startBrowserAuth port lifetime', () => {
  const PORT = 7872;

  function portIsFree(port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const s = netModule.createServer();
      s.once('error', () => resolve(false));
      s.listen(port, () => s.close(() => resolve(true)));
    });
  }

  function get(path: string): Promise<void> {
    return new Promise((resolve) => {
      const req = http.get(
        { host: '127.0.0.1', port: PORT, path, agent: false },
        (res) => {
          res.resume();
          res.on('end', () => resolve());
        },
      );
      req.on('error', () => resolve());
    });
  }

  it('releases the port when a callback carries no code', async () => {
    const authConfig = {
      uaaUrl: 'http://127.0.0.1:9',
      uaaClientId: 'client',
      uaaClientSecret: 'secret',
    };
    const login = startBrowserAuth(authConfig, 'none', undefined, PORT);
    // Attach the expectation before delivering: the rejection lands as soon as
    // the callback arrives, and an unattached promise would be reported as an
    // unhandled rejection instead of a passing assertion.
    const rejected = expect(login).rejects.toThrow(/code missing/i);
    await new Promise((r) => setTimeout(r, 300));
    await get('/callback');
    await rejected;
    // No sleep: a settled promise must mean a free port.
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);
});
