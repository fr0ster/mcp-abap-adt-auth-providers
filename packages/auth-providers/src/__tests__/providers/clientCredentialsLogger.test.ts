/**
 * ClientCredentialsProvider takes a logger like every other token provider, so
 * a consumer's logger sees its token lifecycle. Before 5.2.0 its config had no
 * `logger`, and the base class logged to nothing.
 */

import { describe, expect, it, jest } from '@jest/globals';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../renewal';

const recording = () => {
  const lines: string[] = [];
  // Every argument is kept: the base class passes token details as meta.
  const at =
    (level: string) =>
    (message: string, meta?: unknown): void => {
      lines.push(`${level} ${message} ${JSON.stringify(meta ?? null)}`);
    };
  const logger: ILogger = {
    debug: jest.fn(at('debug')),
    info: jest.fn(at('info')),
    warn: jest.fn(at('warn')),
    error: jest.fn(at('error')),
  };
  return { logger, lines };
};

describe('ClientCredentialsProvider logger', () => {
  it('logs its token lifecycle to the logger it is given', async () => {
    const { logger, lines } = recording();
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      logger,
    });
    // A cached, valid token: getTokens answers it without a request and says so.
    const internals = provider as unknown as {
      authorizationToken?: string;
      expiresAt?: number;
    };
    internals.authorizationToken = 'cached-token';
    internals.expiresAt = Date.now() + 3600_000;

    await provider.getTokens();

    expect(lines.some((l) => l.includes('[BaseTokenProvider]'))).toBe(true);
    expect(lines.join('\n')).not.toContain('cached-token');
  });
});
