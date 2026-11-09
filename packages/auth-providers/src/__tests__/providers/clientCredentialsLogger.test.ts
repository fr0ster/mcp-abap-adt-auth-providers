/**
 * ClientCredentialsProvider takes a logger like every other token provider, so
 * a consumer's logger sees its token lifecycle. Before 5.2.0 its config had no
 * `logger`, and the base class logged to nothing.
 */

import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../renewal';
import { notContains } from '../helpers/expectations';

const recording = () => {
  const lines: string[] = [];
  // Every argument is kept: the base class passes token details as meta.
  const at =
    (level: string) =>
    (message: string, meta?: unknown): void => {
      lines.push(`${level} ${message} ${JSON.stringify(meta ?? null)}`);
    };
  const logger: ILogger = {
    debug: mock.fn(at('debug')),
    info: mock.fn(at('info')),
    warn: mock.fn(at('warn')),
    error: mock.fn(at('error')),
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

    assert.equal(
      lines.some((l) => l.includes('[BaseTokenProvider]')),
      true,
    );
    notContains(lines.join('\n'), 'cached-token');
  });
});
