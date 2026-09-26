/**
 * No token reaches a log line, not even in part. formatToken used to return a
 * token of 50 characters or fewer whole, and a longer one's first and last 25
 * characters. A UAA refresh token is about 34 characters, so it was logged
 * outright.
 */

import { describe, expect, it } from '@jest/globals';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { staticCodeStrategy } from '../../strategies';

const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');

/** An unexpired JWT, so getTokens returns it from cache without a request. */
const ACCESS_TOKEN = `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
  exp: Math.floor(Date.now() / 1000) + 3600,
  sub: 'user',
})}.signaturepartthatislongenoughtomatter`;
/** Shaped like a UAA refresh token: opaque, 34 characters. */
const REFRESH_TOKEN = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-r';

function recordingLogger(): { logger: ILogger; lines: string[] } {
  const lines: string[] = [];
  const record = (level: string) => (message: string, meta?: unknown) => {
    lines.push(`${level} ${message} ${JSON.stringify(meta ?? {})}`);
  };
  return {
    logger: {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    } as ILogger,
    lines,
  };
}

/** Every 8-character window of a secret, so a partial leak is caught too. */
const windows = (secret: string) =>
  Array.from({ length: secret.length - 7 }, (_, i) => secret.slice(i, i + 8));

describe('no token in the logs', () => {
  it('logs neither the access token nor the refresh token, in whole or in part', async () => {
    const { logger, lines } = recordingLogger();
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      accessToken: ACCESS_TOKEN,
      refreshToken: REFRESH_TOKEN,
      authorization: staticCodeStrategy({ payload: 'unused' }),
      logger,
    });
    await provider.getTokens();

    expect(lines.length).toBeGreaterThan(0);
    const all = lines.join('\n');
    for (const secret of [ACCESS_TOKEN, REFRESH_TOKEN]) {
      for (const window of windows(secret)) {
        expect(all).not.toContain(window);
      }
    }
    // What is logged instead says a token was there, and how long it was.
    expect(all).toContain(`<redacted, ${REFRESH_TOKEN.length} chars>`);
  });
});
