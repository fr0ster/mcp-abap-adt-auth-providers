/**
 * A token endpoint's error body never reaches a log line or an error message
 * whole. Only `error` and `error_description` do. A misbehaving server can put
 * tokens in an error body; they must not follow it out.
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const LEAKED_ACCESS = 'leaked-access-token-0123456789abcdef';
const LEAKED_REFRESH = 'leaked-refresh-token-fedcba9876543210';

function failWithTokensInBody(): void {
  mockedAxios.isAxiosError.mockReturnValue(true);
  // refreshJwtToken and getTokenWithClientCredentials call axios({...});
  // the SAML exchange calls axios.post. Both reject the same way.
  (mockedAxios as unknown as jest.Mock<() => Promise<never>>).mockRejectedValue(
    errorWithTokens() as never,
  );
  mockedAxios.post.mockRejectedValue(errorWithTokens() as never);
}

function errorWithTokens(): unknown {
  return {
    isAxiosError: true,
    message: 'Request failed with status code 400',
    response: {
      status: 400,
      data: {
        error: 'invalid_grant',
        error_description: 'refresh token expired',
        access_token: LEAKED_ACCESS,
        refresh_token: LEAKED_REFRESH,
      },
    },
  };
}

function recordingLogger(): { logger: ILogger; text: () => string } {
  const lines: string[] = [];
  const record = (message: string, meta?: unknown) => {
    lines.push(`${message} ${JSON.stringify(meta ?? {})}`);
  };
  return {
    logger: {
      debug: record,
      info: record,
      warn: record,
      error: record,
    } as ILogger,
    text: () => lines.join('\n'),
  };
}

async function messageOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (error) {
    return error instanceof Error
      ? error.message
      : String((error as { message?: string }).message ?? error);
  }
  throw new Error('expected a rejection');
}

const expectNoTokens = (text: string) => {
  expect(text).not.toContain(LEAKED_ACCESS);
  expect(text).not.toContain(LEAKED_REFRESH);
};

describe('OAuth error bodies stay out of logs and messages', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    failWithTokensInBody();
  });

  it('refreshJwtToken reports the error, not the body', async () => {
    const message = await messageOf(
      refreshJwtToken('rt', 'https://uaa', 'client', 'secret'),
    );
    expectNoTokens(message);
    expect(message).toContain('invalid_grant');
    expect(message).toContain('refresh token expired');
  });

  it('getTokenWithClientCredentials reports the error, not the body', async () => {
    const message = await messageOf(
      getTokenWithClientCredentials('https://uaa', 'client', 'secret'),
    );
    expectNoTokens(message);
    expect(message).toContain('invalid_grant');
  });

  it('exchangeSamlAssertion logs the error, not the body', async () => {
    const { logger, text } = recordingLogger();
    await messageOf(
      exchangeSamlAssertion(
        'assertion',
        'https://uaa/oauth/token',
        'client-id',
        'client-secret-value',
        logger,
      ),
    );
    expectNoTokens(text());
    expect(text()).toContain('invalid_grant');
  });

  it('refreshSamlBearerToken logs the error, not the body', async () => {
    const { logger, text } = recordingLogger();
    await messageOf(
      refreshSamlBearerToken(
        'rt-0123456789',
        'https://uaa/oauth/token',
        'client-id',
        'client-secret-value',
        logger,
      ),
    );
    expectNoTokens(text());
    expect(text()).toContain('invalid_grant');
  });

  // error_description is kept for diagnosis, so what it may carry is redacted:
  // any secret the request itself sent, and anything shaped like a JWT.
  describe('a secret inside error_description', () => {
    const SENT_REFRESH = 'sent-refresh-token-0123456789abcdef';
    const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl';

    const failWithDescription = (description: string) => {
      const body = {
        isAxiosError: true,
        message: 'Request failed with status code 400',
        response: {
          status: 400,
          data: { error: 'invalid_grant', error_description: description },
        },
      };
      (
        mockedAxios as unknown as jest.Mock<() => Promise<never>>
      ).mockRejectedValue(body as never);
      mockedAxios.post.mockRejectedValue(body as never);
    };

    it('redacts the refresh token the request sent, and keeps the rest', async () => {
      failWithDescription(`Invalid refresh token (expired): ${SENT_REFRESH}`);
      const message = await messageOf(
        refreshJwtToken(SENT_REFRESH, 'https://uaa', 'client', 'secret'),
      );
      expect(message).not.toContain(SENT_REFRESH);
      expect(message).toContain('Invalid refresh token (expired)');
    });

    it('redacts a JWT the server echoes', async () => {
      failWithDescription(`token ${JWT} is not acceptable`);
      const { logger, text } = recordingLogger();
      await messageOf(
        refreshSamlBearerToken(
          'rt',
          'https://uaa/oauth/token',
          'client-id',
          'client-secret-value',
          logger,
        ),
      );
      expect(text()).not.toContain(JWT);
      expect(text()).toContain('is not acceptable');
    });

    // The request sent the assertion form-urlencoded, so a server echoing its
    // body back returns %2B, %2F and %3D, not + / =. Both forms are redacted.
    it('redacts an assertion echoed back form-urlencoded', async () => {
      const assertion = 'PHNhbWw+QXNzZXJ0aW9u/Pz8+Pw==';
      const encoded = new URLSearchParams({ a: assertion }).toString().slice(2);
      expect(encoded).not.toBe(assertion);
      failWithDescription(`could not parse assertion=${encoded}`);
      const { logger, text } = recordingLogger();
      await messageOf(
        exchangeSamlAssertion(
          assertion,
          'https://uaa/oauth/token',
          'client-id',
          'client-secret-value',
          logger,
        ),
      );
      expect(text()).not.toContain(encoded);
      expect(text()).not.toContain(assertion);
      expect(text()).toContain('could not parse assertion=');
    });

    // A known secret is redacted whatever its length: nothing checks that a
    // client secret is long, and "secret" is six characters.
    it('redacts a short client secret too', async () => {
      failWithDescription('the client secret XyZ9ab is not valid for client');
      const message = await messageOf(
        getTokenWithClientCredentials('https://uaa', 'client', 'XyZ9ab'),
      );
      expect(message).not.toContain('XyZ9ab');
      expect(message).toContain('is not valid for client');
    });

    it('redacts the client secret and the assertion it sent', async () => {
      const assertion = 'PHNhbWw6QXNzZXJ0aW9uPg-assertion-payload';
      failWithDescription(`bad client secret-value-xyz for ${assertion}`);
      const { logger, text } = recordingLogger();
      await messageOf(
        exchangeSamlAssertion(
          assertion,
          'https://uaa/oauth/token',
          'c',
          'secret-value-xyz',
          logger,
        ),
      );
      expect(text()).not.toContain('secret-value-xyz');
      expect(text()).not.toContain(assertion);
      expect(text()).toContain('bad client');
    });
  });
});
