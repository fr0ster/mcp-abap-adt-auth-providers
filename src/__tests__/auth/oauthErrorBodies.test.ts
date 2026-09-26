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
        'c',
        's',
        logger,
      ),
    );
    expectNoTokens(text());
    expect(text()).toContain('invalid_grant');
  });

  it('refreshSamlBearerToken logs the error, not the body', async () => {
    const { logger, text } = recordingLogger();
    await messageOf(
      refreshSamlBearerToken('rt', 'https://uaa/oauth/token', 'c', 's', logger),
    );
    expectNoTokens(text());
    expect(text()).toContain('invalid_grant');
  });
});
