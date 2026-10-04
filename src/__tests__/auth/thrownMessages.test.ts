/**
 * A thrown error's message carries no foreign text. A failure a consumer
 * catches from getTokens(), refreshTokens() or a strategy is logged by
 * whoever catches it — the broker, a server — by its message. What a
 * collaborator or the network threw may hold a key, a passphrase or a token,
 * so the message is fixed words (the refusal's, `loggedError`); the original
 * is the `cause`, which a consumer reads only by choice.
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import axios from 'axios';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import { BrowserAuthError } from '../../errors/TokenProviderErrors';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { BrowserCallbackStrategy } from '../../strategies';

jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock;

const MARKER = 'REVIEW_TEST_PRIVATE_KEY_a41c07';

/** Thrown, with the message and String() of what was thrown. */
async function thrownBy(run: () => Promise<unknown>) {
  try {
    await run();
  } catch (error) {
    const e = error as Error & { cause?: unknown };
    return { error: e, text: `${e.message}\n${String(e)}` };
  }
  throw new Error('nothing was thrown');
}

describe('a thrown error carries no foreign message', () => {
  let original: Error;
  beforeEach(() => {
    jest.resetAllMocks();
    original = Object.assign(new Error(MARKER), { code: 'ECONNREFUSED' });
    mockedAxios.mockRejectedValue(original);
  });

  it.each([
    [
      'client credentials',
      () => getTokenWithClientCredentials('https://uaa', 'cid', 'secret'),
      'Client credentials authentication failed',
    ],
    [
      'UAA refresh',
      () => refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
      'Token refresh failed',
    ],
  ])('%s: fixed words, the original as cause', async (_name, run, words) => {
    const { error, text } = await thrownBy(run);
    expect(text).toContain(words);
    // The allowlisted code still says what happened.
    expect(text).toContain('ECONNREFUSED');
    expect(text).not.toContain(MARKER);
    expect(error.cause).toBe(original);
  });

  it('through a provider: getTokens() throws no window of it', async () => {
    const provider = new ClientCredentialsProvider({
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientSecret: 'secret',
    });
    const { text } = await thrownBy(() => provider.getTokens());
    expect(text).not.toContain(MARKER);
  });

  it('BrowserCallbackStrategy: a BrowserAuthError in fixed words, the original as cause', async () => {
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: async () => {
        throw original;
      },
      openUrl: async () => undefined,
    });
    const { error, text } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a',
      }),
    );
    expect(error).toBeInstanceOf(BrowserAuthError);
    expect(text).toContain('ECONNREFUSED');
    expect(text).not.toContain(MARKER);
    expect(error.cause).toBe(original);
  });
});
