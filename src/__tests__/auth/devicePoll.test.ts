/**
 * The device poll reads what a poll threw through `readSafely`, like every
 * other read of a foreign error: a value whose property read throws (a
 * Proxy) does not break the poll — and, like every rejection of a token
 * request, it is replaced by a safe error in fixed words, never rethrown.
 */

import { describe, expect, it, jest } from '@jest/globals';
import axios, { AxiosError } from 'axios';
import { pollDeviceTokens } from '../../auth/oidcToken';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock };

describe('pollDeviceTokens', () => {
  it('a thrown value whose property read throws: replaced by fixed words', async () => {
    const hostile = new Proxy(
      {},
      {
        has: () => false,
        get: () => {
          throw new Error('read refused');
        },
      },
    );
    mockedAxios.post.mockImplementation(() => Promise.reject(hostile));
    // Wrapped: awaiting the bare Proxy would read its `then`.
    const outcome = await pollDeviceTokens(
      'https://idp.example/token',
      'client',
      undefined,
      'device-code',
      0,
    ).then(
      () => ({ thrown: undefined }),
      (error: unknown) => ({ thrown: error }),
    );
    expect(outcome.thrown).not.toBe(hostile);
    expect(outcome.thrown).toBeInstanceOf(AxiosError);
    expect((outcome.thrown as Error).message).toBe('the token request failed');
    expect((outcome.thrown as Error).cause).toBeUndefined();
  });
});
