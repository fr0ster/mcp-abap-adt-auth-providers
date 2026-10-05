/**
 * The device poll reads what a poll threw through `readSafely`, like every
 * other read of a foreign error: a value whose property read throws (a
 * Proxy) is rethrown as it is, not replaced by the error its read raised.
 */

import { describe, expect, it, jest } from '@jest/globals';
import axios from 'axios';
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
  it('rethrows a thrown value whose property read throws, unchanged', async () => {
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
    expect(outcome.thrown).toBe(hostile);
  });
});
