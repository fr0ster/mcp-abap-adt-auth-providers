import { describe, expect, it, jest } from '@jest/globals';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import { BrowserAuthError } from '../../errors/TokenProviderErrors';
import { manualPasscodeStrategy } from '../../strategies/manualStrategies';

const request = {
  buildAuthorizationUrl: async () => 'https://uaa/passcode',
} as unknown as AuthorizationRequest;

describe('manual strategies are bounded', () => {
  it('a reader that never answers is abandoned at timeoutMs, and told so', async () => {
    let seen: AbortSignal | undefined;
    const strategy = manualPasscodeStrategy({
      timeoutMs: 20,
      read: (_prompt, signal) => {
        seen = signal;
        return new Promise<string>(() => {});
      },
    });
    await expect(strategy.authorize(request)).rejects.toBeInstanceOf(
      BrowserAuthError,
    );
    expect(seen?.aborted).toBe(true);
  });

  it('dispose() resolves only once the pending authorize has already settled', async () => {
    let settled = false;
    const strategy = manualPasscodeStrategy({
      read: () => new Promise<string>(() => {}),
    });
    const authorizing = strategy.authorize(request);
    authorizing.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    expect(settled).toBe(false);

    await strategy.dispose?.();

    expect(settled).toBe(true);
    await expect(authorizing).rejects.toBeInstanceOf(BrowserAuthError);
  });

  it('a disposed strategy refuses the next authorize', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => 'code' });
    await strategy.dispose?.();
    await expect(strategy.authorize(request)).rejects.toBeInstanceOf(
      BrowserAuthError,
    );
  });

  it('without timeoutMs there is no deadline — an answer still arrives', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => ' 123456 ' });
    await expect(strategy.authorize(request)).resolves.toMatchObject({
      payload: '123456',
    });
  });

  it('the terminal reader closes its readline when aborted', async () => {
    const close = jest.fn();
    jest.resetModules();
    jest.doMock('node:readline', () => ({
      createInterface: () => ({
        close,
        [Symbol.asyncIterator]: () => ({ next: () => new Promise(() => {}) }),
      }),
    }));
    const tty = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', {
      value: true,
      configurable: true,
    });
    const write = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    try {
      const { manualPasscodeStrategy: fresh } = await import(
        '../../strategies/manualStrategies'
      );
      const strategy = fresh({ timeoutMs: 20 });
      await expect(strategy.authorize(request)).rejects.toThrow();
      expect(close).toHaveBeenCalled();
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', {
        value: tty,
        configurable: true,
      });
      write.mockRestore();
      jest.dontMock('node:readline');
    }
  });

  it('the terminal reader given an already-aborted signal opens no readline', async () => {
    const createInterface = jest.fn(() => ({
      close: () => {},
      [Symbol.asyncIterator]: () => ({ next: () => new Promise(() => {}) }),
    }));
    jest.resetModules();
    jest.doMock('node:readline', () => ({ createInterface }));
    const tty = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', {
      value: true,
      configurable: true,
    });
    const write = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    // The deadline passes while the URL is still being built.
    let built: () => void = () => {};
    const slow = {
      buildAuthorizationUrl: () =>
        new Promise<string>((resolve) => {
          built = () => resolve('https://uaa/passcode');
        }),
    } as unknown as AuthorizationRequest;
    try {
      const { manualPasscodeStrategy: fresh } = await import(
        '../../strategies/manualStrategies'
      );
      const strategy = fresh({ timeoutMs: 10 });
      await expect(strategy.authorize(slow)).rejects.toBeInstanceOf(Error);
      built();
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(createInterface).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', {
        value: tty,
        configurable: true,
      });
      write.mockRestore();
      jest.dontMock('node:readline');
    }
  });
});
