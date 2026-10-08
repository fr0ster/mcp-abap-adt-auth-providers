import { describe, expect, it, jest } from '@jest/globals';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { manualPasscodeStrategy } from '../../strategies';

// As a provider hands it over: `logger: undefined` present when there is none.
const request = (logger?: ILogger) =>
  ({
    logger,
    buildAuthorizationUrl: async () => 'https://uaa.example/passcode',
  }) as AuthorizationRequest;

describe('manualPasscodeStrategy', () => {
  it('shows where to get the code and returns what the user pastes, trimmed', async () => {
    const info = jest.fn();
    const logger = {
      info,
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    };
    const read = jest.fn(async (_prompt: string) => '  abc123  ');
    const written: string[] = [];
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      });
    let outcome: { payload: string };
    try {
      outcome = await manualPasscodeStrategy({ read }).authorize(
        request(logger),
      );
    } finally {
      stderr.mockRestore();
    }

    expect(outcome.payload).toBe('abc123');
    // The URL on stderr only (C8); the logger the fixed line.
    expect(written).toEqual([
      '🔗 Open this URL in your browser to authenticate:\n',
      '   https://uaa.example/passcode\n',
    ]);
    expect(info.mock.calls.map((call) => call[0])).toEqual([
      'the authorization URL was shown',
    ]);
    expect(String(read.mock.calls[0]![0])).toMatch(
      /passcode|Temporary Authentication Code/i,
    );
  });

  // K14 (6.0.0): which input was empty is no longer named (minor loss).
  it('refuses an empty code', async () => {
    await expect(
      manualPasscodeStrategy({ read: async () => '   ' }).authorize(request()),
    ).rejects.toThrow('no input was received');
  });
});
