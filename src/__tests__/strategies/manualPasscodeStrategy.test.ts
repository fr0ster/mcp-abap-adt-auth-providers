import { describe, expect, it, jest } from '@jest/globals';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { manualPasscodeStrategy } from '../../strategies';

const request = (logger?: ILogger) => ({
  logger,
  buildAuthorizationUrl: async () => 'https://uaa.example/passcode',
});

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

    const outcome = await manualPasscodeStrategy({ read }).authorize(
      request(logger),
    );

    expect(outcome.payload).toBe('abc123');
    expect(String(info.mock.calls[0][0])).toContain(
      'https://uaa.example/passcode',
    );
    expect(String(read.mock.calls[0][0])).toMatch(
      /passcode|Temporary Authentication Code/i,
    );
  });

  it('refuses an empty code', async () => {
    await expect(
      manualPasscodeStrategy({ read: async () => '   ' }).authorize(request()),
    ).rejects.toThrow('No passcode was provided');
  });
});
