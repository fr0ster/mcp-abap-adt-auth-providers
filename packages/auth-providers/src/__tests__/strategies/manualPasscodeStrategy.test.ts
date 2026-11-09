import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { manualPasscodeStrategy } from '../../strategies';
import { thrown } from '../helpers/expectations';

// As a provider hands it over: `logger: undefined` present when there is none.
const request = (logger?: ILogger) =>
  ({
    logger,
    buildAuthorizationUrl: async () => 'https://uaa.example/passcode',
  }) as AuthorizationRequest;

describe('manualPasscodeStrategy', () => {
  it('shows where to get the code and returns what the user pastes, trimmed', async () => {
    const info = mock.fn();
    const logger = {
      info,
      error: mock.fn(),
      warn: mock.fn(),
      debug: mock.fn(),
    };
    const read = mock.fn(async (_prompt: string) => '  abc123  ');
    const written: string[] = [];
    const stderr = mock.method(process.stderr, 'write', (chunk: unknown) => {
      written.push(String(chunk));
      return true;
    });
    let outcome: { payload: string };
    try {
      outcome = await manualPasscodeStrategy({ read }).authorize(
        request(logger),
      );
    } finally {
      stderr.mock.restore();
    }

    assert.equal(outcome.payload, 'abc123');
    // The URL on stderr only; the logger the fixed line.
    assert.deepEqual(written, [
      '🔗 Open this URL in your browser to authenticate:\n',
      '   https://uaa.example/passcode\n',
    ]);
    assert.deepEqual(
      info.mock.calls.map((call) => call.arguments).map((call) => call[0]),
      ['the authorization URL was shown'],
    );
    assert.match(
      String(read.mock.calls.map((call) => call.arguments)[0]![0]),
      /passcode|Temporary Authentication Code/i,
    );
  });

  // Which input was empty is no longer named (minor loss).
  it('refuses an empty code', async () => {
    await assert.rejects(
      manualPasscodeStrategy({ read: async () => '   ' }).authorize(request()),
      thrown('no input was received'),
    );
  });
});
