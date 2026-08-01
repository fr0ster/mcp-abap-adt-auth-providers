/**
 * The non-browser strategies.
 *
 * The stdout assertion is the load-bearing one: under an MCP stdio transport a
 * stray prompt on stdout corrupts the protocol stream.
 */

import { describe, expect, it, jest } from '@jest/globals';
import {
  externalCodeStrategy,
  staticCodeStrategy,
} from '../../strategies/codeStrategies';
import {
  manualPasteStrategy,
  manualSamlResponseStrategy,
} from '../../strategies/manualStrategies';

describe('manual strategies', () => {
  it('prompts without writing a byte to stdout', async () => {
    const written: string[] = [];
    const spy = jest
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      });
    try {
      const strategy = manualPasteStrategy({
        redirectUri: 'http://localhost:61001/callback',
        read: async () => 'pasted-code',
      });
      const outcome = await strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/authorize',
      });
      expect(outcome.payload).toBe('pasted-code');
    } finally {
      spy.mockRestore();
    }
    expect(written).toEqual([]);
  });

  it('accepts a full redirected URL as well as a bare code', async () => {
    const strategy = manualPasteStrategy({
      read: async () => 'http://localhost:61001/callback?code=from-url&state=x',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/authorize',
    });
    expect(outcome.payload).toBe('from-url');
  });

  it('takes a SAMLResponse verbatim, since it never reaches a URL', async () => {
    const strategy = manualSamlResponseStrategy({
      read: async () => '  PHNhbWw+  ',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/sso',
    });
    expect(outcome.payload).toBe('PHNhbWw+');
  });
});

describe('code strategies', () => {
  it('hands the assembled URL to an external provider', async () => {
    const seen: string[] = [];
    const strategy = externalCodeStrategy({
      redirectUri: 'http://localhost:61001/callback',
      provide: async (url) => {
        seen.push(url);
        return 'external-code';
      },
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async (uri) =>
        `https://idp.example/authorize?redirect_uri=${encodeURIComponent(uri)}&code_challenge=abc`,
    });
    expect(seen[0]).toContain('code_challenge=abc');
    expect(outcome.payload).toBe('external-code');
    expect(outcome.redirectUri).toBe('http://localhost:61001/callback');
  });

  it('never calls the builder when the payload is already held', async () => {
    const build = jest.fn(async () => 'https://idp.example/authorize');
    const strategy = staticCodeStrategy({
      redirectUri: 'http://localhost:61001/callback',
      payload: 'already-have-it',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: build,
    });
    expect(build).not.toHaveBeenCalled();
    expect(outcome.payload).toBe('already-have-it');
  });
});
