/**
 * The non-browser strategies.
 *
 * Under an MCP stdio transport a stray prompt on stdout corrupts the
 * protocol stream: that nothing in src writes to stdout is checked
 * statically (noStdoutSources.test.ts); here, that the prompt reaches stderr.
 */

import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import {
  externalCodeStrategy,
  staticCodeStrategy,
} from '../../strategies/codeStrategies';
import {
  manualPasteStrategy,
  manualSamlResponseStrategy,
} from '../../strategies/manualStrategies';
import { contains } from '../helpers/expectations';

describe('manual strategies', () => {
  it('prompts on stderr', async () => {
    const written: string[] = [];
    const spy = mock.method(process.stderr, 'write', (chunk: unknown) => {
      written.push(String(chunk));
      return true;
    });
    try {
      const strategy = manualPasteStrategy({
        redirectUri: 'http://localhost:61001/callback',
        read: async () => 'pasted-code',
      });
      const outcome = await strategy.authorize({
        buildAuthorizationUrl: async () =>
          'https://idp.example/authorize?state=x',
      });
      assert.equal(outcome.payload, 'pasted-code');
    } finally {
      spy.mock.restore();
    }
    contains(written.join(''), 'https://idp.example/authorize?state=x');
  });

  it('accepts a full redirected URL as well as a bare code', async () => {
    const strategy = manualPasteStrategy({
      redirectUri: 'http://localhost:61001/callback',
      read: async () => 'http://localhost:61001/callback?code=from-url&state=x',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async () =>
        'https://idp.example/authorize?state=x',
    });
    assert.equal(outcome.payload, 'from-url');
  });

  it('takes a SAMLResponse verbatim, since it never reaches a URL', async () => {
    const strategy = manualSamlResponseStrategy({
      redirectUri: 'http://localhost:61001/callback',
      read: async () => '  PHNhbWw+  ',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/sso',
    });
    assert.equal(outcome.payload, 'PHNhbWw+');
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
        `https://idp.example/authorize?redirect_uri=${encodeURIComponent(uri)}&code_challenge=abc&state=s`,
    });
    contains(seen[0], 'code_challenge=abc');
    assert.equal(outcome.payload, 'external-code');
    assert.equal(outcome.redirectUri, 'http://localhost:61001/callback');
  });

  it('never calls the builder when the payload is already held', async () => {
    const build = mock.fn(async () => 'https://idp.example/authorize');
    const strategy = staticCodeStrategy({
      redirectUri: 'http://localhost:61001/callback',
      payload: 'already-have-it',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: build,
    });
    assert.equal(build.mock.callCount(), 0);
    assert.equal(outcome.payload, 'already-have-it');
  });
});
