/**
 * The refusals read through auth-errors' `classify` — the one
 * reader of a thrown value (`refusalFrom` and its class ladder
 * are gone with the classes) — and shows that no `what` string is left in
 * `src`: every site names a closed operation.
 *
 * Another own class and `TokenEndpointError` went with their classes: a
 * look-alike of a former class is `unknown` (`tokenProviderFailures.test.ts`,
 * "every throw is an AuthProviderFailure"), and `request-failed` is built by
 * `sendTokenRequest` itself (`tokenRequestSite.test.ts`).
 */

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { classify } from '@mcp-abap-adt/auth-errors';
import { notContains } from '../helpers/expectations';
import { SRC } from '../helpers/packagePaths';

const MARKER = 'SECRET-MARKER';

describe('A.1 — classify rows', () => {
  it('a value whose reading throws → unknown with the operation, verbatim', () => {
    const boom = () => {
      throw new Error(MARKER);
    };
    // `instanceof` runs the getPrototypeOf trap: the ladder itself throws.
    const hostile = new Proxy(
      {},
      {
        get: boom,
        has: boom,
        getPrototypeOf: boom,
        getOwnPropertyDescriptor: boom,
        ownKeys: boom,
      },
    );
    const error = classify(hostile, 'token-request', 'client_credentials');
    assert.equal(error.kind, 'unknown');
    assert.deepEqual(error.facts, {
      operation: 'token-request',
      grant: 'client_credentials',
    });
    assert.equal(
      error.reason,
      'client_credentials token request failed (unknown error)',
    );
    notContains(JSON.stringify(error), MARKER);
  });

  it('a TLS failure code → tls, verbatim words and hint', () => {
    const error = classify(
      Object.assign(new Error(MARKER), {
        code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
      }),
      'token-request',
      'authorization_code',
    );
    assert.equal(error.kind, 'tls');
    assert.deepEqual(error.facts, {
      operation: 'token-request',
      grant: 'authorization_code',
      code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
    });
    assert.equal(
      error.reason,
      'authorization_code token request failed: the server refused the client certificate (ERR_SSL_TLSV1_ALERT_UNKNOWN_CA)',
    );
    assert.equal(
      error.hint,
      "check that the server trusts the certificate's issuer and that the certificate is valid and not revoked",
    );
  });

  it('a foreign value → unknown with its allowlisted facts, verbatim', () => {
    const answered = classify(
      Object.assign(new Error(MARKER), {
        response: { status: 500, data: { error: 'server_error' } },
      }),
      'saml-token-exchange',
    );
    assert.equal(answered.kind, 'unknown');
    assert.deepEqual(answered.facts, {
      operation: 'saml-token-exchange',
      status: 500,
      oauthError: 'server_error',
    });
    assert.equal(
      answered.reason,
      'the SAML token exchange failed (HTTP 500, server_error)',
    );

    const unanswered = classify(
      { message: MARKER, key: 'SECRET_KEY', code: 'ENOENT' },
      'loading-certificate',
    );
    assert.deepEqual(unanswered.facts, {
      operation: 'loading-certificate',
      code: 'ENOENT',
    });
    assert.equal(
      unanswered.reason,
      'loading the certificate failed (unknown error, ENOENT)',
    );

    const bare = classify(MARKER, 'persisting-tokens');
    assert.deepEqual(bare.facts, { operation: 'persisting-tokens' });
    assert.equal(bare.reason, 'persisting the tokens failed (unknown error)');
    notContains(JSON.stringify([answered, unanswered, bare]), MARKER);
  });
});

/** Every string literal this package passes as a `what`. */
function whatLiterals(): string[] {
  const root = SRC;
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (name === '__tests__') continue;
      if (statSync(path).isDirectory()) walk(path);
      else if (name.endsWith('.ts')) files.push(path);
    }
  };
  walk(root);
  const found = new Set<string>();
  const patterns = [
    /\bsafely\(\s*'([^']+)'/g,
    /\batTarget\(\s*'([^']+)'/g,
    /\b(?:loggedError|refusalFrom|refusalWords)\(\s*[^,()]+,\s*'([^']+)'/g,
  ];
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    for (const pattern of patterns) {
      for (const match of source.matchAll(pattern)) {
        if (match[1] !== undefined) found.add(match[1]);
      }
    }
  }
  return [...found].sort();
}

describe('A.8 — every what of this package is a closed operation', () => {
  const literals = whatLiterals();

  it('no call site is left: every what moved to a closed operation (refusalFrom, loggedError, refusalWords gone)', () => {
    // 'the probe' left with `logFields`.
    // 'opening the browser' and 'the presenter' left with `logFields`.
    // 'the token request' left with `tokenEndpointError`.
    // 'onTokens' and 'the refresh' left with `logFields`.
    assert.deepEqual(literals, []);
  });
});
