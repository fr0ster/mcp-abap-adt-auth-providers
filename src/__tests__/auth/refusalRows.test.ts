/**
 * Appendix A.1 rows A1, A15 and A16 through auth-errors' `classify` — the one
 * reader of a thrown value since Task 27 (`refusalFrom` and its class ladder
 * are gone with the classes, spec §6) — and A.8: no `what` string is left in
 * `src`, every site names a closed operation.
 *
 * A13 (another own class) and A14 (`TokenEndpointError`) went with their
 * classes: a look-alike of a former class is `unknown`
 * (`tokenProviderFailures.test.ts`, "L3 total"), and `request-failed` is
 * built by `sendTokenRequest` itself (`tokenRequestSite.test.ts`).
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { classify } from '@mcp-abap-adt/auth-errors';

const MARKER = 'SECRET-MARKER';

describe('A.1 — classify rows', () => {
  it('A1: a value whose reading throws → unknown with the operation, verbatim', () => {
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
    expect(error.kind).toBe('unknown');
    expect(error.facts).toEqual({
      operation: 'token-request',
      grant: 'client_credentials',
    });
    expect(error.reason).toBe(
      'client_credentials token request failed (unknown error)',
    );
    expect(JSON.stringify(error)).not.toContain(MARKER);
  });

  it('A15: a TLS failure code → tls, verbatim words and hint', () => {
    const error = classify(
      Object.assign(new Error(MARKER), {
        code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
      }),
      'token-request',
      'authorization_code',
    );
    expect(error.kind).toBe('tls');
    expect(error.facts).toEqual({
      operation: 'token-request',
      grant: 'authorization_code',
      code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
    });
    expect(error.reason).toBe(
      'authorization_code token request failed: the server refused the client certificate (ERR_SSL_TLSV1_ALERT_UNKNOWN_CA)',
    );
    expect(error.hint).toBe(
      "check that the server trusts the certificate's issuer and that the certificate is valid and not revoked",
    );
  });

  it('A16: a foreign value → unknown with its allowlisted facts, verbatim', () => {
    const answered = classify(
      Object.assign(new Error(MARKER), {
        response: { status: 500, data: { error: 'server_error' } },
      }),
      'saml-token-exchange',
    );
    expect(answered.kind).toBe('unknown');
    expect(answered.facts).toEqual({
      operation: 'saml-token-exchange',
      status: 500,
      oauthError: 'server_error',
    });
    expect(answered.reason).toBe(
      'the SAML token exchange failed (HTTP 500, server_error)',
    );

    const unanswered = classify(
      { message: MARKER, key: 'SECRET_KEY', code: 'ENOENT' },
      'loading-certificate',
    );
    expect(unanswered.facts).toEqual({
      operation: 'loading-certificate',
      code: 'ENOENT',
    });
    expect(unanswered.reason).toBe(
      'loading the certificate failed (unknown error, ENOENT)',
    );

    const bare = classify(MARKER, 'on-tokens-hook');
    expect(bare.facts).toEqual({ operation: 'on-tokens-hook' });
    expect(bare.reason).toBe('onTokens failed (unknown error)');
    expect(JSON.stringify([answered, unanswered, bare])).not.toContain(MARKER);
  });
});

/** Every string literal this package passes as a `what` (A.8). */
function whatLiterals(): string[] {
  const root = join(__dirname, '..', '..');
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

  it('no call site is left: every what moved to a closed operation (refusalFrom, loggedError, refusalWords gone in Task 27)', () => {
    // 'the probe' left with `logFields` (H5: Task 25).
    // 'opening the browser' and 'the presenter' left with `logFields`
    // (H7, H8, H3: Task 23).
    // 'the token request' left with `tokenEndpointError` (D2, H9: Task 21).
    // 'onTokens' and 'the refresh' left with `logFields` (H1, H2: Task 22).
    expect(literals).toEqual([]);
  });
});
