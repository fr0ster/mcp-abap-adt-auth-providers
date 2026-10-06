/**
 * Appendix A.1 rows A1 and A13–A16 through `refusalFrom`, and the closed
 * operation every `what` of this package maps to (A.8, L10).
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { authError, isMinted } from '@mcp-abap-adt/auth-errors';
import { operationFor, refusalFrom } from '../../auth/refusal';
import { TokenEndpointError } from '../../errors/TokenEndpointError';
import { TokenProviderError } from '../../errors/TokenProviderErrors';
import { mintedRefusal } from '../helpers/minted';

const MARKER = 'SECRET-MARKER';

describe('A.1 — refusalFrom rows', () => {
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
    const error = mintedRefusal(
      refusalFrom(hostile, 'client_credentials token request'),
    );
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

  it('A13: another own error → unknown with the operation, its class label lost', () => {
    const own = mintedRefusal(
      refusalFrom(
        new TokenProviderError(MARKER, 'CODE'),
        'password token request',
      ),
    );
    expect(own.kind).toBe('unknown');
    expect(own.facts).toEqual({
      operation: 'token-request',
      grant: 'password',
    });
    expect(own.reason).toBe('password token request failed (unknown error)');
    expect(JSON.stringify(own)).not.toContain('TokenProviderError');
  });

  it('A14: a TokenEndpointError → request-failed, verbatim with and without a response', () => {
    const refused = mintedRefusal(
      refusalFrom(
        new TokenEndpointError(MARKER, {
          status: 401,
          oauthError: 'invalid_client',
        }),
        'client_credentials token request',
      ),
    );
    expect(refused.kind).toBe('request-failed');
    expect(refused.facts).toEqual({
      operation: 'token-request',
      grant: 'client_credentials',
      problem: 'refused',
      status: 401,
      oauthError: 'invalid_client',
    });
    expect(refused.reason).toBe(
      'client_credentials token request failed (HTTP 401, invalid_client)',
    );

    const silent = mintedRefusal(
      refusalFrom(new TokenEndpointError(MARKER, {}), 'the token request'),
    );
    expect(silent.facts).toEqual({
      operation: 'token-request',
      problem: 'no-response',
    });
    expect(silent.reason).toBe(
      'the token request failed (the token endpoint gave no reason)',
    );

    const reset = mintedRefusal(
      refusalFrom(
        new TokenEndpointError(MARKER, { code: 'ECONNRESET' }),
        'the token request',
      ),
    );
    expect(reset.facts).toEqual({
      operation: 'token-request',
      problem: 'no-response',
      code: 'ECONNRESET',
    });
    expect(reset.reason).toBe('the token request failed (ECONNRESET)');
    expect(JSON.stringify([refused, silent, reset])).not.toContain(MARKER);
  });

  it('A15: a TLS failure code → tls, verbatim words and hint', () => {
    const error = mintedRefusal(
      refusalFrom(
        Object.assign(new Error(MARKER), {
          code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
        }),
        'authorization_code token request',
      ),
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
    const answered = mintedRefusal(
      refusalFrom(
        Object.assign(new Error(MARKER), {
          response: { status: 500, data: { error: 'server_error' } },
        }),
        'the SAML token exchange',
      ),
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

    const unanswered = mintedRefusal(
      refusalFrom(
        { message: MARKER, key: 'SECRET_KEY', code: 'ENOENT' },
        'loading the certificate',
      ),
    );
    expect(unanswered.facts).toEqual({
      operation: 'loading-certificate',
      code: 'ENOENT',
    });
    expect(unanswered.reason).toBe(
      'loading the certificate failed (unknown error, ENOENT)',
    );

    const bare = mintedRefusal(refusalFrom(MARKER, 'onTokens'));
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

  it('the scan finds the call sites', () => {
    expect(literals).toEqual(
      expect.arrayContaining([
        'loading the certificate',
        'onTokens',
        'opening the browser',
        'reading the rejection',
        'the presenter',
        'the probe',
        'the token request',
      ]),
    );
  });

  it.each(literals)(
    '%s → an operation whose words are its words (A1)',
    (what) => {
      const mapped = operationFor(what);
      expect(mapped.operation).not.toBe('unfamiliar-error');
      expect(authError.unknown(mapped).reason).toBe(
        `${what} failed (unknown error)`,
      );
    },
  );

  it.each([
    'authorization_code',
    'authorization_code_pkce',
    'password',
    'client_credentials',
    'user_token',
    'client_x509',
    'saml2_bearer',
  ])('"%s token request" → token-request with that grant', (grant) => {
    expect(operationFor(`${grant} token request`)).toEqual({
      operation: 'token-request',
      grant,
    });
  });

  it('a what this package does not use → the unfamiliar operation (L10)', () => {
    expect(operationFor('it')).toEqual({ operation: 'unfamiliar-error' });
    expect(operationFor('nonsense token request')).toEqual({
      operation: 'unfamiliar-error',
    });
    const error = refusalFrom(new Error(MARKER), 'it');
    expect(!error.ok && isMinted(error.refusal)).toBe(true);
  });
});
