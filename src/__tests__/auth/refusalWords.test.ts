/**
 * refusalWords: the package's own refusal words for a thrown value, exported
 * so a consumer relays them instead of copying them. Imported from the
 * package index on purpose — the export is the contract.
 */

import { describe, expect, it } from '@jest/globals';
import { loggedError } from '../../auth/refusal';
import {
  AssertionValidationError,
  CertificateAuthProvider,
  CertificateMaterialError,
  ClientAuthenticationError,
  refusalWords,
  ServiceKeyError,
  SessionDataError,
  TokenEndpointError,
  ValidationError,
} from '../../index';
import { wordsOf } from '../helpers/minted';

const MARKER = 'SECRET-MARKER';
const text = (x: unknown) => JSON.stringify(x);

describe('refusalWords', () => {
  it('is exported from the package index', () => {
    expect(typeof refusalWords).toBe('function');
  });

  it.each([
    [
      'incomplete',
      new CertificateMaterialError(true),
      'the client certificate is incomplete',
      'give a PFX, or a certificate together with its key',
    ],
    [
      'unusable',
      new CertificateMaterialError(false),
      'the client certificate could not be used',
      'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
    ],
    [
      'expired',
      new CertificateMaterialError(false, true),
      'the client certificate has expired',
      'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    ],
  ])(
    'a CertificateMaterialError (%s) → its exact reason and hint',
    (_kind, error, reason, hint) => {
      expect(refusalWords(error, 'loading the certificate')).toEqual({
        reason,
        hint,
      });
    },
  );

  it('a ClientAuthenticationError → its fixed words', () => {
    expect(refusalWords(new ClientAuthenticationError(), 'it')).toEqual({
      reason: 'the client signing key could not be used',
      hint: 'check the private key and that it matches the algorithm',
    });
  });

  it('a TokenEndpointError → the allowlisted facts, nothing of its message', () => {
    const error = new TokenEndpointError(`token request failed: ${MARKER}`, {
      status: 401,
      oauthError: 'invalid_client',
    });
    const words = refusalWords(error, 'the token request');
    expect(words).toEqual({
      reason: 'the token request failed (HTTP 401, invalid_client)',
    });
    expect(text(words)).not.toContain(MARKER);
  });

  it('a foreign Error with a secret in its message → "unknown error", no hint', () => {
    const error = new Error(`passphrase=${MARKER}`, {
      cause: new Error(MARKER),
    });
    const words = refusalWords(error, 'loading the certificate');
    expect(words).toEqual({
      reason: 'loading the certificate failed (unknown error)',
    });
    expect('hint' in words).toBe(false);
    expect(text(words)).not.toContain(MARKER);
  });

  it('a Proxy whose every trap throws → fixed words, no throw', () => {
    const boom = () => {
      throw new Error(MARKER);
    };
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
    let words: unknown;
    expect(() => {
      words = refusalWords(hostile, 'the token source');
    }).not.toThrow();
    expect(words).toEqual({
      reason: 'the token source failed (unknown error)',
    });
  });

  it('a CertificateMaterialError whose own `words` carries a marker → the fixed words', () => {
    const forged = new CertificateMaterialError(true);
    Object.defineProperty(forged, 'words', {
      get: () => ({ reason: MARKER, hint: MARKER }),
    });
    Object.defineProperty(forged, 'message', { value: MARKER });
    const words = refusalWords(forged, 'it');
    expect(words).toEqual({
      reason: 'the client certificate is incomplete',
      hint: 'give a PFX, or a certificate together with its key',
    });
    expect(text(words)).not.toContain(MARKER);
  });

  it('own `words` / `message` getters that throw → fixed words, no throw', () => {
    const boom = () => {
      throw new Error(MARKER);
    };
    const forged = Object.create(CertificateMaterialError.prototype, {
      words: { get: boom },
      message: { get: boom },
      incomplete: { value: false },
      expired: { value: true },
    });
    let words: unknown;
    expect(() => {
      words = refusalWords(forged, 'it');
    }).not.toThrow();
    expect(words).toEqual({
      reason: 'the client certificate has expired',
      hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    });
  });

  it('a throwing `incomplete` flag reads as not set → fixed words, no throw', () => {
    const forged = Object.create(CertificateMaterialError.prototype, {
      incomplete: {
        get: () => {
          throw new Error(MARKER);
        },
      },
    });
    expect(refusalWords(forged, 'it')).toEqual({
      reason: 'the client certificate could not be used',
      hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
    });
  });

  it('a foreign object with a marker `message` getter → nothing of it', () => {
    const forged = {
      get message() {
        return MARKER;
      },
      get words() {
        return { reason: MARKER };
      },
    };
    const words = refusalWords(forged, 'the token source');
    expect(words).toEqual({
      reason: 'the token source failed (unknown error)',
    });
    expect(text(words)).not.toContain(MARKER);
  });

  // A3 (Task 24): an assertion's `check` is no longer read at all — the
  // class carries no rule and answers as any other own class.
  it('an assertion `check` getter is never read', () => {
    const forged = new AssertionValidationError('signature', 'x');
    let reads = 0;
    Object.defineProperty(forged, 'check', {
      get: () => {
        reads += 1;
        return MARKER;
      },
    });
    const words = refusalWords(forged, 'it');
    expect(reads).toBe(0);
    expect(text(words)).not.toContain(MARKER);
  });

  it.each([
    [
      'ValidationError',
      () => new ValidationError('x', ['clientId']),
      'the provider configuration is incomplete or invalid',
    ],
    [
      'ServiceKeyError',
      () => new ServiceKeyError('x', ['uaaUrl']),
      'the service key or session data is incomplete',
    ],
    [
      'SessionDataError',
      () => new SessionDataError('x', ['refreshToken']),
      'the service key or session data is incomplete',
    ],
  ])(
    '%s: missingFields with its own filter/join → only allowlisted names',
    (_name, make, prefix) => {
      const error = make();
      const missing = ['clientId', 'not-a-field', MARKER];
      Object.defineProperty(missing, 'filter', { value: () => [MARKER] });
      Object.defineProperty(missing, 'join', { value: () => MARKER });
      Object.defineProperty(missing, 'map', { value: () => [MARKER] });
      (error as { missingFields: unknown }).missingFields = missing;
      const words = refusalWords(error, 'it');
      expect(words.reason).toBe(`${prefix}: clientId`);
      expect(text(words)).not.toContain(MARKER);
    },
  );

  it('missingFields as a Proxy claiming a huge length → bounded reads, no throw', () => {
    let reads = 0;
    const huge = new Proxy(['clientId'], {
      get: (target, key) => {
        if (key === 'length') return 2 ** 32 - 1;
        reads++;
        return key === '0' ? target[0] : 'scope';
      },
    });
    const error = new ValidationError('x', []);
    (error as { missingFields: unknown }).missingFields = huge;
    const words = refusalWords(error, 'it');
    expect(words.reason).toBe(
      'the provider configuration is incomplete or invalid: clientId, scope',
    );
    expect(reads).toBeLessThanOrEqual(64);
  });

  it('CertificateAuthProvider.prepare: a loader throwing a forged CertificateMaterialError → fixed words', async () => {
    const forged = new CertificateMaterialError(false, true);
    Object.defineProperty(forged, 'words', {
      get: () => ({ reason: MARKER, hint: MARKER }),
    });
    const provider = new CertificateAuthProvider(
      {
        load: async () => ({
          get pfx(): Buffer {
            throw forged;
          },
        }),
      },
      {} as never,
    );
    const outcome = await provider.prepare();
    expect(wordsOf(outcome)).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate has expired',
        hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
      },
    });
    expect(text(outcome)).not.toContain(MARKER);
  });

  it('CertificateAuthProvider.prepare: a forged error whose `words` throws → fixed words, no throw', async () => {
    const forged = new CertificateMaterialError(true);
    Object.defineProperty(forged, 'words', {
      get: () => {
        throw new Error(MARKER);
      },
    });
    const provider = new CertificateAuthProvider(
      {
        load: async () => ({
          get pfx(): Buffer {
            throw forged;
          },
        }),
      },
      {} as never,
    );
    const outcome = await provider.prepare();
    expect(wordsOf(outcome)).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate is incomplete',
        hint: 'give a PFX, or a certificate together with its key',
      },
    });
  });

  it('CertificateMaterialError normalises its flags to booleans', () => {
    const error = new CertificateMaterialError(1 as never, 'yes' as never);
    expect(error.incomplete).toBe(false);
    expect(error.expired).toBe(false);
    expect(error.message).toBe('the client certificate could not be used');
  });

  describe('the word objects `words` hands out cannot be changed', () => {
    const INCOMPLETE = {
      reason: 'the client certificate is incomplete',
      hint: 'give a PFX, or a certificate together with its key',
    };
    // Every way of changing the shared object, tried during a hostile flag
    // read — the moment the refusal is about to choose its words.
    const tamperings: Array<[string, (words: object) => void]> = [
      [
        'assignment',
        (words) => {
          Object.assign(words, { reason: MARKER, hint: MARKER });
        },
      ],
      [
        'defineProperty',
        (words) => {
          Object.defineProperty(words, 'reason', { value: MARKER });
        },
      ],
      [
        'a throwing getter',
        (words) => {
          Object.defineProperty(words, 'reason', {
            get: () => {
              throw new Error(MARKER);
            },
          });
        },
      ],
    ];

    it.each(tamperings)(
      '%s → refusalWords, loggedError, the certificate check and a later construction keep the fixed words',
      async (_how, tamper) => {
        const shared = new CertificateMaterialError(true).words;
        const forged = Object.create(CertificateMaterialError.prototype, {
          incomplete: {
            get: () => {
              try {
                tamper(shared);
              } catch {
                // frozen: the change is refused
              }
              return true;
            },
          },
        });

        expect(refusalWords(forged, 'it')).toEqual(INCOMPLETE);
        expect(loggedError(forged, 'it')).toEqual({ error: INCOMPLETE.reason });
        const provider = new CertificateAuthProvider(
          {
            load: async () => ({
              get pfx(): Buffer {
                throw forged;
              },
            }),
          },
          {} as never,
        );
        expect(wordsOf(await provider.prepare())).toEqual({
          ok: false,
          refusal: INCOMPLETE,
        });

        const genuine = new CertificateMaterialError(true);
        expect(genuine.message).toBe(INCOMPLETE.reason);
        expect(refusalWords(genuine, 'it')).toEqual(INCOMPLETE);
        expect(loggedError(genuine, 'it')).toEqual({
          error: INCOMPLETE.reason,
        });
        expect(text(genuine.words)).not.toContain(MARKER);
      },
    );
  });
});
