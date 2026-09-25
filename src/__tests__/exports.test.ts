/**
 * The package's public surface for SAML assertion validation: what a consumer
 * may import from the package root, and what stays implementation.
 */

import { describe, expect, it } from '@jest/globals';
import type { AssertionCheck, ShippedValidatorOptions } from '../index';
import * as surface from '../index';

describe('public exports — SAML assertion validation', () => {
  it.each([
    'createSignedResponseValidator',
    'createSignedAssertionValidator',
    'createInMemoryReplayStore',
    'defaultReplayStore',
    'AssertionValidationError',
  ])('exports %s', (name) => {
    expect((surface as Record<string, unknown>)[name]).toBeDefined();
  });

  it('exports the types AssertionCheck and ShippedValidatorOptions', () => {
    // Type-only exports vanish at runtime; this compiles only while they are
    // exported, since ts-jest type-checks the suite before running it.
    const check: AssertionCheck = 'replay';
    const options: ShippedValidatorOptions = { idpCertificates: [] };
    expect(check).toBe('replay');
    expect(options.idpCertificates).toEqual([]);
  });

  it.each([
    'parseXsdDateTime',
    'findDuplicateId',
    'resolveSignedElements',
    'isShippedValidator',
  ])('does not export the internal %s', (name) => {
    expect(name in surface).toBe(false);
  });

  it('no longer exports parseSamlNotOnOrAfter', () => {
    expect('parseSamlNotOnOrAfter' in surface).toBe(false);
  });
});
