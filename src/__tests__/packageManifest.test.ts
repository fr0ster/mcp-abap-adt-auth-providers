/**
 * The published manifest declares nothing that does not work from an npm
 * install. The two `bin` commands pointed at `.ts` files run through `tsx`
 * (a devDependency) and imported `../src`, which is not published.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';

const ROOT = join(__dirname, '..', '..');
const manifest = JSON.parse(
  readFileSync(join(ROOT, 'package.json'), 'utf8'),
) as {
  bin?: unknown;
  files?: string[];
  devDependencies?: Record<string, string>;
};

describe('the package manifest', () => {
  it('declares no bin commands', () => {
    expect(manifest.bin).toBeUndefined();
  });

  it('publishes no bin directory, and the tree has none', () => {
    expect(manifest.files).not.toContain('bin');
    expect(existsSync(join(ROOT, 'bin'))).toBe(false);
  });

  it('carries no tsx, which only bin/ used', () => {
    expect(manifest.devDependencies?.tsx).toBeUndefined();
  });

  // Three suites import AbapServiceKeyStore from it at the top level:
  // browserAuth.integration, ClientCredentialsProvider, AuthorizationCodeProvider.
  it('keeps @mcp-abap-adt/auth-stores, which three test suites import', () => {
    expect(
      manifest.devDependencies?.['@mcp-abap-adt/auth-stores'],
    ).toBeDefined();
  });
});
