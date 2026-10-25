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
  scripts?: Record<string, string>;
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

  // tsconfig.json compiles every non-test file under src/, so helpers and
  // stand fixtures in src/__tests__ were built into dist/__tests__ and
  // published with 4.0.0 and 4.1.0. The build uses a config that leaves
  // them out; type-checking still covers them through tsconfig.json.
  it('builds through tsconfig.build.json, which leaves src/__tests__ out', () => {
    expect(manifest.scripts?.build).toContain('-p tsconfig.build.json');
    expect(manifest.scripts?.['build:fast']).toContain(
      '-p tsconfig.build.json',
    );
    const buildConfig = JSON.parse(
      readFileSync(join(ROOT, 'tsconfig.build.json'), 'utf8'),
    ) as { extends?: string; exclude?: string[] };
    expect(buildConfig.extends).toBe('./tsconfig.json');
    expect(buildConfig.exclude).toContain('src/__tests__/**');
  });
});
