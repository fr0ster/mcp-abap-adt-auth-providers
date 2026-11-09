/**
 * The published manifest declares nothing that does not work from an npm
 * install. The two `bin` commands pointed at `.ts` files run through `tsx`
 * (a devDependency) and imported `../src`, which is not published.
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { contains, notContains } from './helpers/expectations';
import { PACKAGE_ROOT } from './helpers/packagePaths';

const ROOT = PACKAGE_ROOT;
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
    assert.equal(manifest.bin, undefined);
  });

  it('publishes no bin directory, and the tree has none', () => {
    notContains(manifest.files, 'bin');
    assert.equal(existsSync(join(ROOT, 'bin')), false);
  });

  it('carries no tsx, which only bin/ used', () => {
    assert.equal(manifest.devDependencies?.tsx, undefined);
  });

  // Three suites import AbapServiceKeyStore from it at the top level:
  // browserAuth.integration, ClientCredentialsProvider, AuthorizationCodeProvider.
  it('keeps @mcp-abap-adt/auth-stores, which three test suites import', () => {
    assert.notEqual(
      manifest.devDependencies?.['@mcp-abap-adt/auth-stores'],
      undefined,
    );
  });

  // tsconfig.json compiles every non-test file under src/, so helpers and
  // stand fixtures in src/__tests__ were built into dist/__tests__ and
  // published with 4.0.0 and 4.1.0. The build uses a config that leaves
  // them out; type-checking still covers them through tsconfig.json.
  it('builds through tsconfig.build.json, which leaves src/__tests__ out', () => {
    contains(manifest.scripts?.build, '-p tsconfig.build.json');
    contains(manifest.scripts?.['build:fast'], '-p tsconfig.build.json');
    const buildConfig = JSON.parse(
      readFileSync(join(ROOT, 'tsconfig.build.json'), 'utf8'),
    ) as { extends?: string; exclude?: string[] };
    assert.equal(buildConfig.extends, './tsconfig.json');
    contains(buildConfig.exclude, 'src/__tests__/**');
  });
});
