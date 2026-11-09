/**
 * The tests run on node:test: no file in src (tests included) imports a
 * Jest package or uses Jest's API, and neither package's manifest names one
 * nor keeps a Jest configuration. Checked over the TypeScript AST, so a
 * word in a comment is no finding and a use is one however it is written.
 */

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it } from 'node:test';
import ts from 'typescript';
import { PACKAGE_ROOT, SRC } from './helpers/packagePaths';

const JEST_PACKAGES: ReadonlySet<string> = new Set([
  'jest',
  '@jest/globals',
  'ts-jest',
  'jest-util',
  '@types/jest',
]);

/** Jest's globals, read as an object or called. */
const JEST_GLOBALS: ReadonlySet<string> = new Set(['jest', 'expect']);

/** Every `.ts` file under `dir`. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith('.ts') ? [path] : [];
  });
}

/** Every use of Jest in `source`, as `line: text`. */
function jestUses(fileName: string, source: string): string[] {
  const file = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.ES2022,
    true,
  );
  const found: string[] = [];
  const report = (node: ts.Node) => {
    const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
    found.push(`${line + 1}: ${node.getText(file)}`);
  };
  const moduleOf = (node: ts.Node): string | undefined => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier !== undefined &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      return node.moduleSpecifier.text;
    }
    if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteral(node.moduleReference.expression)
    ) {
      return node.moduleReference.expression.text;
    }
    if (
      ts.isCallExpression(node) &&
      (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) &&
          node.expression.text === 'require')) &&
      node.arguments[0] !== undefined &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      return node.arguments[0].text;
    }
    return undefined;
  };
  const visit = (node: ts.Node): void => {
    const specifier = moduleOf(node);
    if (specifier !== undefined && JEST_PACKAGES.has(specifier)) report(node);
    // jest.fn(…), expect(…): Jest's globals (no file here names its own so).
    if (
      ts.isIdentifier(node) &&
      JEST_GLOBALS.has(node.text) &&
      ((ts.isPropertyAccessExpression(node.parent) &&
        node.parent.expression === node) ||
        (ts.isCallExpression(node.parent) && node.parent.expression === node))
    ) {
      report(node.parent);
    }
    // jest.Mock, jest.Mocked<…>: Jest's types.
    if (
      ts.isTypeReferenceNode(node) &&
      ts.isQualifiedName(node.typeName) &&
      ts.isIdentifier(node.typeName.left) &&
      node.typeName.left.text === 'jest'
    ) {
      report(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

describe('no Jest', () => {
  it('no file in src imports Jest or uses its API', () => {
    const files = sourceFiles(SRC);
    assert.ok(files.length > 200, `${files.length} files`);
    const found = files.flatMap((path) =>
      jestUses(path, readFileSync(path, 'utf8')).map(
        (line) => `${relative(SRC, path)}:${line}`,
      ),
    );
    assert.deepEqual(found, []);
  });

  it('the scan sees each form of a Jest use (not blind)', () => {
    const source = [
      "import { jest } from '@jest/globals';",
      "import type { Config } from 'jest';",
      "const t = require('ts-jest');",
      'jest.fn();',
      'expect(1).toBe(1);',
      'let m: jest.Mock;',
      // Not Jest: words in a comment, and a name that only holds one.
      '// jest.fn() and expect(…) in a comment',
      'const expected = 1;',
    ].join('\n');
    assert.deepEqual(
      jestUses('probe.ts', source).map((line) => line.split(':')[0]),
      ['1', '2', '3', '4', '5', '6'],
    );
  });

  it('neither manifest names a Jest package, and no Jest configuration is left', () => {
    for (const dir of [
      PACKAGE_ROOT,
      join(PACKAGE_ROOT, '..', 'auth-spnego-gssapi'),
    ]) {
      const manifest: {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      } = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
      const names = [
        ...Object.keys(manifest.dependencies ?? {}),
        ...Object.keys(manifest.devDependencies ?? {}),
      ];
      assert.deepEqual(
        names.filter((name) => JEST_PACKAGES.has(name)),
        [],
        dir,
      );
      assert.equal(existsSync(join(dir, 'jest.config.js')), false, dir);
    }
  });
});
