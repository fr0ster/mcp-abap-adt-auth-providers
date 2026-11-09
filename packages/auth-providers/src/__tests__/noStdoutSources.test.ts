/**
 * Nothing in the package writes to process.stdout: under an MCP or LSP stdio
 * transport stdout carries the protocol, and a stray line corrupts it. The
 * rule is checked statically, over the TypeScript AST of every source file
 * (src, `__tests__` left out): no reference to `process.stdout`, however
 * written, and no call of the console methods that write to stdout
 * (`log`, `info`, `debug`, `dir`, `table`).
 */

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it } from 'node:test';
import ts from 'typescript';
import { SRC } from './helpers/packagePaths';

const STDOUT_CONSOLE: ReadonlySet<string> = new Set([
  'log',
  'info',
  'debug',
  'dir',
  'table',
]);

/** The `.ts` sources under `dir`, `__tests__` left out. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (name === '__tests__') return [];
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith('.ts') ? [path] : [];
  });
}

/** `name` as an identifier, `.name` or `['name']`. */
function memberName(node: ts.Node): string | undefined {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (
    ts.isElementAccessExpression(node) &&
    ts.isStringLiteralLike(node.argumentExpression)
  ) {
    return node.argumentExpression.text;
  }
  return undefined;
}

/** The object of a member access (`process` in `process.stdout`). */
function memberObject(node: ts.Node): ts.Expression | undefined {
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node))
    return node.expression;
  return undefined;
}

const isIdentifier = (node: ts.Node | undefined, name: string): boolean =>
  node !== undefined && ts.isIdentifier(node) && node.text === name;

/** Every line of `source` that writes to stdout, as `line: text`. */
function stdoutWrites(fileName: string, source: string): string[] {
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
  const visit = (node: ts.Node): void => {
    // process.stdout, process['stdout']
    if (
      memberName(node) === 'stdout' &&
      isIdentifier(memberObject(node), 'process')
    ) {
      report(node);
    }
    // const { stdout } = process
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer !== undefined &&
      isIdentifier(node.initializer, 'process') &&
      node.name.elements.some(
        (element) =>
          (element.propertyName !== undefined &&
            ts.isIdentifier(element.propertyName) &&
            element.propertyName.text === 'stdout') ||
          (element.propertyName === undefined &&
            isIdentifier(element.name, 'stdout')),
      )
    ) {
      report(node);
    }
    // console.log(…), console['info'](…)
    if (ts.isCallExpression(node)) {
      const name = memberName(node.expression);
      if (
        name !== undefined &&
        STDOUT_CONSOLE.has(name) &&
        isIdentifier(memberObject(node.expression), 'console')
      ) {
        report(node);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

describe('nothing in src writes to stdout', () => {
  it('no reference to process.stdout and no console.log/info/debug/dir/table', () => {
    const files = sourceFiles(SRC);
    // Not vacuous: the whole package is scanned.
    assert.ok(files.length > 50, `${files.length} files`);
    const found = files.flatMap((path) =>
      stdoutWrites(path, readFileSync(path, 'utf8')).map(
        (line) => `${relative(SRC, path)}:${line}`,
      ),
    );
    assert.deepEqual(found, []);
  });

  it('the scan sees each way of writing to stdout (not blind)', () => {
    const source = [
      "process.stdout.write('a');",
      "process['stdout'].write('b');",
      'const { stdout } = process;',
      'const { stdout: out } = process;',
      "console.log('c');",
      "console.info('d');",
      "console.debug('e');",
      'console.dir({});',
      'console.table([]);',
      "console['log']('f');",
      // Not stdout: stderr and the console methods that write there.
      "process.stderr.write('g');",
      "console.error('h');",
      "console.warn('i');",
    ].join('\n');
    assert.deepEqual(
      stdoutWrites('probe.ts', source).map((line) => line.split(':')[0]),
      ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
    );
  });
});
