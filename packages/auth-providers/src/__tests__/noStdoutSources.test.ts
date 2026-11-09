/**
 * Nothing in the package writes to process.stdout: under an MCP or LSP stdio
 * transport stdout carries the protocol, and a stray line corrupts it. The
 * rule is checked statically, over the TypeScript AST of every source file
 * (src, `__tests__` left out):
 *
 * - no `console` in any form: the package logs only through the `ILogger`
 *   it is given and prompts on stderr, and it names `console` nowhere
 *   (Measured: no production file reads it), so no console method — the
 *   ones that write to stdout or any other — can be reached, however
 *   written (`console.x`, `console['x']`, `const { log } = console`, an
 *   alias, `globalThis.console`, an import of `node:console`);
 * - no `stdout` of the process in any form: `process.stdout`,
 *   `process['stdout']`, `const { stdout } = process`, through an alias of
 *   `process` or `globalThis.process`, an import of `node:process`
 *   (`import { stdout }`, a namespace or default import read for `stdout`).
 */

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it } from 'node:test';
import ts from 'typescript';
import { SRC } from './helpers/packagePaths';

const PROCESS_MODULES: ReadonlySet<string> = new Set([
  'process',
  'node:process',
]);
const CONSOLE_MODULES: ReadonlySet<string> = new Set([
  'console',
  'node:console',
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

/** `name` as `.name` or `['name']`. */
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

/** `globalThis.name` or `globalThis['name']`. */
function globalMember(node: ts.Node, name: string): boolean {
  const object = memberObject(node);
  return (
    memberName(node) === name &&
    object !== undefined &&
    ts.isIdentifier(object) &&
    object.text === 'globalThis'
  );
}

/** Whether a binding pattern takes `name` out of its object. */
function takes(pattern: ts.ObjectBindingPattern, name: string): boolean {
  return pattern.elements.some((element) => {
    const key = element.propertyName ?? element.name;
    return (
      (ts.isIdentifier(key) || ts.isStringLiteral(key)) && key.text === name
    );
  });
}

/** The module a declaration imports, if any. */
function importedModule(node: ts.Node): string | undefined {
  if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier))
    return node.moduleSpecifier.text;
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
}

/** Every reference to `console` or to the process's stdout in `source`, as `line: text`. */
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

  // The names that hold the process: `process` itself, and every alias.
  const processNames = new Set(['process']);
  const isProcess = (node: ts.Node | undefined): boolean =>
    node !== undefined &&
    ((ts.isIdentifier(node) && processNames.has(node.text)) ||
      globalMember(node, 'process'));
  const collectAliases = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      isProcess(node.initializer)
    ) {
      processNames.add(node.name.text);
    }
    const module = importedModule(node);
    if (module !== undefined && PROCESS_MODULES.has(module)) {
      if (ts.isImportDeclaration(node)) {
        const clause = node.importClause;
        if (clause?.name !== undefined) processNames.add(clause.name.text);
        const bindings = clause?.namedBindings;
        if (bindings !== undefined && ts.isNamespaceImport(bindings))
          processNames.add(bindings.name.text);
      }
      if (ts.isImportEqualsDeclaration(node)) processNames.add(node.name.text);
      if (ts.isCallExpression(node) && ts.isVariableDeclaration(node.parent)) {
        if (ts.isIdentifier(node.parent.name))
          processNames.add(node.parent.name.text);
      }
    }
    ts.forEachChild(node, collectAliases);
  };
  // Twice: an alias of an alias declared later in the file.
  collectAliases(file);
  collectAliases(file);

  const visit = (node: ts.Node): void => {
    // console in any form: an identifier read as a value, or a member of globalThis.
    if (
      ts.isIdentifier(node) &&
      node.text === 'console' &&
      !(
        ts.isPropertyAccessExpression(node.parent) && node.parent.name === node
      ) &&
      !(ts.isPropertyAssignment(node.parent) && node.parent.name === node) &&
      !(ts.isPropertySignature(node.parent) && node.parent.name === node) &&
      !(ts.isBindingElement(node.parent) && node.parent.propertyName === node)
    ) {
      report(node.parent);
    }
    if (globalMember(node, 'console')) report(node);
    const module = importedModule(node);
    if (module !== undefined && CONSOLE_MODULES.has(module)) report(node);
    // process.stdout, process['stdout'], alias.stdout, globalThis.process.stdout
    if (memberName(node) === 'stdout' && isProcess(memberObject(node)))
      report(node);
    // const { stdout } = process (or an alias)
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      isProcess(node.initializer) &&
      takes(node.name, 'stdout')
    ) {
      report(node);
    }
    // import { stdout } from 'node:process'
    if (
      ts.isImportDeclaration(node) &&
      module !== undefined &&
      PROCESS_MODULES.has(module) &&
      node.importClause?.namedBindings !== undefined &&
      ts.isNamedImports(node.importClause.namedBindings) &&
      node.importClause.namedBindings.elements.some(
        (element) => (element.propertyName ?? element.name).text === 'stdout',
      )
    ) {
      report(node);
    }
    // const { stdout } = require('node:process')
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer !== undefined &&
      PROCESS_MODULES.has(importedModule(node.initializer) ?? '') &&
      takes(node.name, 'stdout')
    ) {
      report(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

describe('nothing in src writes to stdout', () => {
  it('no console in any form, and no stdout of the process in any form', () => {
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

  it('the scan sees each form (not blind)', () => {
    const forms = [
      "process.stdout.write('a');",
      "process['stdout'].write('b');",
      'const { stdout } = process;',
      'const { stdout: out } = process;',
      "const p = process; p.stdout.write('c');",
      "globalThis.process.stdout.write('d');",
      "import { stdout } from 'node:process';",
      "import { stdout as o } from 'process';",
      "import * as proc from 'node:process'; proc.stdout.write('e');",
      "import proc2 from 'node:process'; proc2.stdout.write('f');",
      "const { stdout: s2 } = require('node:process');",
      "console.log('g');",
      "console.count('h');",
      "console['info']('i');",
      "const { log } = console; log('j');",
      'const c = console;',
      "globalThis.console.log('k');",
      "console.error('l');",
      "import { Console } from 'node:console';",
    ];
    for (const form of forms) {
      assert.notDeepEqual(stdoutWrites('probe.ts', form), [], form);
    }
  });

  it('what is not stdout is no finding', () => {
    const clean = [
      "process.stderr.write('a');",
      'const home = process.env.HOME;',
      'const { stdout } = await run(exe, []);',
      'const result = { stdout: "x" }; result.stdout;',
      '// console.log and process.stdout in a comment',
      'type T = { console: number };',
    ].join('\n');
    assert.deepEqual(stdoutWrites('probe.ts', clean), []);
  });
});
