/**
 * The shape check of the auth error contract, run in-process through
 * auth-errors' module with this repository's own TypeScript. `SHAPE_CHECK` is
 * the whole configuration: rules 1–8, the base by declaration, this
 * repository's `tsconfig.json` and its site lists under `tools/`. Each fixture
 * is refused by exactly its own rule, a conforming provider and this
 * package's own source pass, and every entry of the diagnostic site list is
 * an approved extraction site that is used.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import {
  checkProviderShape,
  reportLines,
  type ShapeCheckOptions,
  type ShapeCheckReport,
  type ShapeFinding,
  type ShapeRule,
} from '@mcp-abap-adt/auth-errors/shape-check';
import * as typescript from 'typescript';
import { caseTitle, contains } from './helpers/expectations';
import { PACKAGE_ROOT } from './helpers/packagePaths';

const ROOT = PACKAGE_ROOT;
/** The repository root: the package lives in packages/auth-providers. */
const REPO_ROOT = resolve(ROOT, '../..');
const FIXTURES = join(ROOT, 'tools', '__fixtures__');
const RULE8_ROOT = join(FIXTURES, 'rule8');

/** How this repository runs the shape check — its whole configuration. */
const SHAPE_CHECK: ShapeCheckOptions = {
  typescript,
  rules: [1, 2, 3, 4, 5, 6, 7, 8],
  root: ROOT,
  project: join(ROOT, 'tsconfig.json'),
  sites: join(ROOT, 'tools'),
  base: './src/auth/AuthProviderBase#AuthProviderBase',
};

/** The findings of a report that checked; anything else fails with its lines. */
function findingsOf(report: ShapeCheckReport): readonly ShapeFinding[] {
  if (report.status !== 'checked') {
    throw new Error(`not checked:\n${reportLines(report).join('\n')}`);
  }
  return report.findings;
}

/** The approved extraction sites — and nothing else. */
const APPROVED = [
  ['src/snc/SncLogonProvider.ts', 'resolve', 'library'],
  ['src/snc/DefaultSncLibraryLocator.ts', 'libraryNotFound', 'candidatePaths'],
  ['src/validation/assertionValidator.ts', 'validate', 'rootElement'],
  ['src/validation/assertionValidator.ts', 'validate', 'id'],
  ['src/validation/signedNode.ts', 'resolveOne', 'referenceUri'],
  ['src/validation/assertionValidator.ts', 'checkStatus', 'statusCode'],
  ['src/validation/assertionValidator.ts', 'validate', 'issuer'],
  ['src/validation/assertionValidator.ts', 'validate', 'notBefore'],
  ['src/validation/assertionValidator.ts', 'validate', 'notOnOrAfter'],
  ['src/validation/assertionValidator.ts', 'validate', 'destination'],
  ['src/providers/saml2Utils.ts', 'acsMismatch', 'configuredUri'],
  ['src/providers/saml2Utils.ts', 'acsMismatch', 'strategyUri'],
  ['src/providers/AuthorizationCodeProvider.ts', 'mismatch', 'configuredUri'],
  ['src/providers/AuthorizationCodeProvider.ts', 'mismatch', 'strategyUri'],
].map(([file, fn, field]) => `${file}#${fn}#${field}`);

function readList(name: string): unknown {
  return JSON.parse(readFileSync(join(ROOT, 'tools', name), 'utf8'));
}

/** The fixtures and the rule each breaks, with how many findings it gives. */
const FIXTURE_RULES: readonly (readonly [ShapeRule, string, number])[] = [
  [1, 'rule1.ts', 2],
  [2, 'rule2.ts', 2],
  [3, 'rule3.ts', 1],
  [4, 'rule4.ts', 2],
  [5, 'rule5.ts', 1],
  [6, 'rule6.ts', 1],
  [7, 'rule7.ts', 2],
];

describe('the shape check', () => {
  it('the shape check finds nothing in this repository', () => {
    assert.deepEqual(reportLines(checkProviderShape(SHAPE_CHECK)), []);
  });

  it('the assertion site list is empty: no cast to a contract type anywhere', () => {
    assert.deepEqual(readList('assertion-sites.json'), []);
  });

  it('the diagnostic site list names exactly the approved extraction sites', () => {
    const list = readList('diagnostic-sites.json') as {
      file: string;
      function: string;
      field: string;
    }[];
    assert.deepEqual(
      list.map((site) => `${site.file}#${site.function}#${site.field}`).sort(),
      [...APPROVED].sort(),
    );
  });

  it('every listed site is used: without the list, each is reported, and nothing else', () => {
    const empty = mkdtempSync(join(tmpdir(), 'shape-sites-'));
    try {
      const findings = findingsOf(
        checkProviderShape({ ...SHAPE_CHECK, rules: [6], sites: empty }),
      );
      assert.ok(findings.length > 0, `${findings.length} > ${0}`);
      const reported = new Set<string>();
      for (const finding of findings) {
        assert.equal(finding.rule, 6);
        // `… diagnostics (a, b) passed outside … (<file>, <function>)`
        const what = finding.what;
        const open = what.indexOf('diagnostics (') + 'diagnostics ('.length;
        const fields = what.slice(open, what.indexOf(')', open));
        const site = what.slice(
          what.lastIndexOf('(') + 1,
          what.lastIndexOf(')'),
        );
        const [file, fn] = site.split(', ');
        assert.equal(file, finding.file);
        for (const field of fields.split(', ')) {
          reported.add(`${file}#${fn}#${field}`);
        }
      }
      assert.deepEqual([...reported].sort(), [...APPROVED].sort());
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  for (const [caseIndex, caseRow] of FIXTURE_RULES.entries()) {
    const [rule, fixture, count] = caseRow;
    it(
      caseTitle(
        'rule %s: refuses %s, every finding its own rule',
        caseRow,
        caseIndex,
      ),
      () => {
        const findings = findingsOf(
          checkProviderShape({
            ...SHAPE_CHECK,
            files: [join(FIXTURES, fixture)],
          }),
        );
        assert.equal(findings.length, count);
        for (const finding of findings) {
          assert.deepEqual(
            [finding.file, finding.rule],
            [`tools/__fixtures__/${fixture}`, rule],
          );
        }
      },
    );
  }

  it('rule 2: a subclass of AuthProviderBase declaring establish is reported', () => {
    const findings = findingsOf(
      checkProviderShape({
        ...SHAPE_CHECK,
        files: [join(FIXTURES, 'rule2.ts')],
      }),
    );
    assert.equal(
      findings.some(
        (finding) =>
          finding.rule === 2 &&
          finding.what.includes(
            'a class reaching AuthProviderBase declares establish',
          ),
      ),
      true,
    );
  });

  it('rule 8: a Basic value and a base64 of a client secret in src/auth and src/providers; legacyBasic passes', () => {
    const findings = findingsOf(
      checkProviderShape({
        typescript,
        rules: [8],
        root: RULE8_ROOT,
        project: join(RULE8_ROOT, 'tsconfig.json'),
        sites: null,
      }),
    );
    assert.deepEqual(
      findings.map((finding) => [finding.file, finding.rule]),
      [
        ['src/auth/basicHeader.ts', 8],
        ['src/providers/secretBase64.ts', 8],
      ],
    );
  });

  it('passes a provider that extends the base and relays a minted refusal', () => {
    assert.deepEqual(
      reportLines(
        checkProviderShape({
          ...SHAPE_CHECK,
          files: [join(FIXTURES, 'clean.ts')],
        }),
      ),
      [],
    );
  });

  it("every fixture's rule is one the configuration runs, rule 8 included", () => {
    const broken = [...FIXTURE_RULES.map(([rule]) => rule), 8];
    for (const rule of broken) {
      contains(SHAPE_CHECK.rules, rule);
    }
  });

  describe('the publishing gate runs it', () => {
    const scripts = (
      JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
        scripts: Record<string, string>;
      }
    ).scripts;

    it('test:shape runs this file', () => {
      assert.equal(
        scripts['test:shape'],
        'npm run --silent test:build && node tools/run-tests.mjs .test-build/__tests__/shapeCheck.test.js',
      );
    });

    it('prepublishOnly builds, then runs test:shape', () => {
      assert.equal(
        scripts.prepublishOnly,
        'npm run build && npm run test:shape',
      );
    });

    it('the release workflow runs test:shape after the build', () => {
      const workflow = readFileSync(
        join(REPO_ROOT, '.github', 'workflows', 'release.yml'),
        'utf8',
      );
      const build = workflow.indexOf('run: npm run build\n');
      const shape = workflow.indexOf('run: npm run test:shape\n');
      assert.ok(build >= 0, `${build} >= ${0}`);
      assert.ok(shape > build, `${shape} > ${build}`);
    });

    it('lint:check is Biome alone: it runs no checking script', () => {
      assert.equal(
        scripts['lint:check'],
        'biome check --error-on-warnings src tools/remove.mjs tools/run-tests.mjs tools/node-test-arguments.mjs tools/node-test-arguments.d.mts',
      );
    });
  });
});
