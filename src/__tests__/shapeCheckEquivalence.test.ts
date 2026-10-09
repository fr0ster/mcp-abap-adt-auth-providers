/**
 * Transitional: the shape check run through auth-errors' module decides
 * exactly what the script it replaces decided. `tools/check-provider-shape.mjs`
 * is that script (the 2.1.1 file, its hash asserted; it is self-contained, so
 * it still runs with a newer auth-errors installed). On every entry of the
 * matrix it is compared with `reportLines` of the module on the same options,
 * and with the installed command (status, stdout and stderr byte for byte).
 * Deleted together with the script once the comparison has run green.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  checkProviderShape,
  reportLines,
  type ShapeCheckOptions,
  type ShapeCheckReport,
} from '@mcp-abap-adt/auth-errors/shape-check';
import * as typescript from 'typescript';

const ROOT = resolve(__dirname, '../..');
const SCRIPT = join(ROOT, 'tools', 'check-provider-shape.mjs');
const SCRIPT_SHA256 =
  '681d8cbdc6177d2436955e172d9aded58ea67e8b9a604d1fbaf1f81c70715603';
const INSTALLED = require.resolve(
  '@mcp-abap-adt/auth-errors/tools/check-provider-shape.mjs',
);
const FIXTURES = 'tools/__fixtures__';
const RULE8_ROOT = join(ROOT, FIXTURES, 'rule8');
const BASE = './src/auth/AuthProviderBase#AuthProviderBase';
const ALL = [1, 2, 3, 4, 5, 6, 7, 8] as const;
const RUN = 180_000;

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

function run(command: string, args: readonly string[]): Run {
  const child = spawnSync(process.execPath, [command, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  return { status: child.status, stdout: child.stdout, stderr: child.stderr };
}

/** The script's lines: what it printed, one finding a line. */
function lines(text: string): string[] {
  return text.split('\n').filter((line) => line.length > 0);
}

/** The script's run and the module's report decide the same. */
function expectSame(script: Run, report: ShapeCheckReport): void {
  switch (report.status) {
    case 'checked':
      expect(script.stderr).toBe('');
      expect(script.status).toBe(report.findings.length === 0 ? 0 : 1);
      expect(lines(script.stdout)).toEqual(reportLines(report));
      return;
    case 'usage-error':
      expect(script.status).toBe(2);
      expect(script.stdout).toBe('');
      expect(script.stderr.startsWith(`${report.message}\n`)).toBe(true);
      return;
    case 'type-errors':
      expect(script.status).toBe(2);
      expect(script.stdout).toBe('');
      expect(script.stderr).toBe(
        `the shape check needs a program that type-checks:\n${report.diagnostics}`,
      );
      return;
  }
}

const emptySites = mkdtempSync(join(tmpdir(), 'shape-equivalence-sites-'));
afterAll(() => rmSync(emptySites, { recursive: true, force: true }));

const configured: ShapeCheckOptions = {
  typescript,
  rules: ALL,
  root: ROOT,
  project: join(ROOT, 'tsconfig.json'),
  sites: join(ROOT, 'tools'),
  base: BASE,
};

/** Each entry: the command's arguments and the module's options. */
const MATRIX: readonly (readonly [
  string,
  readonly string[],
  ShapeCheckOptions,
])[] = [
  [
    'own tree as configured',
    ['--rules', ALL.join(','), '--base', BASE],
    configured,
  ],
  [
    'own tree, rule 6, an empty sites directory',
    ['--rules', '6', '--sites', emptySites],
    { ...configured, rules: [6], sites: emptySites, base: undefined },
  ],
  [
    'own tree, rules 1–8, an empty sites directory',
    ['--rules', ALL.join(','), '--base', BASE, '--sites', emptySites],
    { ...configured, sites: emptySites },
  ],
  ...[
    'rule1.ts',
    'rule2.ts',
    'rule3.ts',
    'rule4.ts',
    'rule5.ts',
    'rule6.ts',
    'rule7.ts',
    'clean.ts',
  ].map(
    (fixture) =>
      [
        `${fixture} as configured`,
        ['--rules', ALL.join(','), '--base', BASE, `${FIXTURES}/${fixture}`],
        { ...configured, files: [join(ROOT, FIXTURES, fixture)] },
      ] as const,
  ),
  [
    'the rule-8 tree, rule 8',
    ['--rules', '8', '--root', `${FIXTURES}/rule8`],
    {
      typescript,
      rules: [8],
      root: RULE8_ROOT,
      project: join(RULE8_ROOT, 'tsconfig.json'),
      sites: null,
    },
  ],
];

/** The entries whose module report had findings, filled as they run. */
const reporting: string[] = [];

describe('the module decides what the 2.1.1 script decided', () => {
  it('tools/ holds the 2.1.1 script', () => {
    expect(
      createHash('sha256').update(readFileSync(SCRIPT)).digest('hex'),
    ).toBe(SCRIPT_SHA256);
  });

  it('the installed command is not that script', () => {
    expect(readFileSync(INSTALLED).equals(readFileSync(SCRIPT))).toBe(false);
  });

  it.each(MATRIX)(
    '%s',
    (_name, args, options) => {
      const script = run(SCRIPT, args);
      const report = checkProviderShape(options);
      if (report.status === 'checked' && report.findings.length > 0) {
        reporting.push(_name);
      }
      expectSame(script, report);
      expect(run(INSTALLED, args)).toStrictEqual(script);
    },
    RUN,
  );

  it('the matrix compared findings, not only clean runs', () => {
    // every entry but the configured tree and clean.ts reports something
    expect(reporting).toHaveLength(MATRIX.length - 2);
  });
});
