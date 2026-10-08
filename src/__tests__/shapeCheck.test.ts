/**
 * The shape check of the auth error contract, as
 * `lint:check` runs it here — rules 1–8, the base by declaration: its copy is
 * the canonical one, each fixture is refused by exactly its own rule, a
 * conforming provider and this package's own source pass, and every entry of
 * the diagnostic site list is an approved extraction site that is used.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(__dirname, '../..');
const SCRIPT = join(ROOT, 'tools', 'check-provider-shape.mjs');
const RULES = '1,2,3,4,5,6,7,8';
const BASE = './src/auth/AuthProviderBase#AuthProviderBase';
const FIXTURES = 'tools/__fixtures__';
/** Each run type-checks the program: allow it the time it needs. */
const RUN = 60_000;

interface Run {
  status: number | null;
  findings: string[];
  stderr: string;
}

function check(args: string[]): Run {
  const run = spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  const findings = run.stdout
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0);
  return { status: run.status, findings, stderr: run.stderr };
}

function asLintCheck(...files: string[]): Run {
  return check(['--rules', RULES, '--base', BASE, ...files]);
}

/** `<file>:<line>:<column>: rule <n>: …` → `[file, n]`, by plain string reads. */
function located(finding: string): [string, string] {
  const file = finding.slice(0, finding.indexOf(':'));
  const marker = ': rule ';
  const at = finding.indexOf(marker) + marker.length;
  return [file, finding.slice(at, finding.indexOf(':', at))];
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

describe('the shape check', () => {
  it('R1: tools/ holds a byte-identical copy of the one auth-errors publishes', () => {
    const canonical = readFileSync(
      require.resolve(
        '@mcp-abap-adt/auth-errors/tools/check-provider-shape.mjs',
      ),
    );
    expect(readFileSync(SCRIPT).equals(canonical)).toBe(true);
  });

  it('lint:check runs it after Biome, rules 1–8, the base by declaration', () => {
    const manifest = JSON.parse(
      readFileSync(join(ROOT, 'package.json'), 'utf8'),
    ) as { scripts: Record<string, string> };
    const lint = manifest.scripts['lint:check'] ?? '';
    const shape = `node tools/check-provider-shape.mjs --rules ${RULES} --base ${BASE}`;
    expect(lint.endsWith(` && ${shape}`)).toBe(true);
    expect(lint.startsWith('npx biome check')).toBe(true);
  });

  it('the assertion site list is empty: no cast to a contract type anywhere', () => {
    expect(readList('assertion-sites.json')).toStrictEqual([]);
  });

  it('the diagnostic site list names exactly the approved extraction sites', () => {
    const list = readList('diagnostic-sites.json') as {
      file: string;
      function: string;
      field: string;
    }[];
    expect(
      list.map((site) => `${site.file}#${site.function}#${site.field}`).sort(),
    ).toStrictEqual([...APPROVED].sort());
  });

  it(
    'every listed site is used: without the list, each is reported, and nothing else',
    () => {
      const empty = mkdtempSync(join(tmpdir(), 'shape-sites-'));
      try {
        const { status, findings, stderr } = check([
          '--rules',
          '6',
          '--sites',
          empty,
        ]);
        expect(stderr).toBe('');
        expect(status).toBe(1);
        const reported = new Set<string>();
        for (const finding of findings) {
          expect(located(finding)[1]).toBe('6');
          // `… diagnostics (a, b) passed outside … (<file>, <function>)`
          const open =
            finding.indexOf('diagnostics (') + 'diagnostics ('.length;
          const fields = finding.slice(open, finding.indexOf(')', open));
          const site = finding.slice(
            finding.lastIndexOf('(') + 1,
            finding.lastIndexOf(')'),
          );
          const [file, fn] = site.split(', ');
          for (const field of fields.split(', ')) {
            reported.add(`${file}#${fn}#${field}`);
          }
        }
        expect([...reported].sort()).toStrictEqual([...APPROVED].sort());
      } finally {
        rmSync(empty, { recursive: true, force: true });
      }
    },
    RUN,
  );

  it.each([
    ['1', 'rule1.ts', 2],
    ['2', 'rule2.ts', 2],
    ['3', 'rule3.ts', 1],
    ['4', 'rule4.ts', 2],
    ['5', 'rule5.ts', 1],
    ['6', 'rule6.ts', 1],
    ['7', 'rule7.ts', 2],
  ])(
    'rule %s: refuses %s, every finding its own rule',
    (rule, fixture, count) => {
      const file = `${FIXTURES}/${fixture}`;
      const { status, findings, stderr } = asLintCheck(file);

      expect(stderr).toBe('');
      expect(status).toBe(1);
      expect(findings).toHaveLength(count);
      for (const finding of findings) {
        expect(located(finding)).toStrictEqual([file, rule]);
      }
    },
    RUN,
  );

  it(
    'rule 2: a subclass of AuthProviderBase declaring establish is reported',
    () => {
      const { findings } = asLintCheck(`${FIXTURES}/rule2.ts`);
      expect(
        findings.some((finding) =>
          finding.includes(
            'rule 2: a class reaching AuthProviderBase declares establish',
          ),
        ),
      ).toBe(true);
    },
    RUN,
  );

  it(
    'rule 8: a Basic value and a base64 of a client secret in src/auth and src/providers; legacyBasic passes',
    () => {
      const { status, findings, stderr } = check([
        '--rules',
        '8',
        '--root',
        `${FIXTURES}/rule8`,
      ]);

      expect(stderr).toBe('');
      expect(status).toBe(1);
      expect(findings.map(located)).toStrictEqual([
        ['src/auth/basicHeader.ts', '8'],
        ['src/providers/secretBase64.ts', '8'],
      ]);
    },
    RUN,
  );

  it(
    'passes a provider that extends the base and relays a minted refusal',
    () => {
      expect(asLintCheck(`${FIXTURES}/clean.ts`)).toStrictEqual({
        status: 0,
        findings: [],
        stderr: '',
      });
    },
    RUN,
  );

  it(
    "passes this package's own source, as lint:check runs it",
    () => {
      expect(asLintCheck()).toStrictEqual({
        status: 0,
        findings: [],
        stderr: '',
      });
    },
    RUN,
  );
});
