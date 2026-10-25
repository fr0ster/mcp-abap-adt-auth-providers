// The real binding, built from source, loaded by the built package (dist/) in
// a child node process — a machine with no ticket.
//
// Where it runs: CI's `auth-spnego-gssapi` job (Linux, macOS, Windows; x64),
// after `npm rebuild kerberos --build-from-source` and `npm run build`, with
// KERBEROS_BINDING=built. Anywhere else the binding is not built (installs run
// with --ignore-scripts), so the test is skipped and says why.
//
// Linux and macOS: KRB5CCNAME points at a cache file that does not exist, in
// a fresh temporary directory, so the process has no ticket → `no-credential`.
// Windows: the runner is joined to no domain; what SSPI answers there is To
// measure — the test requires only that the binding loaded and that the
// answer is one of the contract's, and prints it.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from '@jest/globals';

const BUILT = process.env.KERBEROS_BINDING === 'built';
const PROBLEMS = [
  'no-credential',
  'service-unknown',
  'kdc-unreachable',
  'clock-skew',
  'binding-unavailable',
  'source-failed',
];

const describeBuilt = BUILT ? describe : describe.skip;
const where = BUILT
  ? 'the built kerberos binding'
  : 'the built kerberos binding — skipped: KERBEROS_BINDING=built is not set (CI auth-spnego-gssapi job only)';

function askChild(
  mechanism: 'spnego' | 'kerberos',
  env: NodeJS.ProcessEnv,
): unknown {
  const entry = path.resolve(__dirname, '../../dist/index.js');
  const script = `
const { gssapiTokenSource } = require(${JSON.stringify(entry)});
gssapiTokenSource({ mechanism: ${JSON.stringify(mechanism)} })
  .token('HTTP@spnego.invalid', {})
  .then((answer) => process.stderr.write('ANSWER ' + JSON.stringify(answer) + '\\n'));
`;
  const run = spawnSync(process.execPath, ['-e', script], {
    env,
    encoding: 'utf8',
  });
  expect(run.status).toBe(0);
  expect(run.stdout).toBe('');
  const line = run.stderr.split('\n').find((l) => l.startsWith('ANSWER '));
  expect(line).toBeDefined();
  return JSON.parse((line ?? '').slice('ANSWER '.length));
}

describeBuilt(where, () => {
  it.each(['spnego', 'kerberos'] as const)(
    '%s: a machine with no ticket gets no token',
    (mechanism) => {
      if (process.platform === 'win32') {
        const answer = askChild(mechanism, { ...process.env }) as {
          ok: boolean;
          problem?: string;
          token?: string;
        };
        process.stderr.write(
          `Windows, ${mechanism}: ${answer.ok ? `ok, a token of ${answer.token?.length} chars` : `problem ${answer.problem}`}\n`,
        );
        if (answer.ok) expect(typeof answer.token).toBe('string');
        else {
          expect(PROBLEMS).toContain(answer.problem);
          expect(answer.problem).not.toBe('binding-unavailable');
        }
        return;
      }
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gssapi-no-ticket-'));
      try {
        const answer = askChild(mechanism, {
          ...process.env,
          KRB5CCNAME: `FILE:${path.join(dir, 'cc')}`,
        });
        expect(answer).toEqual({ ok: false, problem: 'no-credential' });
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});
