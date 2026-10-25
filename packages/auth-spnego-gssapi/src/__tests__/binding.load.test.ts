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
  'mechanism-unsupported',
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

/**
 * A diagnostic for a mismatch only: the binding called directly, in the same
 * environment, and its raw error message returned — on a CI machine with no
 * ticket it names no secret, and it is the text a missing phrase needs.
 */
function rawBindingMessage(
  mechanism: 'spnego' | 'kerberos',
  env: NodeJS.ProcessEnv,
): string {
  const kerberos = path.resolve(__dirname, '../../node_modules/kerberos');
  const script = `
const k = require(${JSON.stringify(kerberos)});
const oid = ${JSON.stringify(mechanism)} === 'spnego' ? k.GSS_MECH_OID_SPNEGO : k.GSS_MECH_OID_KRB5;
k.initializeClient(process.platform === 'win32' ? 'HTTP/spnego.invalid' : 'HTTP@spnego.invalid', { mechOID: oid })
  .then((c) => c.step(''))
  .then(
    () => process.stderr.write('RAW (a token, no error)\\n'),
    (e) => process.stderr.write('RAW ' + JSON.stringify(String(e && e.message)) + '\\n'),
  );
`;
  const run = spawnSync(process.execPath, ['-e', script], {
    env,
    encoding: 'utf8',
  });
  return (
    run.stderr.split('\n').find((l) => l.startsWith('RAW ')) ??
    `RAW (none; exit ${run.status})`
  );
}

/**
 * What a token is, by bytes alone (this package may not import the
 * provider's `readNegotiateToken` across its rootDir): `ntlm` when
 * `NTLMSSP\0` appears anywhere in it (raw, or as a SPNEGO mechToken),
 * `kerberos` when the Kerberos V5 mechanism OID (1.2.840.113554.1.2.2) does
 * and it is not NTLM, else `other`. Only a classification for a printed
 * measurement on the Windows runner — not a validator.
 */
function classifyToken(token: string): 'ntlm' | 'kerberos' | 'other' {
  const bytes = Buffer.from(token, 'base64');
  if (bytes.includes(Buffer.from('NTLMSSP\0', 'latin1'))) return 'ntlm';
  const krb5 = Buffer.from([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
  ]);
  if (bytes.includes(krb5)) return 'kerberos';
  return 'other';
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
        if (answer.ok) {
          expect(typeof answer.token).toBe('string');
          const kind = classifyToken(answer.token ?? '');
          process.stderr.write(
            `Windows, ${mechanism}: the token is ${kind} (first bytes ${Buffer.from(
              answer.token ?? '',
              'base64',
            )
              .subarray(0, 12)
              .toString('hex')})\n`,
          );
          expect(['ntlm', 'kerberos', 'other']).toContain(kind);
        } else {
          expect(PROBLEMS).toContain(answer.problem);
          expect(answer.problem).not.toBe('binding-unavailable');
          process.stderr.write(
            `Windows, ${mechanism}, no ticket: ${rawBindingMessage(mechanism, { ...process.env })}\n`,
          );
        }
        return;
      }
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gssapi-no-ticket-'));
      try {
        const env = {
          ...process.env,
          KRB5CCNAME: `FILE:${path.join(dir, 'cc')}`,
        };
        const answer = askChild(mechanism, env);
        // macOS (GSS.framework) answers spnego with no ticket by
        // " An unsupported mechanism was requested: unknown mech-code 0 for
        // mech unknown" (measured 2026-10-25).
        const expected =
          process.platform === 'darwin' && mechanism === 'spnego'
            ? { ok: false, problem: 'mechanism-unsupported' }
            : { ok: false, problem: 'no-credential' };
        if (JSON.stringify(answer) !== JSON.stringify(expected))
          process.stderr.write(
            `${process.platform}, ${mechanism}, no ticket: answer ${JSON.stringify(answer)}; binding ${rawBindingMessage(mechanism, env)}\n`,
          );
        expect(answer).toEqual(expected);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});
