/**
 * The pin of SncSystem's execFile mock (helpers/sncExecFileMock.ts): a plain
 * `mock.fn` assigned to `child_process.execFile` before SncSystem loads is
 * what its captured `promisify(execFile)` calls — and only because it is in
 * place first.
 */

import '../helpers/sncExecFileMock';
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { queryRegistry } from '../../snc/SncSystem';
import { execFileMock } from '../helpers/sncExecFileMock';

it('SncSystem runs the mocked execFile and reads its stdout', async () => {
  const stdout = await queryRegistry(
    '/nonexistent/reg.exe',
    'HKLM\\Software\\SAP\\SecureLogin',
    'InstallPath64',
  );
  assert.equal(execFileMock.mock.callCount(), 1);
  assert.equal(
    execFileMock.mock.calls[0]?.arguments[0],
    '/nonexistent/reg.exe',
  );
  assert.ok(stdout?.includes('InstallPath64'), String(stdout));
});
