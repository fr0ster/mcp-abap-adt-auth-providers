/**
 * `node:child_process`'s `execFile` replaced for the whole test file by a
 * plain `mock.fn`, before `SncSystem` loads (what was its jest.mock).
 * `SncSystem` captures `promisify(execFile)` when it loads, so neither
 * `mock.method` (its proxy hands promisify the real `execFile`'s
 * `promisify.custom`) nor a later assignment reaches it (measured in plan
 * step 1). Import it for its effect FIRST:
 *
 *     import '../helpers/sncExecFileMock';
 *
 * The fake answers reg.exe's output for InstallPath64, and an aborted
 * signal with an `ABORT_ERR` carrying a secret in its message.
 */

import { after, mock } from 'node:test';

import childProcess = require('node:child_process');

/** What the fake answers: reg.exe's output, or an abort. */
export const execFileMock = mock.fn(
  (
    _file: string,
    _args: string[],
    options: { signal?: AbortSignal; timeout?: number; windowsHide?: boolean },
    callback: (error: Error | null, result?: { stdout: string }) => void,
  ): void => {
    if (options.signal?.aborted) {
      callback(Object.assign(new Error('SECRET-ABORT'), { code: 'ABORT_ERR' }));
      return;
    }
    callback(null, {
      stdout:
        '\r\nHKEY_LOCAL_MACHINE\\Software\\SAP\\SecureLogin\r\n    InstallPath64    REG_SZ    C:\\SLC\\\r\n',
    });
  },
);

const real = childProcess.execFile;
Reflect.set(childProcess, 'execFile', execFileMock);
after(() => {
  Reflect.set(childProcess, 'execFile', real);
});
