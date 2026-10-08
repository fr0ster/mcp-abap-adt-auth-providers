/**
 * The user's rule (2026-10-06): no built-in timeout on the registry query;
 * the moment's signal reaches `execFile`, so an abort kills the child. Proven
 * on a real process: a stand-in for reg.exe that records its pid and sleeps.
 *
 * Runs on POSIX only (a `/bin/sh` script stands in for reg.exe); skipped on
 * Windows, where the stand-in would have to be a real executable.
 */
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import { queryRegistry } from '../../snc/SncSystem';
import { allowExecutable } from '../helpers/noRealBrowser';

const posix = process.platform !== 'win32';
const describePosix = posix ? describe : describe.skip;

/** Whether a process with this pid still exists. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

async function until(check: () => boolean): Promise<void> {
  while (!check()) await new Promise((resolve) => setImmediate(resolve));
}

describePosix('queryRegistry with a real child process', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snc-reg-'));
  const pidFile = join(dir, 'pid');
  const standIn = join(dir, 'reg.sh');
  writeFileSync(
    standIn,
    `#!/bin/sh\necho $$ > "${pidFile}"\nexec sleep 60\n`,
    'utf8',
  );
  chmodSync(standIn, 0o700);
  // The suite's guard starts only registered programs: this stand-in.
  allowExecutable(standIn);

  it('an abort kills the child: no process is left, the query rejects aborted', async () => {
    const controller = new AbortController();
    const query = queryRegistry(standIn, 'HKLM\\X', 'Y', controller.signal);
    const settled = query.then(
      () => undefined,
      (error: unknown) => error,
    );
    await until(() => {
      try {
        return readFileSync(pidFile, 'utf8').trim() !== '';
      } catch {
        return false;
      }
    });
    const pid = Number(readFileSync(pidFile, 'utf8').trim());
    expect(alive(pid)).toBe(true);
    controller.abort();
    const thrown = await settled;
    expect(isAuthProviderFailure(thrown)).toBe(true);
    expect(readFailure(thrown, 'resolving-snc-library')).toMatchObject({
      kind: 'interactive-login',
      facts: { outcome: 'aborted' },
    });
    await until(() => !alive(pid));
    expect(alive(pid)).toBe(false);
  });
});
