/**
 * Everything SNC discovery asks of the machine, behind one seam, so the rules
 * — which library wins, whether the Secure Login Client's installation holds
 * it — can be tested with a fake. `nodeSncSystem()` is the real one.
 */

import { execFile } from 'node:child_process';
import { open } from 'node:fs/promises';
import { win32 } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);

/** How long `reg query` may take before the value counts as absent. */
const REG_TIMEOUT_MS = 5000;

export interface SncSystem {
  readonly platform: NodeJS.Platform;
  /** `process.arch` — the architecture a library must be built for. */
  readonly arch: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The first `bytes` of a file, or `null` when it cannot be read. */
  readHead(path: string, bytes: number): Promise<Buffer | null>;
  /** A registry value (Windows), or `undefined` when absent or elsewhere. */
  readRegistryValue(key: string, name: string): Promise<string | undefined>;
}

export function parseRegQuery(
  output: string,
  name: string,
): string | undefined {
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s+(\S.*?)\s+REG_\w+\s+(.*?)\s*$/.exec(line);
    if (!match) continue;
    const [, valueName, data] = match;
    if (valueName?.toLowerCase() === name.toLowerCase()) return data;
  }
  return undefined;
}

/** The system's own reg.exe, never whatever PATH finds first. */
function regExe(): string {
  return win32.join(
    process.env.SystemRoot?.trim() || 'C:\\Windows',
    'System32',
    'reg.exe',
  );
}

export function nodeSncSystem(): SncSystem {
  return {
    platform: process.platform,
    arch: process.arch,
    env: process.env,
    async readHead(path, bytes) {
      try {
        const file = await open(path, 'r');
        try {
          const buffer = Buffer.alloc(bytes);
          const { bytesRead } = await file.read(buffer, 0, bytes, 0);
          return buffer.subarray(0, bytesRead);
        } finally {
          await file.close();
        }
      } catch {
        return null;
      }
    },
    async readRegistryValue(key, name) {
      if (process.platform !== 'win32') return undefined;
      try {
        const { stdout } = await run(
          regExe(),
          ['query', key, '/v', name, '/reg:64'],
          { windowsHide: true, timeout: REG_TIMEOUT_MS },
        );
        return parseRegQuery(stdout, name);
      } catch {
        return undefined;
      }
    },
  };
}
