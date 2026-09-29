/**
 * Everything SNC discovery asks of the machine, behind one seam, so the rules
 * — which library wins, when the Secure Login Client is checked — can be
 * tested with a fake. `nodeSncSystem()` is the real one.
 */

import { execFile } from 'node:child_process';
import { open } from 'node:fs/promises';
import { promisify } from 'node:util';

const run = promisify(execFile);

export interface SncSystem {
  readonly platform: NodeJS.Platform;
  /** `process.arch` — the architecture a library must be built for. */
  readonly arch: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The first `bytes` of a file, or `null` when it cannot be read. */
  readHead(path: string, bytes: number): Promise<Buffer | null>;
  /** A registry value (Windows), or `undefined` when absent or elsewhere. */
  readRegistryValue(key: string, name: string): Promise<string | undefined>;
  /** Running processes' names or paths. Throws when they cannot be listed. */
  listProcessNames(): Promise<string[]>;
}

export function parseRegQuery(
  output: string,
  name: string,
): string | undefined {
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s+(\S.*?)\s+REG_\w+\s+(.*?)\s*$/.exec(line);
    if (match && match[1].toLowerCase() === name.toLowerCase()) return match[2];
  }
  return undefined;
}

export function parseTasklistCsv(output: string): string[] {
  return output
    .split(/\r?\n/)
    .map((line) => /^"([^"]*)"/.exec(line)?.[1])
    .filter((name): name is string => Boolean(name));
}

export function parsePsComm(output: string): string[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && line !== 'COMM');
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
          'reg',
          ['query', key, '/v', name, '/reg:64'],
          { windowsHide: true },
        );
        return parseRegQuery(stdout, name);
      } catch {
        return undefined;
      }
    },
    async listProcessNames() {
      if (process.platform === 'win32') {
        const { stdout } = await run('tasklist', ['/FO', 'CSV', '/NH'], {
          windowsHide: true,
        });
        return parseTasklistCsv(stdout);
      }
      const { stdout } = await run('ps', ['-Ao', 'comm']);
      return parsePsComm(stdout);
    },
  };
}
