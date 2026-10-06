/**
 * Everything SNC discovery asks of the machine, behind one seam, so the rules
 * — which library wins, whether the Secure Login Client's installation holds
 * it — can be tested with a fake. `nodeSncSystem()` is the real one.
 *
 * No timer of this package's choosing (the user's rule): the registry query
 * runs until `reg.exe` answers, or until the signal it is given aborts — the
 * abort kills the child. Bounding it is the consumer's decision.
 */

import { execFile } from 'node:child_process';
import { open } from 'node:fs/promises';
import { win32 } from 'node:path';
import { promisify } from 'node:util';
import { abortedFailure } from '../auth/attempt';

const run = promisify(execFile);

export interface SncSystem {
  readonly platform: NodeJS.Platform;
  /** `process.arch` — the architecture a library must be built for. */
  readonly arch: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The first `bytes` of a file, or `null` when it cannot be read. */
  readHead(path: string, bytes: number): Promise<Buffer | null>;
  /**
   * A registry value (Windows), or `undefined` when absent or elsewhere.
   * `signal`, when given, ends the read: an aborted one rejects with an
   * `AuthProviderFailure` of `interactive-login` `aborted`.
   */
  readRegistryValue(
    key: string,
    name: string,
    signal?: AbortSignal,
  ): Promise<string | undefined>;
}

/** Whitespace as `reg.exe` writes it between and around its columns. */
function isSpace(char: string | undefined): boolean {
  return (
    char === ' ' ||
    char === '\t' ||
    char === '\r' ||
    char === '\n' ||
    char === '\v' ||
    char === '\f'
  );
}

/** A character of a `REG_*` type name: a letter, a digit or `_`. */
function isTypeChar(char: string | undefined): boolean {
  if (char === undefined) return false;
  return (
    (char >= 'A' && char <= 'Z') ||
    (char >= 'a' && char <= 'z') ||
    (char >= '0' && char <= '9') ||
    char === '_'
  );
}

/**
 * One value line of `reg query` — `    <name>    REG_<TYPE>    <data>` — as
 * its name and its data, trimmed; `undefined` for any other line. Plain code:
 * the output is read, never matched by a regular expression.
 */
function valueLine(line: string): { name: string; data: string } | undefined {
  if (!isSpace(line[0])) return undefined;
  const body = line.trim();
  // The type column: the first `REG_` preceded by whitespace, followed by
  // its name characters and then whitespace (or the line's end, no data).
  for (
    let at = body.indexOf('REG_');
    at !== -1;
    at = body.indexOf('REG_', at + 1)
  ) {
    // At 0 it is the value's name (`REG_…`), not its type column.
    if (at === 0 || !isSpace(body[at - 1])) continue;
    let end = at + 4;
    while (isTypeChar(body[end])) end++;
    if (end === at + 4) continue;
    if (end < body.length && !isSpace(body[end])) continue;
    const name = body.slice(0, at).trim();
    if (name === '') return undefined;
    return { name, data: body.slice(end).trim() };
  }
  return undefined;
}

/**
 * The data of value `name` in `reg query` output, trimmed — a value ending in
 * spaces or a CR/LF would otherwise reach a candidate path (RF4).
 */
export function parseRegQuery(
  output: string,
  name: string,
): string | undefined {
  const wanted = name.toLowerCase();
  for (const line of output.split('\n')) {
    const value = valueLine(line);
    if (value && value.name.toLowerCase() === wanted) return value.data;
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

/**
 * Runs `<exe> query <key> /v <name> /reg:64` with no shell and no timeout;
 * its standard output, or `undefined` when it fails. An abort of `signal`
 * kills the child and rejects `aborted`.
 */
export async function queryRegistry(
  exe: string,
  key: string,
  name: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  try {
    const { stdout } = await run(exe, ['query', key, '/v', name, '/reg:64'], {
      windowsHide: true,
      ...(signal === undefined ? {} : { signal }),
    });
    return stdout;
  } catch {
    // Whatever the child or execFile said stays here: an abort is the
    // consumer's, anything else reads as an absent value.
    if (signal?.aborted) throw abortedFailure();
    return undefined;
  }
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
    async readRegistryValue(key, name, signal) {
      if (process.platform !== 'win32') return undefined;
      const stdout = await queryRegistry(regExe(), key, name, signal);
      return stdout === undefined ? undefined : parseRegQuery(stdout, name);
    },
  };
}
