import { afterEach, describe, expect, it, jest } from '@jest/globals';

jest.mock('node:child_process', () => ({
  execFile: jest.fn(
    (
      _file: string,
      _args: string[],
      options: { signal?: AbortSignal },
      callback: (error: Error | null, result?: { stdout: string }) => void,
    ) => {
      if (options.signal?.aborted) {
        callback(
          Object.assign(new Error('SECRET-ABORT'), { code: 'ABORT_ERR' }),
        );
        return;
      }
      callback(null, {
        stdout:
          '\r\nHKEY_LOCAL_MACHINE\\Software\\SAP\\SecureLogin\r\n    InstallPath64    REG_SZ    C:\\SLC\\\r\n',
      });
    },
  ),
}));

import { execFile } from 'node:child_process';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import { nodeSncSystem, parseRegQuery } from '../../snc/SncSystem';

describe('parseRegQuery', () => {
  const output = [
    '',
    'HKEY_LOCAL_MACHINE\\Software\\SAP\\SecureLogin',
    '    InstallPath64    REG_SZ    C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    '',
  ].join('\r\n');
  it('reads the value, spaces included, name case-insensitive', () => {
    expect(parseRegQuery(output, 'installpath64')).toBe(
      'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    );
  });
  it('RF4: a value ending in spaces and CR/LF is trimmed', () => {
    expect(
      parseRegQuery(
        '\r\nHKEY_LOCAL_MACHINE\\X\r\n    InstallPath64    REG_SZ    C:\\Program Files (x86)\\SLC\\   \r\n\r\n',
        'InstallPath64',
      ),
    ).toBe('C:\\Program Files (x86)\\SLC\\');
  });
  it('a value name with spaces, a LF-only output, an empty value', () => {
    const out =
      '\n    Install Path    REG_EXPAND_SZ    D:\\x\n    Empty    REG_SZ    \n';
    expect(parseRegQuery(out, 'install path')).toBe('D:\\x');
    expect(parseRegQuery(out, 'Empty')).toBe('');
  });
  it('a line not indented, or with no REG_ type, is no value', () => {
    expect(
      parseRegQuery('InstallPath64    REG_SZ    C:\\x', 'InstallPath64'),
    ).toBeUndefined();
    expect(
      parseRegQuery('    InstallPath64    C:\\x', 'InstallPath64'),
    ).toBeUndefined();
    expect(
      parseRegQuery('    InstallPath64    REG_    C:\\x', 'InstallPath64'),
    ).toBeUndefined();
  });
  it('undefined when absent or when reg reports an error', () => {
    expect(parseRegQuery(output, 'InstallPath32')).toBeUndefined();
    expect(
      parseRegQuery(
        'ERROR: The system was unable to find the specified registry key or value.',
        'InstallPath64',
      ),
    ).toBeUndefined();
  });
});

describe('nodeSncSystem reading the registry', () => {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  const systemRoot = process.env.SystemRoot;
  const calls = () =>
    (execFile as unknown as jest.Mock).mock.calls as unknown as [
      string,
      string[],
      { timeout?: number; signal?: AbortSignal; windowsHide?: boolean },
    ][];
  afterEach(() => {
    if (platform) Object.defineProperty(process, 'platform', platform);
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
    (execFile as unknown as jest.Mock).mockClear();
  });
  const asWindows = () =>
    Object.defineProperty(process, 'platform', { value: 'win32' });

  it('runs reg.exe by absolute path under SystemRoot, with no timeout of its own', async () => {
    asWindows();
    process.env.SystemRoot = 'D:\\WinDir';
    const value = await nodeSncSystem().readRegistryValue(
      'HKLM\\Software\\SAP\\SecureLogin',
      'InstallPath64',
    );
    expect(value).toBe('C:\\SLC\\');
    const [file, args, options] = calls()[0]!;
    expect(file).toBe('D:\\WinDir\\System32\\reg.exe');
    expect(args).toEqual([
      'query',
      'HKLM\\Software\\SAP\\SecureLogin',
      '/v',
      'InstallPath64',
      '/reg:64',
    ]);
    // The user's rule: no built-in timeout. Without a signal the query
    // waits for reg.exe; bounding it is the consumer's decision.
    expect(options).toEqual({ windowsHide: true });
    expect(options).not.toHaveProperty('timeout');
  });

  it('passes the signal to execFile, so an abort kills reg.exe', async () => {
    asWindows();
    const controller = new AbortController();
    await nodeSncSystem().readRegistryValue('HKLM\\X', 'Y', controller.signal);
    const [, , options] = calls()[0]!;
    expect(options.signal).toBe(controller.signal);
    expect(options).not.toHaveProperty('timeout');
  });

  it('an aborted query rejects aborted — never the child’s text', async () => {
    asWindows();
    const controller = new AbortController();
    controller.abort();
    const thrown = await nodeSncSystem()
      .readRegistryValue('HKLM\\X', 'Y', controller.signal)
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    expect(isAuthProviderFailure(thrown)).toBe(true);
    expect(readFailure(thrown, 'resolving-snc-library')).toMatchObject({
      kind: 'interactive-login',
      facts: { outcome: 'aborted' },
    });
    expect(JSON.stringify(thrown)).not.toContain('SECRET');
  });

  it('falls back to C:\\Windows without SystemRoot', async () => {
    asWindows();
    delete process.env.SystemRoot;
    await nodeSncSystem().readRegistryValue('HKLM\\X', 'Y');
    expect(calls()[0]![0]).toBe('C:\\Windows\\System32\\reg.exe');
  });

  it('has no process listing', () => {
    expect('listProcessNames' in nodeSncSystem()).toBe(false);
  });
});
