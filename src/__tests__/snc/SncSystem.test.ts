import { afterEach, describe, expect, it, jest } from '@jest/globals';

jest.mock('node:child_process', () => ({
  execFile: jest.fn(
    (
      _file: string,
      _args: string[],
      _options: object,
      callback: (error: Error | null, result: { stdout: string }) => void,
    ) => {
      callback(null, {
        stdout:
          '\r\nHKEY_LOCAL_MACHINE\\Software\\SAP\\SecureLogin\r\n    InstallPath64    REG_SZ    C:\\SLC\\\r\n',
      });
    },
  ),
}));

import { execFile } from 'node:child_process';
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
      { timeout?: number },
    ][];
  afterEach(() => {
    if (platform) Object.defineProperty(process, 'platform', platform);
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
    (execFile as unknown as jest.Mock).mockClear();
  });
  const asWindows = () =>
    Object.defineProperty(process, 'platform', { value: 'win32' });

  it('runs reg.exe by absolute path under SystemRoot, with a 5 s timeout', async () => {
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
    expect(options.timeout).toBe(5000);
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
