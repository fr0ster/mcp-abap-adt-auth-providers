import '../helpers/sncExecFileMock';

import assert from 'node:assert/strict';
import { afterEach, describe, it, mock } from 'node:test';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import { nodeSncSystem, parseRegQuery } from '../../snc/SncSystem';
import { hasProperty, matchObject, notContains } from '../helpers/expectations';
import { clearMock } from '../helpers/mockOnce';
import { execFileMock } from '../helpers/sncExecFileMock';

describe('parseRegQuery', () => {
  const output = [
    '',
    'HKEY_LOCAL_MACHINE\\Software\\SAP\\SecureLogin',
    '    InstallPath64    REG_SZ    C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    '',
  ].join('\r\n');
  it('reads the value, spaces included, name case-insensitive', () => {
    assert.equal(
      parseRegQuery(output, 'installpath64'),
      'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    );
  });
  it('RF4: a value ending in spaces and CR/LF is trimmed', () => {
    assert.equal(
      parseRegQuery(
        '\r\nHKEY_LOCAL_MACHINE\\X\r\n    InstallPath64    REG_SZ    C:\\Program Files (x86)\\SLC\\   \r\n\r\n',
        'InstallPath64',
      ),
      'C:\\Program Files (x86)\\SLC\\',
    );
  });
  it('a value name with spaces, a LF-only output, an empty value', () => {
    const out =
      '\n    Install Path    REG_EXPAND_SZ    D:\\x\n    Empty    REG_SZ    \n';
    assert.equal(parseRegQuery(out, 'install path'), 'D:\\x');
    assert.equal(parseRegQuery(out, 'Empty'), '');
  });
  it('a value whose name begins with REG_ is still found', () => {
    assert.equal(
      parseRegQuery(
        '\r\nHKEY_LOCAL_MACHINE\\X\r\n    REG_PATH    REG_SZ    C:\\x\r\n',
        'REG_PATH',
      ),
      'C:\\x',
    );
  });
  it('a line not indented, or with no REG_ type, is no value', () => {
    assert.equal(
      parseRegQuery('InstallPath64    REG_SZ    C:\\x', 'InstallPath64'),
      undefined,
    );
    assert.equal(
      parseRegQuery('    InstallPath64    C:\\x', 'InstallPath64'),
      undefined,
    );
    assert.equal(
      parseRegQuery('    InstallPath64    REG_    C:\\x', 'InstallPath64'),
      undefined,
    );
  });
  it('undefined when absent or when reg reports an error', () => {
    assert.equal(parseRegQuery(output, 'InstallPath32'), undefined);
    assert.equal(
      parseRegQuery(
        'ERROR: The system was unable to find the specified registry key or value.',
        'InstallPath64',
      ),
      undefined,
    );
  });
});

describe('nodeSncSystem reading the registry', () => {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  const systemRoot = process.env.SystemRoot;
  const calls = () => execFileMock.mock.calls.map((call) => call.arguments);
  afterEach(() => {
    if (platform) Object.defineProperty(process, 'platform', platform);
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
    clearMock(execFileMock);
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
    assert.equal(value, 'C:\\SLC\\');
    const [file, args, options] = calls()[0]!;
    assert.equal(file, 'D:\\WinDir\\System32\\reg.exe');
    assert.deepEqual(args, [
      'query',
      'HKLM\\Software\\SAP\\SecureLogin',
      '/v',
      'InstallPath64',
      '/reg:64',
    ]);
    // The user's rule: no built-in timeout. Without a signal the query
    // waits for reg.exe; bounding it is the consumer's decision.
    assert.deepEqual(options, { windowsHide: true });
    assert.equal(hasProperty(options, 'timeout'), false);
  });

  it('passes the signal to execFile, so an abort kills reg.exe', async () => {
    asWindows();
    const controller = new AbortController();
    await nodeSncSystem().readRegistryValue('HKLM\\X', 'Y', controller.signal);
    const [, , options] = calls()[0]!;
    assert.equal(options.signal, controller.signal);
    assert.equal(hasProperty(options, 'timeout'), false);
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
    assert.equal(isAuthProviderFailure(thrown), true);
    matchObject(readFailure(thrown, 'resolving-snc-library'), {
      kind: 'interactive-login',
      facts: { outcome: 'aborted' },
    });
    notContains(JSON.stringify(thrown), 'SECRET');
  });

  it('falls back to C:\\Windows without SystemRoot', async () => {
    asWindows();
    delete process.env.SystemRoot;
    await nodeSncSystem().readRegistryValue('HKLM\\X', 'Y');
    assert.equal(calls()[0]![0], 'C:\\Windows\\System32\\reg.exe');
  });

  it('has no process listing', () => {
    assert.equal('listProcessNames' in nodeSncSystem(), false);
  });
});
