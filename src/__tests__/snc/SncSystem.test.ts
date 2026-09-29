import { describe, expect, it } from '@jest/globals';
import {
  parsePsComm,
  parseRegQuery,
  parseTasklistCsv,
} from '../../snc/SncSystem';

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

describe('parseTasklistCsv', () => {
  it('takes the image name from each line', () => {
    expect(
      parseTasklistCsv(
        '"System Idle Process","0","Services","0","8 K"\r\n"sbus.exe","4","Console","1","1 K"\r\n',
      ),
    ).toEqual(['System Idle Process', 'sbus.exe']);
  });
});

describe('parsePsComm', () => {
  it('drops the header and blank lines', () => {
    expect(
      parsePsComm(
        'COMM\n/sbin/launchd\n/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client\n\n',
      ),
    ).toEqual([
      '/sbin/launchd',
      '/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client',
    ]);
  });
});
