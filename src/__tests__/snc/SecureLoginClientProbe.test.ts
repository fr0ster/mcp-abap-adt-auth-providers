import { describe, expect, it } from '@jest/globals';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { fakeSystem } from './fakeSystem';

const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath32':
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\',
};

describe('appliesTo', () => {
  const probe = new SecureLoginClientProbe(fakeSystem({ registry: REGISTRY }));
  it.each([
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\PROGRAM FILES\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
  ])('applies to %s', async (p) => {
    await expect(probe.appliesTo(p)).resolves.toBe(true);
  });
  it.each([
    'C:\\Windows\\System32\\gsskrb5.dll',
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLoginOther\\sapcrypto.dll',
  ])('not to %s', async (p) => {
    await expect(probe.appliesTo(p)).resolves.toBe(false);
  });
  it('to nothing when the client is not installed', async () => {
    await expect(
      new SecureLoginClientProbe(fakeSystem()).appliesTo(
        'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
      ),
    ).resolves.toBe(false);
  });
  it('to the app bundle on macOS', async () => {
    const mac = new SecureLoginClientProbe(fakeSystem({ platform: 'darwin' }));
    await expect(
      mac.appliesTo(
        '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib',
      ),
    ).resolves.toBe(true);
    await expect(mac.appliesTo('/usr/lib/libgssapi_krb5.dylib')).resolves.toBe(
      false,
    );
  });
});

describe('check', () => {
  it('passes when sbus.exe runs, any case', async () => {
    await expect(
      new SecureLoginClientProbe(
        fakeSystem({ processes: ['SBUS.EXE'] }),
      ).check(),
    ).resolves.toBeUndefined();
  });
  it('fails when only sbusagent.exe runs', async () => {
    await expect(
      new SecureLoginClientProbe(
        fakeSystem({ processes: ['sbusagent.exe'] }),
      ).check(),
    ).rejects.toThrow(/not running .*sbus\.exe/);
  });
  it('an unreadable process list says the check could not run, without the tool’s message', async () => {
    const error = await new SecureLoginClientProbe(
      fakeSystem({ processes: new Error('access denied SECRET-TOOL') }),
    )
      .check()
      .catch((e: unknown) => e);
    expect((error as Error).message).toMatch(
      /Could not check whether the SAP Secure Login Client is running/,
    );
    expect((error as Error).message).not.toMatch(/SECRET-TOOL/);
  });
  it('macOS looks for the app bundle', async () => {
    await expect(
      new SecureLoginClientProbe(
        fakeSystem({
          platform: 'darwin',
          processes: [
            '/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client',
          ],
        }),
      ).check(),
    ).resolves.toBeUndefined();
    await expect(
      new SecureLoginClientProbe(
        fakeSystem({ platform: 'darwin', processes: ['/sbin/launchd'] }),
      ).check(),
    ).rejects.toThrow(/not running/);
  });
});
