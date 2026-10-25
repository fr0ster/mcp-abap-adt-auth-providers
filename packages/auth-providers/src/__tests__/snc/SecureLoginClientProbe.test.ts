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

describe('the probe names, it does not check', () => {
  it('has no check()', () => {
    const probe = new SecureLoginClientProbe(fakeSystem());
    expect(probe.product).toBe('SAP Secure Login Client');
    expect('check' in probe).toBe(false);
  });
});

describe('the moment’s signal', () => {
  it('reaches each registry read', async () => {
    const reads: { key: string; name: string; signal?: AbortSignal }[] = [];
    const controller = new AbortController();
    await new SecureLoginClientProbe(
      fakeSystem({ registry: REGISTRY, registryReads: reads }),
    ).appliesTo('C:\\x\\sapcrypto.dll', controller.signal);
    expect(reads.map((r) => [r.name, r.signal])).toEqual([
      ['InstallPath64', controller.signal],
      ['InstallPath32', controller.signal],
    ]);
  });
});
