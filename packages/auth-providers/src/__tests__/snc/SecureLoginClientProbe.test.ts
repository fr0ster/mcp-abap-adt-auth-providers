import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { caseTitle } from '../helpers/expectations';
import { fakeSystem } from './fakeSystem';

const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath32':
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\',
};

describe('appliesTo', () => {
  const probe = new SecureLoginClientProbe(fakeSystem({ registry: REGISTRY }));
  for (const [caseIndex, caseRow] of [
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\PROGRAM FILES\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
  ].entries()) {
    const p = caseRow;
    it(caseTitle('applies to %s', caseRow, caseIndex), async () => {
      assert.equal(await probe.appliesTo(p), true);
    });
  }
  for (const [caseIndex, caseRow] of [
    'C:\\Windows\\System32\\gsskrb5.dll',
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLoginOther\\sapcrypto.dll',
  ].entries()) {
    const p = caseRow;
    it(caseTitle('not to %s', caseRow, caseIndex), async () => {
      assert.equal(await probe.appliesTo(p), false);
    });
  }
  it('to nothing when the client is not installed', async () => {
    assert.equal(
      await new SecureLoginClientProbe(fakeSystem()).appliesTo(
        'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
      ),
      false,
    );
  });
  it('to the app bundle on macOS', async () => {
    const mac = new SecureLoginClientProbe(fakeSystem({ platform: 'darwin' }));
    assert.equal(
      await mac.appliesTo(
        '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib',
      ),
      true,
    );
    assert.equal(await mac.appliesTo('/usr/lib/libgssapi_krb5.dylib'), false);
  });
});

describe('the probe names, it does not check', () => {
  it('has no check()', () => {
    const probe = new SecureLoginClientProbe(fakeSystem());
    assert.equal(probe.product, 'SAP Secure Login Client');
    assert.equal('check' in probe, false);
  });
});

describe('the moment’s signal', () => {
  it('reaches each registry read', async () => {
    const reads: { key: string; name: string; signal?: AbortSignal }[] = [];
    const controller = new AbortController();
    await new SecureLoginClientProbe(
      fakeSystem({ registry: REGISTRY, registryReads: reads }),
    ).appliesTo('C:\\x\\sapcrypto.dll', controller.signal);
    assert.deepEqual(
      reads.map((r) => [r.name, r.signal]),
      [
        ['InstallPath64', controller.signal],
        ['InstallPath32', controller.signal],
      ],
    );
  });
});
