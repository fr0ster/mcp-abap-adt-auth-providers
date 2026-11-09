import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, mock } from 'node:test';
import type { ITokenRefresher } from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { FileCertificateMaterialLoader } from '../../credentials/FileCertificateMaterialLoader';
import { SamlAuthProvider } from '../../credentials/SamlAuthProvider';
import { TokenAuthProvider } from '../../credentials/TokenAuthProvider';
import { matchObject, notContains } from '../helpers/expectations';
import { configurationOf, thrownFrom, wordsOf } from '../helpers/minted';
import { CERTIFICATES } from '../helpers/packagePaths';
import { recordingTargets } from '../helpers/targets';

const refusal = { at: 'request' as const, status: 401, error: {} };
const fixture = (name: string) => readFileSync(join(CERTIFICATES, name));
const broken = () => recordingTargets({ throws: true });

describe('BasicAuthProvider', () => {
  const p = new BasicAuthProvider('USER', 'S3CRET-PW');

  it('writes the header and offers user/passwd to the logon', async () => {
    const t = recordingTargets();
    assert.deepEqual(await p.establish(t.logonTarget), { ok: true });
    assert.deepEqual(await p.authorize(t.requestTarget), { ok: true });
    assert.deepEqual(t.logon.params, [{ user: 'USER', passwd: 'S3CRET-PW' }]);
    assert.equal(
      t.request.headers.Authorization,
      `Basic ${Buffer.from('USER:S3CRET-PW').toString('base64')}`,
    );
  });

  it('an untyped caller without user or password sends empty ones, never "undefined"', async () => {
    const t = recordingTargets();
    await new BasicAuthProvider(
      undefined as never,
      undefined as never,
    ).authorize(t.requestTarget);
    assert.equal(
      t.request.headers.Authorization,
      `Basic ${Buffer.from(':').toString('base64')}`,
    );
  });

  it('goes on when the wire takes no logon parameters (HTTP)', async () => {
    assert.deepEqual(
      await p.establish(
        recordingTargets({ acceptsLogonParameters: false }).logonTarget,
      ),
      { ok: true },
    );
  });

  it('a throwing target is an Oops without the password', async () => {
    for (const outcome of [
      await p.establish(broken().logonTarget),
      await p.authorize(broken().requestTarget),
    ]) {
      matchObject(outcome, { ok: false });
      assert.doesNotMatch(
        JSON.stringify(outcome),
        /S3CRET-PW|SECRET-IN-TARGET/,
      );
    }
  });

  it('rejected is an Oops without the password', async () => {
    const outcome = await p.rejected(refusal);
    matchObject(outcome, {
      ok: false,
      refusal: { reason: 'the user or password was refused' },
    });
    assert.doesNotMatch(JSON.stringify(outcome), /S3CRET-PW/);
  });
});

describe('SamlAuthProvider', () => {
  const p = new SamlAuthProvider('MYSAPSSO2=SECRET-COOKIE');

  it('writes the cookies', async () => {
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    assert.deepEqual(t.request.cookies, ['MYSAPSSO2=SECRET-COOKIE']);
  });

  it('a throwing target and rejected are Oops without the cookie', async () => {
    for (const outcome of [
      await p.authorize(broken().requestTarget),
      await p.rejected(refusal),
    ]) {
      assert.equal(outcome.ok, false);
      assert.doesNotMatch(JSON.stringify(outcome), /SECRET-COOKIE/);
    }
  });
});

describe('TokenAuthProvider', () => {
  it('fixed: bearer, and rejected is an Oops without the token', async () => {
    const p = TokenAuthProvider.fixed('SECRET-T');
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    assert.equal(t.request.headers.Authorization, 'Bearer SECRET-T');
    const outcome = await p.rejected(refusal);
    matchObject(outcome, {
      ok: false,
      refusal: { hint: 'obtain a new token' },
    });
    assert.doesNotMatch(JSON.stringify(outcome), /SECRET-T/);
  });

  it('from(refresher): getToken per attempt, refreshToken once, Ok on a new token', async () => {
    const getToken = mock.fn(async () => 'A');
    const refreshToken = mock.fn(async () => 'B');
    const refresher: ITokenRefresher = { getToken, refreshToken };
    const p = TokenAuthProvider.from(refresher);
    await p.authorize(recordingTargets().requestTarget);
    assert.deepEqual(await p.rejected(refusal), { ok: true });
    assert.equal(getToken.mock.callCount(), 1);
    assert.equal(refreshToken.mock.callCount(), 1);
  });

  it('from(refresher): a renewal returning the refused token is an Oops', async () => {
    const p = TokenAuthProvider.from({
      getToken: async () => 'unchanged',
      refreshToken: async () => 'unchanged',
    });
    await p.authorize(recordingTargets().requestTarget);
    matchObject(await p.rejected(refusal), {
      ok: false,
      refusal: {
        reason: 'the renewal returned the credential that was refused',
      },
    });
  });

  it('from(refresher): a refresher error with a secret in its message stays out', async () => {
    const p = TokenAuthProvider.from({
      getToken: async () => {
        throw new Error('token rejected: SECRET-OPAQUE');
      },
      refreshToken: async () => {
        throw new Error('refresh failed for SECRET-REFRESH');
      },
    });
    for (const outcome of [
      await p.authorize(recordingTargets().requestTarget),
      await p.rejected(refusal),
    ]) {
      matchObject(outcome, {
        ok: false,
        refusal: { reason: 'the token source failed (unknown error)' },
      });
      assert.doesNotMatch(JSON.stringify(outcome), /SECRET/);
    }
  });
});

describe('CertificateAuthProvider', () => {
  const config = { url: 'https://h', authType: 'certificate' } as ISapConfig;

  it('prepare loads, establish hands the material to the logon', async () => {
    const cert = fixture('client.crt');
    const key = fixture('client.key');
    const p = new CertificateAuthProvider(
      { load: async () => ({ cert, key }) },
      config,
    );
    assert.deepEqual(await p.prepare(), { ok: true });
    const t = recordingTargets();
    assert.deepEqual(await p.establish(t.logonTarget), { ok: true });
    assert.deepEqual(t.logon.tls, [{ cert, key }]);
  });

  it("the loader's configuration failure is the refusal; a foreign one gives its code only", async () => {
    const own = new CertificateAuthProvider(
      new FileCertificateMaterialLoader(),
      { ...config, certPath: 'SECRET-PATH', certPfxPath: 'SECRET-PFX' },
    );
    // The loader's configuration case, once a ValidationError
    // answered with the moment's fallback.
    const refused = await own.prepare();
    assert.deepEqual(wordsOf(refused), {
      ok: false,
      refusal: {
        reason:
          'certificate auth: provide either PEM (certPath + certKeyPath) or certPfxPath, not both',
        hint: 'check the provider configuration',
      },
    });
    notContains(JSON.stringify(refused), 'SECRET');
    const fsError = Object.assign(
      new Error("ENOENT: no such file 'C:\\\\SECRET\\\\key.pem'"),
      { code: 'ENOENT' },
    );
    const foreign = new CertificateAuthProvider(
      {
        load: async () => {
          throw fsError;
        },
      },
      config,
    );
    const outcome = await foreign.prepare();
    assert.deepEqual(wordsOf(outcome), {
      ok: false,
      refusal: {
        reason: 'loading the certificate failed (unknown error, ENOENT)',
      },
    });
  });

  it('returns the target Oops when the wire has no TLS; a throwing target is an Oops', async () => {
    const p = new CertificateAuthProvider(
      {
        load: async () => ({
          pfx: fixture('client.pfx'),
          passphrase: 'test-passphrase',
        }),
      },
      config,
    );
    await p.prepare();
    matchObject(
      await p.establish(recordingTargets({ acceptsTls: false }).logonTarget),
      {
        ok: false,
        refusal: { reason: 'this wire carries no TLS material (RFC)' },
      },
    );
    const outcome = await p.establish(broken().logonTarget);
    assert.equal(outcome.ok, false);
    assert.doesNotMatch(JSON.stringify(outcome), /test-passphrase/);
  });

  it('establish before prepare is an Oops, not a throw', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({}) }, config);
    matchObject(await p.establish(recordingTargets().logonTarget), {
      ok: false,
    });
  });
});

describe('CertificateAuthProvider.fromFiles', () => {
  it('assembles a FileCertificateMaterialLoader', () => {
    const p = CertificateAuthProvider.fromFiles({
      url: 'https://h',
      authType: 'certificate',
    } as ISapConfig);
    assert.ok(
      (p as unknown as { loader: unknown }).loader instanceof
        FileCertificateMaterialLoader,
    );
  });
});

describe('FileCertificateMaterialLoader', () => {
  // Configuration failures, no longer ValidationError.
  it('configuration errors are configuration failures', async () => {
    const loader = new FileCertificateMaterialLoader();
    assert.equal(
      configurationOf(
        await thrownFrom(() =>
          loader.load({
            url: 'h',
            authType: 'certificate',
            certPath: 'a',
            certPfxPath: 'b',
          } as ISapConfig),
        ),
      ).case,
      'certificate-pem-and-pfx',
    );
    assert.equal(
      configurationOf(
        await thrownFrom(() =>
          loader.load({ url: 'h', authType: 'certificate' } as ISapConfig),
        ),
      ).case,
      'certificate-files-missing',
    );
  });
});
