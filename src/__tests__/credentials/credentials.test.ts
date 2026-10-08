import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, jest } from '@jest/globals';
import type { ITokenRefresher } from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { FileCertificateMaterialLoader } from '../../credentials/FileCertificateMaterialLoader';
import { SamlAuthProvider } from '../../credentials/SamlAuthProvider';
import { TokenAuthProvider } from '../../credentials/TokenAuthProvider';
import { configurationOf, thrownFrom, wordsOf } from '../helpers/minted';
import { recordingTargets } from '../helpers/targets';

const refusal = { at: 'request' as const, status: 401, error: {} };
const fixture = (name: string) =>
  readFileSync(join(__dirname, '..', 'fixtures', 'certificates', name));
const broken = () => recordingTargets({ throws: true });

describe('BasicAuthProvider', () => {
  const p = new BasicAuthProvider('USER', 'S3CRET-PW');

  it('writes the header and offers user/passwd to the logon', async () => {
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    await expect(p.authorize(t.requestTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.params).toEqual([{ user: 'USER', passwd: 'S3CRET-PW' }]);
    expect(t.request.headers.Authorization).toBe(
      `Basic ${Buffer.from('USER:S3CRET-PW').toString('base64')}`,
    );
  });

  it('an untyped caller without user or password sends empty ones, never "undefined"', async () => {
    const t = recordingTargets();
    await new BasicAuthProvider(
      undefined as never,
      undefined as never,
    ).authorize(t.requestTarget);
    expect(t.request.headers.Authorization).toBe(
      `Basic ${Buffer.from(':').toString('base64')}`,
    );
  });

  it('goes on when the wire takes no logon parameters (HTTP)', async () => {
    await expect(
      p.establish(
        recordingTargets({ acceptsLogonParameters: false }).logonTarget,
      ),
    ).resolves.toEqual({ ok: true });
  });

  it('a throwing target is an Oops without the password', async () => {
    for (const outcome of [
      await p.establish(broken().logonTarget),
      await p.authorize(broken().requestTarget),
    ]) {
      expect(outcome).toMatchObject({ ok: false });
      expect(JSON.stringify(outcome)).not.toMatch(/S3CRET-PW|SECRET-IN-TARGET/);
    }
  });

  it('rejected is an Oops without the password', async () => {
    const outcome = await p.rejected(refusal);
    expect(outcome).toMatchObject({
      ok: false,
      refusal: { reason: 'the user or password was refused' },
    });
    expect(JSON.stringify(outcome)).not.toMatch(/S3CRET-PW/);
  });
});

describe('SamlAuthProvider', () => {
  const p = new SamlAuthProvider('MYSAPSSO2=SECRET-COOKIE');

  it('writes the cookies', async () => {
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.cookies).toEqual(['MYSAPSSO2=SECRET-COOKIE']);
  });

  it('a throwing target and rejected are Oops without the cookie', async () => {
    for (const outcome of [
      await p.authorize(broken().requestTarget),
      await p.rejected(refusal),
    ]) {
      expect(outcome.ok).toBe(false);
      expect(JSON.stringify(outcome)).not.toMatch(/SECRET-COOKIE/);
    }
  });
});

describe('TokenAuthProvider', () => {
  it('fixed: bearer, and rejected is an Oops without the token', async () => {
    const p = TokenAuthProvider.fixed('SECRET-T');
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.headers.Authorization).toBe('Bearer SECRET-T');
    const outcome = await p.rejected(refusal);
    expect(outcome).toMatchObject({
      ok: false,
      refusal: { hint: 'obtain a new token' },
    });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-T/);
  });

  it('from(refresher): getToken per attempt, refreshToken once, Ok on a new token', async () => {
    const refresher: ITokenRefresher = {
      getToken: jest.fn(async () => 'A'),
      refreshToken: jest.fn(async () => 'B'),
    };
    const p = TokenAuthProvider.from(refresher);
    await p.authorize(recordingTargets().requestTarget);
    await expect(p.rejected(refusal)).resolves.toEqual({ ok: true });
    expect(refresher.getToken).toHaveBeenCalledTimes(1);
    expect(refresher.refreshToken).toHaveBeenCalledTimes(1);
  });

  it('from(refresher): a renewal returning the refused token is an Oops', async () => {
    const p = TokenAuthProvider.from({
      getToken: async () => 'unchanged',
      refreshToken: async () => 'unchanged',
    });
    await p.authorize(recordingTargets().requestTarget);
    await expect(p.rejected(refusal)).resolves.toMatchObject({
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
      expect(outcome).toMatchObject({
        ok: false,
        refusal: { reason: 'the token source failed (unknown error)' },
      });
      expect(JSON.stringify(outcome)).not.toMatch(/SECRET/);
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
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.tls).toEqual([{ cert, key }]);
  });

  it("the loader's configuration failure is the refusal (E17); a foreign one gives its code only", async () => {
    const own = new CertificateAuthProvider(
      new FileCertificateMaterialLoader(),
      { ...config, certPath: 'SECRET-PATH', certPfxPath: 'SECRET-PFX' },
    );
    // The loader's configuration case, once a ValidationError
    // answered with the moment's fallback.
    const refused = await own.prepare();
    expect(wordsOf(refused)).toEqual({
      ok: false,
      refusal: {
        reason:
          'certificate auth: provide either PEM (certPath + certKeyPath) or certPfxPath, not both',
        hint: 'check the provider configuration',
      },
    });
    expect(JSON.stringify(refused)).not.toContain('SECRET');
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
    expect(wordsOf(outcome)).toEqual({
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
    await expect(
      p.establish(recordingTargets({ acceptsTls: false }).logonTarget),
    ).resolves.toMatchObject({
      ok: false,
      refusal: { reason: 'this wire carries no TLS material (RFC)' },
    });
    const outcome = await p.establish(broken().logonTarget);
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome)).not.toMatch(/test-passphrase/);
  });

  it('establish before prepare is an Oops, not a throw', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({}) }, config);
    await expect(
      p.establish(recordingTargets().logonTarget),
    ).resolves.toMatchObject({ ok: false });
  });
});

describe('CertificateAuthProvider.fromFiles', () => {
  it('assembles a FileCertificateMaterialLoader', () => {
    const p = CertificateAuthProvider.fromFiles({
      url: 'https://h',
      authType: 'certificate',
    } as ISapConfig);
    expect((p as unknown as { loader: unknown }).loader).toBeInstanceOf(
      FileCertificateMaterialLoader,
    );
  });
});

describe('FileCertificateMaterialLoader', () => {
  // Configuration failures, no longer ValidationError.
  it('configuration errors are configuration failures (E17, E18)', async () => {
    const loader = new FileCertificateMaterialLoader();
    expect(
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
    ).toBe('certificate-pem-and-pfx');
    expect(
      configurationOf(
        await thrownFrom(() =>
          loader.load({ url: 'h', authType: 'certificate' } as ISapConfig),
        ),
      ).case,
    ).toBe('certificate-files-missing');
  });
});
