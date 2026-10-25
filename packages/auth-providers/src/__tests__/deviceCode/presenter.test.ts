import { describe, expect, it, jest } from '@jest/globals';
import { consoleDeviceCodePresenter } from '../../deviceCode/DeviceCodePresenter';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { refreshThenLogin } from '../../renewal';

const prompt = {
  verificationUri: 'https://idp/device',
  verificationUriComplete: 'https://idp/device?c=AB',
  userCode: 'AB-CD',
  expiresInSeconds: 600,
};

describe('device-code presenter', () => {
  it('console presenter: to the logger when there is one, never stdout', async () => {
    const info = jest.fn();
    const out = jest.spyOn(process.stdout, 'write');
    await consoleDeviceCodePresenter({
      info,
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as never).present(prompt);
    expect(info.mock.calls.flat().join('\n')).toMatch(
      /https:\/\/idp\/device[\s\S]*AB-CD/,
    );
    expect(out).not.toHaveBeenCalled();
    out.mockRestore();
  });

  it('console presenter: to stderr without a logger', async () => {
    const err = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
    await consoleDeviceCodePresenter().present(prompt);
    expect(err.mock.calls.map((c) => String(c[0])).join('')).toMatch(
      /Enter code: AB-CD/,
    );
    err.mockRestore();
  });

  it('the provider requires a presenter and toConsole assembles one', () => {
    // @ts-expect-error presenter is required
    expect(() => new OidcDeviceFlowProvider({ clientId: 'c' })).toBeDefined();
    const p = OidcDeviceFlowProvider.toConsole({
      renewal: refreshThenLogin(),
      clientId: 'c',
    });
    expect(
      typeof (p as unknown as { config: { presenter: { present: unknown } } })
        .config.presenter.present,
    ).toBe('function');
  });
});
