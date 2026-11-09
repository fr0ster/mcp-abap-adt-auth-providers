import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
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
  // That nothing in src writes to stdout is checked statically
  // (noStdoutSources.test.ts); here, where each prompt goes.
  it('console presenter: to the logger when there is one', async () => {
    const info = mock.fn();
    await consoleDeviceCodePresenter({
      info,
      debug: mock.fn(),
      warn: mock.fn(),
      error: mock.fn(),
    } as never).present(prompt);
    assert.match(
      info.mock.calls.flatMap((call) => call.arguments).join('\n'),
      /https:\/\/idp\/device[\s\S]*AB-CD/,
    );
  });

  it('console presenter: to stderr without a logger', async () => {
    const err = mock.method(process.stderr, 'write', () => true);
    await consoleDeviceCodePresenter().present(prompt);
    assert.match(
      err.mock.calls
        .map((call) => call.arguments)
        .map((c) => String(c[0]))
        .join(''),
      /Enter code: AB-CD/,
    );
    err.mock.restore();
  });

  it('the provider requires a presenter and toConsole assembles one', () => {
    // A compile-time check (`npm run test:check`): the config requires a
    // presenter. It was `expect(() => …).toBeDefined()`, which held for any
    // function and proved nothing at run time.
    const withoutPresenter = () =>
      // @ts-expect-error presenter is required
      new OidcDeviceFlowProvider({ clientId: 'c' });
    void withoutPresenter;
    const p = OidcDeviceFlowProvider.toConsole({
      renewal: refreshThenLogin(),
      clientId: 'c',
    });
    assert.equal(
      typeof (p as unknown as { config: { presenter: { present: unknown } } })
        .config.presenter.present,
      'function',
    );
  });
});
