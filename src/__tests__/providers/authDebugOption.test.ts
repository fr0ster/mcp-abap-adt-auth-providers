/**
 * `authDebug` (spec §6, "Where the option lives"): a constructor option of
 * every token provider (`TokenProviderDebug`, joined into every
 * `…ProviderConfig` through `TokenProviderHooks`), read once as
 * `config.authDebug === true` — `'true'`, `1` or an environment variable
 * never opt in. Threaded to the token sites in Task 21.
 */

import { afterEach, describe, expect, it } from '@jest/globals';
import type {
  AuthorizationCodeProviderConfig,
  ClientCredentialsProviderConfig,
  OidcBrowserProviderConfig,
  OidcDeviceFlowProviderConfig,
  OidcPasswordProviderConfig,
  OidcTokenExchangeProviderConfig,
  Saml2BearerProviderConfig,
  Saml2PureProviderConfig,
  TokenProviderDebug,
  UaaPasscodeProviderConfig,
} from '../../index';
import { ClientCredentialsProvider } from '../../providers';
import { refreshThenLogin } from '../../renewal';

/** A provider showing what its base read. */
class Probe extends ClientCredentialsProvider {
  get debugging(): boolean {
    return this.authDebug;
  }
}

const make = (authDebug: unknown): Probe =>
  new Probe({
    renewal: refreshThenLogin(),
    uaaUrl: 'https://uaa.example',
    clientId: 'client',
    clientSecret: 'secret',
    ...(authDebug === 'absent' ? {} : { authDebug: authDebug as boolean }),
  });

describe('authDebug', () => {
  const ENV = process.env.DEBUG_AUTH_PROVIDERS;
  afterEach(() => {
    if (ENV === undefined) delete process.env.DEBUG_AUTH_PROVIDERS;
    else process.env.DEBUG_AUTH_PROVIDERS = ENV;
  });

  it('true opts in', () => {
    expect(make(true).debugging).toBe(true);
  });

  it.each([
    ['absent', 'absent'],
    ['undefined', undefined],
    ['false', false],
    ["the string 'true'", 'true'],
    ['1', 1],
  ])('%s does not', (_name, value) => {
    expect(make(value).debugging).toBe(false);
  });

  it('DEBUG_AUTH_PROVIDERS=true in the environment does not', () => {
    process.env.DEBUG_AUTH_PROVIDERS = 'true';
    expect(make('absent').debugging).toBe(false);
  });

  it('is read once, at construction', () => {
    const config: ClientCredentialsProviderConfig = {
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      authDebug: false,
    };
    const probe = new Probe(config);
    (config as { authDebug?: boolean }).authDebug = true;
    expect(probe.debugging).toBe(false);
  });

  it('every token provider config accepts it (type check)', () => {
    const debug: TokenProviderDebug = { authDebug: true };
    const accepts: Array<
      | Pick<AuthorizationCodeProviderConfig, 'authDebug'>
      | Pick<ClientCredentialsProviderConfig, 'authDebug'>
      | Pick<OidcBrowserProviderConfig, 'authDebug'>
      | Pick<OidcDeviceFlowProviderConfig, 'authDebug'>
      | Pick<OidcPasswordProviderConfig, 'authDebug'>
      | Pick<OidcTokenExchangeProviderConfig, 'authDebug'>
      | Pick<Saml2BearerProviderConfig, 'authDebug'>
      | Pick<Saml2PureProviderConfig, 'authDebug'>
      | Pick<UaaPasscodeProviderConfig, 'authDebug'>
    > = [debug, { authDebug: undefined }];
    expect(accepts).toHaveLength(2);
  });
});
