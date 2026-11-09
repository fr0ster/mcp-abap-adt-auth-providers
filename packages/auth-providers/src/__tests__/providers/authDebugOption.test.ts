/**
 * `authDebug`: a constructor option of
 * every token provider (`TokenProviderDebug`, joined into every
 * `…ProviderConfig` through `TokenProviderHooks`), read once as
 * `config.authDebug === true` — `'true'`, `1` or an environment variable
 * never opt in. Threaded to the token sites.
 */

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
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
import { cases, caseTitle } from '../helpers/expectations';

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
    assert.equal(make(true).debugging, true);
  });

  for (const [caseIndex, caseRow] of cases([
    ['absent', 'absent'],
    ['undefined', undefined],
    ['false', false],
    ["the string 'true'", 'true'],
    ['1', 1],
  ]).entries()) {
    const [_name, value] = caseRow;
    it(caseTitle('%s does not', caseRow, caseIndex), () => {
      assert.equal(make(value).debugging, false);
    });
  }

  it('DEBUG_AUTH_PROVIDERS=true in the environment does not', () => {
    process.env.DEBUG_AUTH_PROVIDERS = 'true';
    assert.equal(make('absent').debugging, false);
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
    assert.equal(probe.debugging, false);
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
    assert.equal(accepts.length, 2);
  });
});
