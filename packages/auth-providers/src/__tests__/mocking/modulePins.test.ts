/**
 * The pins of `mock.method` on a module object, one per module a moved test
 * mocks that way (oidcToken, oidcDiscovery, tokenRefresher,
 * saml2TokenExchange, node:child_process). The importers' compiled code
 * reads the function off the module object at each call (`(0,
 * oidcToken_1.passwordGrant)(…)`, `child_process.spawn(…)`), so the mock
 * replaces what production calls, with no module registry in between.
 */

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { afterEach, it, mock } from 'node:test';
import type { IAssertionValidator } from '@mcp-abap-adt/interfaces-auth';
import { runLauncher } from '../../auth/browserLaunch';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { refreshThenLogin } from '../../renewal';
import { staticCodeStrategy } from '../../strategies/codeStrategies';

import childProcess = require('node:child_process');
import oidcDiscovery = require('../../auth/oidcDiscovery');
import oidcToken = require('../../auth/oidcToken');
import saml2TokenExchange = require('../../auth/saml2TokenExchange');
import tokenRefresher = require('../../auth/tokenRefresher');

afterEach(() => mock.restoreAll());

const refused = { at: 'request' as const, status: 401, error: {} };

/** A JWT whose `exp` is `seconds` from now (no signature: never verified here). */
function jwtExpiringIn(seconds: number): string {
  const part = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'none' })}.${part({ exp: Math.floor(Date.now() / 1000) + seconds })}.`;
}

it('oidcToken: the provider calls the mocked passwordGrant', async () => {
  const grant = mock.method(oidcToken, 'passwordGrant', async () => ({
    accessToken: 'mocked',
    expiresIn: 60,
  }));
  const tokens = await new OidcPasswordProvider({
    renewal: refreshThenLogin(),
    clientId: 'c',
    clientSecret: 's',
    username: 'u',
    password: 'p',
    tokenEndpoint: 'https://idp.invalid/token',
  }).getTokens();
  assert.equal(grant.mock.callCount(), 1);
  assert.equal(tokens.authorizationToken, 'mocked');
});

it('oidcDiscovery: the provider calls the mocked discoverOidc', async () => {
  const discover = mock.method(oidcDiscovery, 'discoverOidc', async () => ({
    token_endpoint: 'https://idp.invalid/discovered/token',
  }));
  const grant = mock.method(oidcToken, 'passwordGrant', async () => ({
    accessToken: 'mocked',
    expiresIn: 60,
  }));
  await new OidcPasswordProvider({
    renewal: refreshThenLogin(),
    clientId: 'c',
    clientSecret: 's',
    username: 'u',
    password: 'p',
    issuerUrl: 'https://idp.invalid',
  }).getTokens();
  assert.equal(discover.mock.callCount(), 1);
  assert.equal(
    grant.mock.calls[0]?.arguments[0],
    'https://idp.invalid/discovered/token',
  );
});

it('tokenRefresher: the provider calls the mocked refreshJwtToken', async () => {
  const refresh = mock.method(tokenRefresher, 'refreshJwtToken', async () => ({
    // Another token than the one held: a renewal must change it.
    accessToken: jwtExpiringIn(7200),
    refreshToken: 'R2',
    expiresIn: 3600,
  }));
  const provider = new AuthorizationCodeProvider({
    renewal: refreshThenLogin(),
    uaaUrl: 'https://uaa.invalid',
    clientId: 'client',
    clientSecret: 'secret',
    accessToken: jwtExpiringIn(3600),
    refreshToken: 'R1',
    authorization: staticCodeStrategy({ payload: 'code' }),
  });
  assert.deepEqual(await provider.rejected(refused), { ok: true });
  assert.equal(refresh.mock.callCount(), 1);
  assert.equal(refresh.mock.calls[0]?.arguments[0], 'R1');
});

it('saml2TokenExchange: the provider calls the mocked refreshSamlBearerToken', async () => {
  const refresh = mock.method(
    saml2TokenExchange,
    'refreshSamlBearerToken',
    async () => ({ accessToken: jwtExpiringIn(3600), expiresIn: 3600 }),
  );
  const exchange = mock.method(saml2TokenExchange, 'exchangeSamlAssertion');
  const accepting: IAssertionValidator = {
    async validate(payload) {
      return {
        expiresAt: new Date(Date.now() + 3600_000),
        assertionId: '_stub',
        issuer: 'urn:stub:idp',
        raw: payload,
        signedXml: payload,
      };
    },
  };
  await new Saml2BearerProvider({
    renewal: refreshThenLogin(),
    idpSsoUrl: 'https://idp.invalid/sso',
    spEntityId: 'sp-entity',
    uaaUrl: 'https://uaa.invalid',
    clientId: 'client',
    clientSecret: 'secret',
    accessToken: jwtExpiringIn(-3600),
    refreshToken: 'seeded-refresh',
    idpInitiated: true,
    authorization: staticCodeStrategy({ payload: 'unused' }),
    assertionValidator: accepting,
  }).getTokens();
  assert.equal(refresh.mock.callCount(), 1);
  assert.equal(exchange.mock.callCount(), 0);
});

it('node:child_process: the launcher calls the mocked spawn', async () => {
  const spawn = mock.method(childProcess, 'spawn', () => {
    const child = Object.assign(new EventEmitter(), { unref: () => undefined });
    setImmediate(() => child.emit('spawn'));
    return child;
  });
  await new Promise<void>((resolve, reject) => {
    runLauncher(
      { command: '/nonexistent/launcher', args: ['u'], settlesOn: 'spawn' },
      { onSuccess: resolve, onFailure: reject },
    );
  });
  assert.equal(spawn.mock.callCount(), 1);
  assert.equal(spawn.mock.calls[0]?.arguments[0], '/nonexistent/launcher');
});
