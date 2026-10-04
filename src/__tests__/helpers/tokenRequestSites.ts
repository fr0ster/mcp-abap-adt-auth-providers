/**
 * Every token-request site, called the same way: without `auth` as today with
 * the secret `sec`, with `auth` and no secret. Shared by the tests that run a
 * property over all of them.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { exchangeCodeForToken } from '../../auth/browserAuth';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import {
  exchangeAuthorizationCode,
  initiateDeviceAuthorization,
  passwordGrant,
  pollDeviceTokens,
  refreshOidcToken,
  tokenExchange,
} from '../../auth/oidcToken';
import { exchangePasscode } from '../../auth/passcodeAuth';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import type { TokenRequestAuth } from '../../auth/tokenRequest';

/** Every site answers this: token fields and device fields. */
export const tokenReply = {
  data: {
    access_token: 'at',
    refresh_token: 'rt',
    expires_in: 60,
    device_code: 'dc',
    user_code: 'uc',
    verification_uri: 'https://idp/device',
  },
};

export interface Site {
  name: string;
  /** Without `auth`, the site runs as today with the secret `sec`. */
  run: (auth?: TokenRequestAuth, logger?: ILogger) => Promise<unknown>;
  /** The URL the site sends to today: the draft's endpoint. */
  endpoint: string;
  grantType: string;
  /** The grant's own parameters, which a strategy only adds to. */
  grant: Record<string, string>;
  /** The site's own headers besides Content-Type. */
  ownHeaders?: Record<string, string>;
}

export const OIDC = 'https://idp/token';
const secretUnless = (auth?: TokenRequestAuth) => (auth ? undefined : 'sec');

export const SITES: Site[] = [
  {
    name: 'clientCredentialsAuth',
    run: (auth) =>
      getTokenWithClientCredentials(
        'https://uaa',
        'cid',
        secretUnless(auth),
        auth,
      ),
    endpoint: 'https://uaa/oauth/token',
    grantType: 'client_credentials',
    grant: { grant_type: 'client_credentials' },
  },
  {
    name: 'tokenRefresher',
    run: (auth) =>
      refreshJwtToken('old-rt', 'https://uaa', 'cid', secretUnless(auth), auth),
    endpoint: 'https://uaa/oauth/token',
    grantType: 'refresh_token',
    grant: { grant_type: 'refresh_token', refresh_token: 'old-rt' },
  },
  {
    name: 'browserAuth.exchangeCodeForToken',
    run: (auth, logger) =>
      exchangeCodeForToken(
        {
          uaaUrl: 'https://uaa',
          uaaClientId: 'cid',
          uaaClientSecret: secretUnless(auth),
        } as Parameters<typeof exchangeCodeForToken>[0],
        'the-code',
        'http://localhost:61001/callback',
        logger,
        auth,
      ),
    endpoint: 'https://uaa/oauth/token',
    grantType: 'authorization_code',
    grant: {
      grant_type: 'authorization_code',
      code: 'the-code',
      redirect_uri: 'http://localhost:61001/callback',
    },
  },
  {
    name: 'passcodeAuth',
    run: (auth, logger) =>
      exchangePasscode(
        'https://uaa/',
        'cid',
        secretUnless(auth),
        'CODE',
        logger,
        auth,
      ),
    endpoint: 'https://uaa/oauth/token',
    grantType: 'password',
    grant: { grant_type: 'password', passcode: 'CODE' },
    ownHeaders: { Accept: 'application/json' },
  },
  {
    name: 'saml2TokenExchange.exchangeSamlAssertion',
    run: (auth, logger) =>
      exchangeSamlAssertion(
        'ASSERTION',
        'https://t/token',
        'cid',
        secretUnless(auth),
        logger,
        auth,
      ),
    endpoint: 'https://t/token',
    grantType: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
    grant: {
      grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
      assertion: 'ASSERTION',
    },
  },
  {
    name: 'saml2TokenExchange.refreshSamlBearerToken',
    run: (auth, logger) =>
      refreshSamlBearerToken(
        'old-rt',
        'https://t/token',
        'cid',
        secretUnless(auth),
        logger,
        auth,
      ),
    endpoint: 'https://t/token',
    grantType: 'refresh_token',
    grant: { grant_type: 'refresh_token', refresh_token: 'old-rt' },
  },
  {
    name: 'oidcToken.exchangeAuthorizationCode',
    run: (auth, logger) =>
      exchangeAuthorizationCode(
        OIDC,
        'cid',
        secretUnless(auth),
        'the-code',
        'http://localhost:61001/callback',
        'verifier',
        logger,
        auth,
      ),
    endpoint: OIDC,
    grantType: 'authorization_code',
    grant: {
      grant_type: 'authorization_code',
      code: 'the-code',
      redirect_uri: 'http://localhost:61001/callback',
      code_verifier: 'verifier',
    },
  },
  {
    name: 'oidcToken.refreshOidcToken',
    run: (auth, logger) =>
      refreshOidcToken(OIDC, 'cid', secretUnless(auth), 'old-rt', logger, auth),
    endpoint: OIDC,
    grantType: 'refresh_token',
    grant: { grant_type: 'refresh_token', refresh_token: 'old-rt' },
  },
  {
    name: 'oidcToken.initiateDeviceAuthorization',
    run: (auth, logger) =>
      initiateDeviceAuthorization(
        'https://idp/device-auth',
        'cid',
        'openid',
        logger,
        auth,
      ),
    endpoint: 'https://idp/device-auth',
    grantType: 'device_authorization',
    grant: { scope: 'openid' },
  },
  {
    name: 'oidcToken.pollDeviceTokens',
    run: (auth, logger) =>
      pollDeviceTokens(OIDC, 'cid', secretUnless(auth), 'dc', 0, logger, auth),
    endpoint: OIDC,
    grantType: 'urn:ietf:params:oauth:grant-type:device_code',
    grant: {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: 'dc',
    },
  },
  {
    name: 'oidcToken.passwordGrant',
    run: (auth, logger) =>
      passwordGrant(
        OIDC,
        'cid',
        secretUnless(auth),
        'user',
        'pw',
        'openid',
        logger,
        auth,
      ),
    endpoint: OIDC,
    grantType: 'password',
    grant: {
      grant_type: 'password',
      username: 'user',
      password: 'pw',
      scope: 'openid',
    },
  },
  {
    name: 'oidcToken.tokenExchange',
    run: (auth, logger) =>
      tokenExchange(
        OIDC,
        'cid',
        secretUnless(auth),
        'subj',
        'urn:ietf:params:oauth:token-type:access_token',
        'openid',
        'aud',
        undefined,
        undefined,
        logger,
        auth,
      ),
    endpoint: OIDC,
    grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
    grant: {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: 'subj',
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      scope: 'openid',
      audience: 'aud',
    },
  },
];
