/**
 * Every token-request site, called the same way: without `auth` as today with
 * a client secret (`sec` unless given), with `auth` and no secret. Shared by the tests that run a
 * property over all of them.
 */

import type { Operation } from '@mcp-abap-adt/interfaces-auth';
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
import type {
  TokenRequestAuth,
  TokenSiteOptions,
} from '../../auth/tokenRequest';

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
  /**
   * Without `auth`, the site runs as today with `secret` (default `sec`);
   * the device initiation sends none.
   */
  run: (
    auth?: TokenRequestAuth,
    logger?: ILogger,
    secret?: string,
    options?: TokenSiteOptions,
  ) => Promise<unknown>;
  /** The site's operation (spec A.8): its failure's and its line's. */
  operation: Operation;
  /** 5.4.2's label of the site's refused-request line. */
  label542: string;
  /** Whether the path without a strategy sends a Basic header of its own. */
  legacyBasic: boolean;
  /** The level of its `2xx`-without-token line: `error` at the UAA code exchange. */
  missingLevel: 'error' | 'debug';
  /** The problem of its `2xx` without what it needs. */
  missingProblem: 'no-access-token' | 'incomplete-response';
  /** The URL the site sends to today: the draft's endpoint. */
  endpoint: string;
  grantType: string;
  /** The grant's own parameters, which a strategy only adds to. */
  grant: Record<string, string>;
  /** The site's own headers besides Content-Type. */
  ownHeaders?: Record<string, string>;
}

export const OIDC = 'https://idp/token';
const secretUnless = (auth?: TokenRequestAuth, secret = 'sec') =>
  auth ? undefined : secret;

export const SITES: Site[] = [
  {
    name: 'clientCredentialsAuth',
    operation: 'client-credentials',
    label542: 'Client credentials authentication failed',
    legacyBasic: false,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      getTokenWithClientCredentials(
        'https://uaa',
        'cid',
        secretUnless(auth, secret),
        auth,
        logger,
        options,
      ),
    endpoint: 'https://uaa/oauth/token',
    grantType: 'client_credentials',
    grant: { grant_type: 'client_credentials' },
  },
  {
    name: 'tokenRefresher',
    operation: 'token-refresh',
    label542: 'Token refresh failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      refreshJwtToken(
        'old-rt',
        'https://uaa',
        'cid',
        secretUnless(auth, secret),
        auth,
        logger,
        options,
      ),
    endpoint: 'https://uaa/oauth/token',
    grantType: 'refresh_token',
    grant: { grant_type: 'refresh_token', refresh_token: 'old-rt' },
  },
  {
    name: 'browserAuth.exchangeCodeForToken',
    operation: 'code-exchange',
    label542: 'Token exchange failed',
    legacyBasic: true,
    missingLevel: 'error',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      exchangeCodeForToken(
        {
          uaaUrl: 'https://uaa',
          uaaClientId: 'cid',
          uaaClientSecret: secretUnless(auth, secret),
        } as Parameters<typeof exchangeCodeForToken>[0],
        'the-code',
        'http://localhost:61001/callback',
        logger,
        auth,
        options,
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
    operation: 'passcode-exchange',
    label542: 'Passcode exchange failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      exchangePasscode(
        'https://uaa/',
        'cid',
        secretUnless(auth, secret),
        'CODE',
        logger,
        auth,
        options,
      ),
    endpoint: 'https://uaa/oauth/token',
    grantType: 'password',
    grant: { grant_type: 'password', passcode: 'CODE' },
    ownHeaders: { Accept: 'application/json' },
  },
  {
    name: 'saml2TokenExchange.exchangeSamlAssertion',
    operation: 'saml-token-exchange',
    label542: '[SAML] Token exchange failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      exchangeSamlAssertion(
        'ASSERTION',
        'https://t/token',
        'cid',
        secretUnless(auth, secret),
        logger,
        auth,
        options,
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
    operation: 'saml-token-refresh',
    label542: '[SAML] Token refresh failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      refreshSamlBearerToken(
        'old-rt',
        'https://t/token',
        'cid',
        secretUnless(auth, secret),
        logger,
        auth,
        options,
      ),
    endpoint: 'https://t/token',
    grantType: 'refresh_token',
    grant: { grant_type: 'refresh_token', refresh_token: 'old-rt' },
  },
  {
    name: 'oidcToken.exchangeAuthorizationCode',
    operation: 'oidc-token-request',
    label542: 'OIDC authorization code exchange failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      exchangeAuthorizationCode(
        OIDC,
        'cid',
        secretUnless(auth, secret),
        'the-code',
        'http://localhost:61001/callback',
        'verifier',
        logger,
        auth,
        options,
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
    operation: 'oidc-token-request',
    label542: 'OIDC token refresh failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      refreshOidcToken(
        OIDC,
        'cid',
        secretUnless(auth, secret),
        'old-rt',
        logger,
        auth,
        options,
      ),
    endpoint: OIDC,
    grantType: 'refresh_token',
    grant: { grant_type: 'refresh_token', refresh_token: 'old-rt' },
  },
  {
    name: 'oidcToken.initiateDeviceAuthorization',
    operation: 'device-authorization',
    label542: 'OIDC device authorization failed',
    legacyBasic: false,
    missingLevel: 'debug',
    missingProblem: 'incomplete-response',
    run: (auth, logger, _secret, options) =>
      initiateDeviceAuthorization(
        'https://idp/device-auth',
        'cid',
        'openid',
        logger,
        auth,
        options,
      ),
    endpoint: 'https://idp/device-auth',
    grantType: 'device_authorization',
    grant: { scope: 'openid' },
  },
  {
    name: 'oidcToken.pollDeviceTokens',
    operation: 'device-poll',
    label542: 'OIDC device poll failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      pollDeviceTokens(
        OIDC,
        'cid',
        secretUnless(auth, secret),
        'dc',
        0,
        logger,
        auth,
        options,
      ),
    endpoint: OIDC,
    grantType: 'urn:ietf:params:oauth:grant-type:device_code',
    grant: {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: 'dc',
    },
  },
  {
    name: 'oidcToken.passwordGrant',
    operation: 'password-grant',
    label542: 'OIDC password grant failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      passwordGrant(
        OIDC,
        'cid',
        secretUnless(auth, secret),
        'user',
        'pw',
        'openid',
        logger,
        auth,
        options,
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
    operation: 'oidc-token-request',
    label542: 'OIDC token exchange failed',
    legacyBasic: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (auth, logger, secret, options) =>
      tokenExchange(
        OIDC,
        'cid',
        secretUnless(auth, secret),
        'subj',
        'urn:ietf:params:oauth:token-type:access_token',
        'openid',
        'aud',
        undefined,
        undefined,
        logger,
        auth,
        options,
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

/**
 * The words' subject of each token operation, as auth-errors renders it
 * (pinned per operation in tokenRequestSite.test.ts, "each token site's
 * phrase").
 */
const PHRASES: Partial<Record<Operation, string>> = {
  'code-exchange': 'the code exchange',
  'token-refresh': 'the token refresh',
  'client-credentials': 'the client credentials request',
  'passcode-exchange': 'the passcode exchange',
  'saml-token-exchange': 'the SAML token exchange',
  'saml-token-refresh': 'the SAML token refresh',
  'oidc-token-request': 'the OIDC token request',
  'device-authorization': 'the OIDC device authorization',
  'device-poll': 'the device poll',
  'password-grant': 'the OIDC password grant',
  'oidc-discovery': 'OIDC discovery',
};

export function phrase(operation: Operation): string {
  const words = PHRASES[operation];
  if (words === undefined) throw new Error(`no phrase for ${operation}`);
  return words;
}
