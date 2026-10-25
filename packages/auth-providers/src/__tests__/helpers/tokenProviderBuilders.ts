/**
 * Every way to build a token provider — each constructor, each static
 * factory, and `SsoProviderFactory` — from the fields a test adds
 * (`renewal`, `persistence`, …), with collaborators that record a call they
 * must never get. Shared by the construction-refusal suites.
 */

import { jest } from '@jest/globals';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { SsoProviderFactory } from '../../sso/SsoProviderFactory';
import { certificate } from './certificates';

type Recorder = jest.Mock<(...args: never[]) => Promise<unknown>>;

/** A strategy that records a call it must never get. */
export const authorize: Recorder = jest.fn(async () => ({
  payload: 'code',
  redirectUri: 'r',
}));
const strategy = { authorize } as unknown as IAuthorizationStrategy<never>;
export const presenter: { present: Recorder } = {
  present: jest.fn(async () => undefined),
};
export const validator: { validate: Recorder } = {
  validate: jest.fn(async () => ({}) as never),
};
const trust = { idpCertificates: [String(certificate().cert)] };

const uaa = { uaaUrl: 'https://uaa.example', clientId: 'c', clientSecret: 's' };
const oidc = {
  clientId: 'c',
  tokenEndpoint: 'https://idp.example/token',
  authorizationEndpoint: 'https://idp.example/authorize',
};
const saml = {
  idpSsoUrl: 'https://idp.example/sso',
  spEntityId: 'sp',
  idpEntityId: 'idp',
  uaaUrl: 'https://uaa.example',
  clientId: 'c',
  clientSecret: 's',
  idpInitiated: true,
};
const pure = {
  idpSsoUrl: 'https://idp.example/sso',
  spEntityId: 'sp',
  idpEntityId: 'idp',
  cookieProvider: async () => 'c=1',
};

/**
 * `base` with `extra`'s own properties copied as descriptors — an accessor
 * stays an accessor, never run here.
 */
export const own = (base: object, extra: object): object =>
  Object.defineProperties({ ...base }, Object.getOwnPropertyDescriptors(extra));

/** Each way to build a token provider, given the extra fields. */
export const BUILDERS: ReadonlyArray<[string, (extra: object) => unknown]> = [
  [
    'ClientCredentialsProvider',
    (x) => new ClientCredentialsProvider(own({ ...uaa }, x) as never),
  ],
  [
    'AuthorizationCodeProvider',
    (x) =>
      new AuthorizationCodeProvider(
        own(
          {
            ...uaa,
            authorization: strategy,
          },
          x,
        ) as never,
      ),
  ],
  [
    'AuthorizationCodeProvider.inBrowser',
    (x) => AuthorizationCodeProvider.inBrowser(own({ ...uaa }, x) as never),
  ],
  [
    'OidcBrowserProvider',
    (x) =>
      new OidcBrowserProvider(
        own(
          {
            ...oidc,
            authorization: strategy,
          },
          x,
        ) as never,
      ),
  ],
  [
    'OidcBrowserProvider.inBrowser',
    (x) => OidcBrowserProvider.inBrowser(own({ ...oidc }, x) as never),
  ],
  [
    'OidcDeviceFlowProvider',
    (x) =>
      new OidcDeviceFlowProvider(
        own(
          {
            ...oidc,
            deviceAuthorizationEndpoint: 'https://idp.example/device',
            presenter,
          },
          x,
        ) as never,
      ),
  ],
  [
    'OidcDeviceFlowProvider.toConsole',
    (x) =>
      OidcDeviceFlowProvider.toConsole(
        own(
          {
            ...oidc,
            deviceAuthorizationEndpoint: 'https://idp.example/device',
          },
          x,
        ) as never,
      ),
  ],
  [
    'OidcPasswordProvider',
    (x) =>
      new OidcPasswordProvider(
        own(
          {
            ...oidc,
            username: 'u',
            password: 'p',
          },
          x,
        ) as never,
      ),
  ],
  [
    'OidcTokenExchangeProvider',
    (x) =>
      new OidcTokenExchangeProvider(
        own(
          {
            ...oidc,
            subjectToken: 't',
            subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
          },
          x,
        ) as never,
      ),
  ],
  [
    'Saml2BearerProvider',
    (x) =>
      new Saml2BearerProvider(
        own(
          {
            ...saml,
            authorization: strategy,
            assertionValidator: validator,
          },
          x,
        ) as never,
      ),
  ],
  [
    'Saml2BearerProvider.inBrowser',
    (x) => Saml2BearerProvider.inBrowser(own({ ...saml }, x) as never, trust),
  ],
  [
    'Saml2PureProvider',
    (x) =>
      new Saml2PureProvider(
        own(
          {
            ...pure,
            authorization: strategy,
            assertionValidator: validator,
          },
          x,
        ) as never,
      ),
  ],
  [
    'Saml2PureProvider.inBrowser',
    (x) => Saml2PureProvider.inBrowser(own({ ...pure }, x) as never, trust),
  ],
  [
    'UaaPasscodeProvider',
    (x) =>
      new UaaPasscodeProvider(
        own(
          {
            uaaUrl: 'https://uaa.example',
            clientId: 'c',
            authorization: strategy,
          },
          x,
        ) as never,
      ),
  ],
  [
    'UaaPasscodeProvider.fromTerminal',
    (x) =>
      UaaPasscodeProvider.fromTerminal(
        own(
          {
            uaaUrl: 'https://uaa.example',
            clientId: 'c',
          },
          x,
        ) as never,
      ),
  ],
  [
    'SsoProviderFactory oidc password',
    (x) =>
      SsoProviderFactory.create({
        protocol: 'oidc',
        flow: 'password',
        config: own({ ...oidc, username: 'u', password: 'p' }, x),
      } as never),
  ],
];

/** A Proxy whose every read throws an Error holding `secret`. */
export function throwingProxy(secret: string): object {
  return new Proxy(
    {},
    {
      get() {
        throw new Error(secret);
      },
      has() {
        throw new Error(secret);
      },
      getOwnPropertyDescriptor() {
        throw new Error(secret);
      },
    },
  );
}
