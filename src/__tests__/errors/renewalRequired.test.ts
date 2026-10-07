/**
 * `renewal` is required in every token provider's configuration (spec
 * §6c.3, rule 7): a missing or unusable one is refused at construction —
 * `configuration` `required-fields-missing`, `fields: ['renewal']` —
 * read as own data like every other required collaborator, through every
 * constructor and every static factory. Nothing is called, nothing sent.
 */

import { describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import axios from 'axios';
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
import { certificate } from '../helpers/certificates';

const SECRET = 'RENEWAL-OPTION-SECRET-7';

/** A strategy that records a call it must never get. */
const authorize = jest.fn(async () => ({ payload: 'code', redirectUri: 'r' }));
const strategy = { authorize } as unknown as IAuthorizationStrategy<never>;
const presenter = { present: jest.fn(async () => undefined) };
const validator = { validate: jest.fn(async () => ({}) as never) };
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
const own = (base: object, extra: object): object =>
  Object.defineProperties({ ...base }, Object.getOwnPropertyDescriptors(extra));

/** Each way to build a token provider, given the extra (renewal) fields. */
const BUILDERS: ReadonlyArray<[string, (extra: object) => unknown]> = [
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

const throwingProxy = new Proxy(
  {},
  {
    get() {
      throw new Error(SECRET);
    },
    has() {
      throw new Error(SECRET);
    },
    getOwnPropertyDescriptor() {
      throw new Error(SECRET);
    },
  },
);

/** What `renewal` is given, as extra fields — or as an accessor. */
const UNUSABLE: ReadonlyArray<[string, () => object]> = [
  ['missing', () => ({})],
  ['undefined', () => ({ renewal: undefined })],
  ['null', () => ({ renewal: null })],
  ['a string', () => ({ renewal: 'refreshThenLogin' })],
  ['an object without next', () => ({ renewal: {} })],
  ['next not a function', () => ({ renewal: { next: 'refresh' } })],
  ['a throwing Proxy', () => ({ renewal: throwingProxy })],
  [
    'a next getter that throws',
    () => ({
      renewal: Object.defineProperty({}, 'next', {
        get() {
          throw new Error(SECRET);
        },
      }),
    }),
  ],
  [
    'an accessor on the options (never run)',
    () =>
      Object.defineProperty({}, 'renewal', {
        enumerable: true,
        get() {
          throw new Error(SECRET);
        },
      }),
  ],
];

describe('a missing or unusable renewal is refused at construction', () => {
  const cases = BUILDERS.flatMap(([builder, build]) =>
    UNUSABLE.map(([what, extra]) => [builder, what, build, extra] as const),
  );

  it.each(cases)('%s, renewal %s', (_builder, _what, build, extra) => {
    const post = jest.spyOn(axios, 'post');
    const request = jest.spyOn(axios, 'request');
    let thrown: unknown;
    try {
      build(extra());
    } catch (error) {
      thrown = error;
    }
    try {
      expect(isAuthProviderFailure(thrown)).toBe(true);
      const error = readFailure(thrown, 'unfamiliar-error');
      expect(error).toMatchObject({
        kind: 'configuration',
        facts: { case: 'required-fields-missing', fields: ['renewal'] },
        reason: 'required configuration is missing: renewal',
      });
      expect(JSON.stringify(error)).not.toContain(SECRET);
      expect(String(thrown)).not.toContain(SECRET);
      expect(authorize).not.toHaveBeenCalled();
      expect(presenter.present).not.toHaveBeenCalled();
      expect(validator.validate).not.toHaveBeenCalled();
      expect(post).not.toHaveBeenCalled();
      expect(request).not.toHaveBeenCalled();
    } finally {
      post.mockRestore();
      request.mockRestore();
    }
  });
});
