/**
 * The keys of what this package hands out. An optional field without a value
 * is present, set to `undefined` — as it always was — not left out: the
 * broker and the stores merge these objects (`{ ...stored, ...result }`), so
 * the key's presence is behaviour. `toEqual` cannot tell the two apart, so
 * each test asks `Object.hasOwn`.
 */

import { join } from 'node:path';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type {
  AssertionContext,
  AuthorizationRequest,
  CallbackServerFactory,
  IAssertionValidator,
  IAuthorizationStrategy,
  ICallbackServerOptions,
  ITokenResult,
} from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import axios from 'axios';
import { FileCertificateMaterialLoader } from '../../credentials/FileCertificateMaterialLoader';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import { BrowserCallbackStrategy } from '../../strategies/BrowserCallbackStrategy';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock };

/** A JWT valid for an hour, so the second getTokens() answers the cache. */
function jwt(): string {
  const part = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'none' })}.${part({ exp: Math.floor(Date.now() / 1000) + 3600 })}.`;
}

/** A token endpoint that answers every grant without a refresh token. */
function answerWithoutRefreshToken(): void {
  const reply = async (url: unknown) =>
    String(url).includes('/device')
      ? {
          data: {
            device_code: 'dc',
            user_code: 'UC',
            verification_uri: 'https://idp.example/activate',
            interval: 0,
          },
        }
      : { data: { access_token: jwt(), expires_in: 3600 } };
  mockedAxios.mockImplementation(async (config: { url?: unknown }) =>
    reply(config.url),
  );
  mockedAxios.post.mockImplementation(async (url: unknown) => reply(url));
}

beforeEach(() => {
  jest.resetAllMocks();
  answerWithoutRefreshToken();
});

const SAML_PAYLOAD = Buffer.from(
  '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r">' +
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"><saml2:Issuer>idp</saml2:Issuer></saml2:Assertion>' +
    '</samlp:Response>',
  'utf8',
).toString('base64');

/** Accepts every payload and records the context it was given. */
function recordingValidator(contexts: AssertionContext[]): IAssertionValidator {
  return {
    async validate(payload, context) {
      contexts.push(context);
      return {
        expiresAt: new Date(Date.now() + 3600_000),
        assertionId: '_stub',
        issuer: 'urn:stub:idp',
        raw: payload,
        signedXml: payload,
      };
    },
  };
}

/** A strategy answering `payload` at once, recording the request. */
function answering<T>(
  payload: T,
  seen: AuthorizationRequest[] = [],
): IAuthorizationStrategy<T> {
  return {
    authorize: async (request) => {
      seen.push(request);
      return { payload, redirectUri: 'http://localhost:61001/callback' };
    },
  };
}

/**
 * The protected moments, reached the way the base class reaches them: the
 * login with an attempt (Task 22a: its signal and its exclusive section),
 * the refresh with the refresh token the base read.
 */
interface Moments {
  performLogin(attempt: {
    signal: AbortSignal;
    exclusive<R>(work: () => Promise<R>): Promise<R>;
  }): Promise<ITokenResult>;
  performRefresh(refreshToken: string): Promise<ITokenResult>;
}
const attempt = {
  signal: new AbortController().signal,
  exclusive: <R>(work: () => Promise<R>) => work(),
};
const moments = (provider: unknown) => {
  const reached = provider as Moments;
  return {
    performLogin: () => reached.performLogin(attempt),
    performRefresh: () => reached.performRefresh('rt'),
  };
};

const sorted = (keys: string[]) => [...keys].sort();
const OAUTH = sorted([
  'authorizationToken',
  'refreshToken',
  'authType',
  'expiresIn',
]);
const OIDC = sorted([...OAUTH, 'tokenType']);

// The keys each provider's result carried in 5.4.0, `undefined` values
// included. `seeded` builds it with a refresh token, for the refresh row.
const providers: [
  string,
  (seeded: boolean, seen?: AuthorizationRequest[]) => unknown,
  string[],
  string[] | null,
][] = [
  [
    'AuthorizationCodeProvider',
    (seeded, seen) =>
      new AuthorizationCodeProvider({
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa.example',
        clientId: 'cid',
        clientSecret: 's',
        authorization: answering('the-code', seen),
        ...(seeded ? { refreshToken: 'rt' } : {}),
      }),
    OAUTH,
    OAUTH,
  ],
  [
    'ClientCredentialsProvider',
    () =>
      new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa.example',
        clientId: 'cid',
        clientSecret: 's',
      }),
    OAUTH,
    null,
  ],
  [
    'OidcBrowserProvider',
    (seeded, seen) =>
      new OidcBrowserProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        tokenEndpoint: 'https://idp.example/token',
        authorizationEndpoint: 'https://idp.example/auth',
        authorization: answering({ code: 'the-code' }, seen),
        ...(seeded ? { refreshToken: 'rt' } : {}),
      }),
    OIDC,
    OIDC,
  ],
  [
    'OidcDeviceFlowProvider',
    (seeded) =>
      new OidcDeviceFlowProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        tokenEndpoint: 'https://idp.example/token',
        deviceAuthorizationEndpoint: 'https://idp.example/device',
        presenter: { present: async () => {} },
        ...(seeded ? { refreshToken: 'rt' } : {}),
      }),
    OIDC,
    OIDC,
  ],
  [
    'OidcPasswordProvider',
    (seeded) =>
      new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        tokenEndpoint: 'https://idp.example/token',
        username: 'u',
        password: 'p',
        ...(seeded ? { refreshToken: 'rt' } : {}),
      }),
    OIDC,
    OIDC,
  ],
  [
    'OidcTokenExchangeProvider',
    () =>
      new OidcTokenExchangeProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        tokenEndpoint: 'https://idp.example/token',
        subjectToken: 'subject',
        subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      }),
    OIDC,
    null,
  ],
  [
    'Saml2BearerProvider',
    (seeded, seen) =>
      new Saml2BearerProvider({
        renewal: refreshThenLogin(),
        idpSsoUrl: 'https://idp.example/sso',
        spEntityId: 'sp-entity',
        uaaUrl: 'https://uaa.example',
        clientId: 'cid',
        idpInitiated: true,
        authorization: answering(SAML_PAYLOAD, seen),
        assertionValidator: recordingValidator([]),
        ...(seeded ? { refreshToken: 'rt' } : {}),
      }),
    OIDC,
    OIDC,
  ],
  [
    'Saml2PureProvider',
    (_seeded, seen) =>
      new Saml2PureProvider({
        renewal: refreshThenLogin(),
        idpSsoUrl: 'https://idp.example/sso',
        spEntityId: 'sp-entity',
        idpInitiated: true,
        authorization: answering(SAML_PAYLOAD, seen),
        assertionValidator: recordingValidator([]),
        cookieProvider: async () => 'SAP_SESSIONID=x',
      }),
    sorted(['authorizationToken', 'authType', 'tokenType', 'expiresAt']),
    null,
  ],
  [
    'UaaPasscodeProvider',
    (seeded, seen) =>
      new UaaPasscodeProvider({
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa.example',
        clientId: 'cf',
        clientSecret: 's',
        authorization: answering('passcode', seen),
        ...(seeded ? { refreshToken: 'rt' } : {}),
      }),
    OIDC,
    OIDC,
  ],
];

describe.each(providers)(
  '%s result',
  (_name, build, loginKeys, refreshKeys) => {
    it('login: the keys of 5.4.0, an absent value present as undefined', async () => {
      const result = await moments(build(false)).performLogin();
      expect(sorted(Object.keys(result))).toEqual(loginKeys);
    });

    if (refreshKeys) {
      it('refresh: the keys of 5.4.0', async () => {
        const result = await moments(build(true)).performRefresh();
        expect(sorted(Object.keys(result))).toEqual(refreshKeys);
      });
    }
  },
);

describe.each(
  providers.filter(([name]) =>
    [
      'AuthorizationCodeProvider',
      'OidcBrowserProvider',
      'Saml2BearerProvider',
      'Saml2PureProvider',
      'UaaPasscodeProvider',
    ].includes(name),
  ),
)('%s: the request its strategy gets', (_name, build) => {
  it('carries logger as an own key, undefined, without a logger', async () => {
    const seen: AuthorizationRequest[] = [];
    await moments(build(false, seen)).performLogin();
    expect(seen).toHaveLength(1);
    expect(Object.hasOwn(seen[0]!, 'logger')).toBe(true);
    expect(seen[0]!.logger).toBeUndefined();
  });
});

describe.each([
  [
    'Saml2BearerProvider',
    (validator: IAssertionValidator) =>
      new Saml2BearerProvider({
        renewal: refreshThenLogin(),
        idpSsoUrl: 'https://idp.example/sso',
        spEntityId: 'sp-entity',
        uaaUrl: 'https://uaa.example',
        clientId: 'cid',
        idpInitiated: true,
        authorization: answering(SAML_PAYLOAD),
        assertionValidator: validator,
      }),
  ],
  [
    'Saml2PureProvider',
    (validator: IAssertionValidator) =>
      new Saml2PureProvider({
        renewal: refreshThenLogin(),
        idpSsoUrl: 'https://idp.example/sso',
        spEntityId: 'sp-entity',
        idpInitiated: true,
        authorization: answering(SAML_PAYLOAD),
        assertionValidator: validator,
        cookieProvider: async () => 'SAP_SESSIONID=x',
      }),
  ],
])('%s: the assertion context', (_name, build) => {
  it('IdP-initiated, no idpEntityId, no logger: each an own key, undefined', async () => {
    const contexts: AssertionContext[] = [];
    await moments(build(recordingValidator(contexts))).performLogin();
    expect(contexts).toHaveLength(1);
    const [context] = contexts;
    for (const key of ['expectedInResponseTo', 'expectedIssuer', 'logger']) {
      expect(Object.hasOwn(context!, key)).toBe(true);
    }
    expect(context!.expectedInResponseTo).toBeUndefined();
    expect(context!.expectedIssuer).toBeUndefined();
    expect(context!.logger).toBeUndefined();
  });
});

describe('token result, through getTokens()', () => {
  it('carries refreshToken as an own key, undefined, when the grant gives none — login and cache alike', async () => {
    const reply = { data: { access_token: jwt(), expires_in: 3600 } };
    mockedAxios.mockResolvedValue(reply);
    mockedAxios.post.mockResolvedValue(reply);
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
    });

    const fresh = await provider.getTokens();
    expect(Object.hasOwn(fresh, 'refreshToken')).toBe(true);
    expect(fresh.refreshToken).toBeUndefined();

    const cached = await provider.getTokens();
    expect(cached.authorizationToken).toBe(fresh.authorizationToken);
    expect(Object.hasOwn(cached, 'refreshToken')).toBe(true);
    expect(cached.refreshToken).toBeUndefined();

    // Spec §4.4 (Task 27): every result this package produces sets its
    // refresh-token disposition — none given, nothing cut: keep.
    expect(fresh.refreshTokenDisposition).toBe('keep');
    expect(cached.refreshTokenDisposition).toBe('keep');
  });
});

describe('the request a strategy gets, through getTokens()', () => {
  it('carries logger as an own key, undefined, when the provider has none', async () => {
    mockedAxios.mockResolvedValue({ data: { access_token: jwt() } });
    mockedAxios.post.mockResolvedValue({ data: { access_token: jwt() } });
    const seen: AuthorizationRequest[] = [];
    const strategy: IAuthorizationStrategy<string> = {
      authorize: async (request) => {
        seen.push(request);
        return { payload: 'passcode', redirectUri: '' };
      },
    };
    const provider = new UaaPasscodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      authorization: strategy,
    });

    await provider.getTokens();
    expect(seen).toHaveLength(1);
    expect(Object.hasOwn(seen[0]!, 'logger')).toBe(true);
    expect(seen[0]!.logger).toBeUndefined();
  });
});

describe('the callback server options', () => {
  it('carry logger as an own key, undefined, when the request has none', async () => {
    const seen: ICallbackServerOptions[] = [];
    const callbackServer: CallbackServerFactory<string> = async (options) => {
      seen.push(options);
      throw new Error('stop');
    };
    const strategy = new BrowserCallbackStrategy<string>({
      port: 0,
      callbackServer,
    });

    await expect(
      strategy.authorize({ buildAuthorizationUrl: async () => 'https://x' }),
    ).rejects.toThrow();
    expect(seen).toHaveLength(1);
    expect(Object.hasOwn(seen[0]!, 'logger')).toBe(true);
    expect(seen[0]!.logger).toBeUndefined();
  });
});

describe('FileCertificateMaterialLoader', () => {
  it('returns passphrase as an own key, undefined, when none is configured', async () => {
    const dir = join(__dirname, '..', 'fixtures', 'certificates');
    const material = await new FileCertificateMaterialLoader().load({
      url: 'https://h',
      authType: 'certificate',
      certPath: join(dir, 'client.crt'),
      certKeyPath: join(dir, 'client.key'),
    } as ISapConfig);
    expect(Object.hasOwn(material, 'passphrase')).toBe(true);
    expect(material.passphrase).toBeUndefined();
  });

  it('returns a PFX with passphrase as an own key, undefined, when none is configured', async () => {
    const dir = join(__dirname, '..', 'fixtures', 'certificates');
    const material = await new FileCertificateMaterialLoader().load({
      url: 'https://h',
      authType: 'certificate',
      certPfxPath: join(dir, 'client.pfx'),
    } as ISapConfig);
    expect(sorted(Object.keys(material))).toEqual(['passphrase', 'pfx']);
    expect(material.passphrase).toBeUndefined();
  });
});
