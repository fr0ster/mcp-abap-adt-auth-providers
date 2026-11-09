/**
 * Providers take a client authentication and pin one certificate.
 *
 * axios is mocked at the module boundary, so every real token-request site
 * runs: what is asserted is what the strategy was asked (its drafts) and what
 * each request carried (its URL and its TLS agent's certificate).
 */

import { CERTIFICATES } from '../helpers/packagePaths';
import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, it, type Mock, mock } from 'node:test';
import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  IAssertionValidator,
  IAuthorizationStrategy,
  ICertificateMaterial,
  IClientAuthentication,
  ITokenRequestDraft,
} from '@mcp-abap-adt/interfaces-auth';
import { certificateFailure } from '../../auth/certificateMaterial';
import { toBearerAssertion } from '../../auth/samlBearerAssertion';
import { clientSecretBasic } from '../../clientAuthentication';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import { clearAxiosMockCalls, mockedAxios } from '../helpers/axiosModuleMock';
import { caseTitle, matchObject, thrown } from '../helpers/expectations';
import { configurationOf, wordsOf } from '../helpers/minted';
import { recordingTargets } from '../helpers/targets';

/** The words of `client-certificate` `unusable`. */
const CERTIFICATE_UNUSABLE = authError['client-certificate']({
  problem: 'unusable',
});

// Automocked, but with axios's own error class: the sites throw it.

const dir = CERTIFICATES;
const read = (name: string) => readFileSync(join(dir, name));
const A: ICertificateMaterial = {
  cert: read('client.crt'),
  key: read('client.key'),
};
const B: ICertificateMaterial = {
  cert: read('other.crt'),
  key: read('other.key'),
};

function jwt(label: string, secondsFromNow = 3600): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${encode({ alg: 'none' })}.${encode({ exp, label })}.sig`;
}

let issued = 0;
interface Sent {
  url: string;
  body: Record<string, string>;
  cert?: unknown;
}
let sent: Sent[] = [];
const discovery = new Map<string, unknown>();

beforeEach(() => {
  clearAxiosMockCalls();
  sent = [];
  mockedAxios.mock.mockImplementation(async (config: any) => {
    sent.push({
      url: config.url,
      body: Object.fromEntries(new URLSearchParams(config.data)),
      cert: config.httpsAgent?.options?.cert,
    });
    if (String(config.url).includes('/device')) {
      return {
        data: {
          device_code: 'dc',
          user_code: 'UC',
          verification_uri: 'https://idp/verify',
          interval: 0,
        },
      };
    }
    issued += 1;
    return {
      data: {
        access_token: jwt(`at-${issued}`),
        refresh_token: `rt-${issued}`,
        expires_in: 3600,
      },
    };
  });
  mockedAxios.post.mock.mockImplementation(async () => {
    throw new Error('a request went out without the strategy');
  });
  mockedAxios.get.mock.mockImplementation(async (url: string) => {
    const doc = discovery.get(url);
    if (!doc) throw new Error(`no discovery document at ${url}`);
    return { data: doc };
  });
});

/** A strategy that records each draft; with materials, answers them in turn. */
function recording(materials?: Array<ICertificateMaterial | Error>) {
  const drafts: ITokenRequestDraft[] = [];
  let calls = 0;
  const strategy: IClientAuthentication = {
    authenticate: async (draft) => {
      drafts.push(draft);
      return { parameters: { client_id: draft.clientId } };
    },
  };
  if (materials) {
    strategy.tlsMaterial = async () => {
      const answer = materials[Math.min(calls, materials.length - 1)]!;
      calls += 1;
      if (answer instanceof Error) throw answer;
      return answer;
    };
  }
  return { strategy, drafts, tlsCalls: () => calls };
}

const codeStrategy = (
  payload = 'the-code',
): IAuthorizationStrategy<string> & {
  authorize: Mock<IAuthorizationStrategy<string>['authorize']>;
} => ({
  authorize: mock.fn<IAuthorizationStrategy<string>['authorize']>(async () => ({
    payload,
    redirectUri: 'http://localhost:61001/callback',
  })),
});

const oidcCodeStrategy = (): IAuthorizationStrategy<{ code: string }> => ({
  authorize: async () => ({
    payload: { code: 'the-code' },
    redirectUri: 'http://localhost:61001/callback',
  }),
});

const acceptingSamlValidator = (): IAssertionValidator => ({
  async validate(payload) {
    return {
      expiresAt: new Date(Date.now() + 3600_000),
      assertionId: '_stub',
      issuer: 'urn:stub:idp',
      raw: payload,
      signedXml: payload,
    };
  },
});

const samlPayload = (): string => {
  const assertion =
    '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"><saml2:Issuer>idp</saml2:Issuer></saml2:Assertion>';
  const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
  return Buffer.from(response, 'utf8').toString('base64');
};

let issuerCount = 0;
/** A fresh issuer (discovery is cached per URL) publishing `document`. */
function issuerWith(document: Record<string, unknown>): string {
  issuerCount += 1;
  const issuer = `https://idp-${issuerCount}.example`;
  discovery.set(`${issuer}/.well-known/openid-configuration`, {
    issuer,
    token_endpoint: `${issuer}/token`,
    authorization_endpoint: `${issuer}/auth`,
    device_authorization_endpoint: `${issuer}/device`,
    ...document,
  });
  return issuer;
}

const grants = (drafts: ITokenRequestDraft[]) => drafts.map((d) => d.grantType);

describe('the strategy reaches every request a provider sends', () => {
  it('ClientCredentialsProvider: the client_credentials request', async () => {
    const { strategy, drafts } = recording();
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    assert.deepEqual(await provider.prepare(), { ok: true });
    assert.deepEqual(drafts, [
      {
        endpoint: 'https://uaa/oauth/token',
        tokenEndpoint: 'https://uaa/oauth/token',
        clientId: 'cid',
        grantType: 'client_credentials',
      },
    ]);
    assert.equal(sent.length, 1);
  });

  it('AuthorizationCodeProvider: the code exchange and the refresh', async () => {
    const { strategy, drafts } = recording();
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      authorization: codeStrategy(),
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    assert.deepEqual(grants(drafts), ['authorization_code', 'refresh_token']);
    assert.deepEqual(
      sent.map((s) => s.url),
      ['https://uaa/oauth/token', 'https://uaa/oauth/token'],
    );
  });

  it('UaaPasscodeProvider: the passcode exchange and the refresh', async () => {
    const { strategy, drafts } = recording();
    const provider = new UaaPasscodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cf',
      authorization: codeStrategy('passcode'),
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    assert.deepEqual(grants(drafts), ['password', 'refresh_token']);
    assert.equal(sent.length, 2);
  });

  it('Saml2BearerProvider: the assertion exchange and its refresh', async () => {
    const { strategy, drafts } = recording();
    const provider = new Saml2BearerProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      idpInitiated: true,
      authorization: codeStrategy(samlPayload()),
      assertionValidator: acceptingSamlValidator(),
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    assert.deepEqual(grants(drafts), [
      'urn:ietf:params:oauth:grant-type:saml2-bearer',
      'refresh_token',
    ]);
    assert.equal(sent[0]!.body.assertion, toBearerAssertion(samlPayload()));
    assert.equal(sent.length, 2);
  });

  it('OidcBrowserProvider: the code exchange and the refresh', async () => {
    const { strategy, drafts } = recording();
    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp/token',
      authorizationEndpoint: 'https://idp/auth',
      authorization: oidcCodeStrategy(),
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    assert.deepEqual(grants(drafts), ['authorization_code', 'refresh_token']);
    assert.equal(sent.length, 2);
  });

  it('OidcDeviceFlowProvider: the device initiation, the poll and the refresh', async () => {
    const { strategy, drafts } = recording();
    const provider = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp/token',
      deviceAuthorizationEndpoint: 'https://idp/device',
      presenter: { present: async () => {} },
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    assert.deepEqual(grants(drafts), [
      'device_authorization',
      'urn:ietf:params:oauth:grant-type:device_code',
      'refresh_token',
    ]);
    assert.deepEqual(
      sent.map((s) => s.url),
      ['https://idp/device', 'https://idp/token', 'https://idp/token'],
    );
  });

  it('OidcPasswordProvider: the password grant and the refresh', async () => {
    const { strategy, drafts } = recording();
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp/token',
      username: 'u',
      password: 'p',
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    assert.deepEqual(grants(drafts), ['password', 'refresh_token']);
    assert.equal(sent.length, 2);
  });

  it('OidcTokenExchangeProvider: the token exchange', async () => {
    const { strategy, drafts } = recording();
    const provider = new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp/token',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    assert.deepEqual(grants(drafts), [
      'urn:ietf:params:oauth:grant-type:token-exchange',
    ]);
    assert.equal(sent.length, 1);
  });
});

describe('a strategy and a clientSecret together', () => {
  const strategy = recording().strategy;
  const both: Array<[string, () => unknown]> = [
    [
      'ClientCredentialsProvider',
      () =>
        new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa',
          clientId: 'cid',
          clientSecret: 's',
          clientAuthentication: strategy,
        }),
    ],
    [
      'AuthorizationCodeProvider',
      () =>
        new AuthorizationCodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa',
          clientId: 'cid',
          clientSecret: 's',
          authorization: codeStrategy(),
          clientAuthentication: strategy,
        }),
    ],
    [
      'UaaPasscodeProvider',
      () =>
        new UaaPasscodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa',
          clientId: 'cf',
          clientSecret: 's',
          authorization: codeStrategy(),
          clientAuthentication: strategy,
        }),
    ],
    [
      'Saml2BearerProvider',
      () =>
        new Saml2BearerProvider({
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp/sso',
          spEntityId: 'sp-entity',
          uaaUrl: 'https://uaa',
          clientId: 'cid',
          clientSecret: 's',
          idpInitiated: true,
          authorization: codeStrategy(),
          assertionValidator: acceptingSamlValidator(),
          clientAuthentication: strategy,
        }),
    ],
    [
      'OidcBrowserProvider',
      () =>
        new OidcBrowserProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          clientSecret: 's',
          authorization: oidcCodeStrategy(),
          clientAuthentication: strategy,
        }),
    ],
    [
      'OidcDeviceFlowProvider',
      () =>
        new OidcDeviceFlowProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          clientSecret: 's',
          presenter: { present: async () => {} },
          clientAuthentication: strategy,
        }),
    ],
    [
      'OidcPasswordProvider',
      () =>
        new OidcPasswordProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          clientSecret: 's',
          username: 'u',
          password: 'p',
          clientAuthentication: strategy,
        }),
    ],
    [
      'OidcTokenExchangeProvider',
      () =>
        new OidcTokenExchangeProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          clientSecret: 's',
          subjectToken: 'subject',
          subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
          clientAuthentication: strategy,
        }),
    ],
  ];

  // A configuration failure naming clientSecret.
  for (const [caseIndex, caseRow] of both.entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: a configuration failure naming clientSecret',
        caseRow,
        caseIndex,
      ),
      () => {
        let thrown: unknown;
        try {
          make();
        } catch (error) {
          thrown = error;
        }
        matchObject(configurationOf(thrown), {
          case: 'client-secret-beside-client-authentication',
          fields: ['clientSecret'],
        });
      },
    );
  }
});

describe('a strategy satisfies the clientSecret requirement', () => {
  it('ClientCredentialsProvider without a secret is still refused', () => {
    assert.throws(
      () =>
        new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa',
          clientId: 'cid',
        } as never),
      thrown(/clientSecret/),
    );
  });

  it('ClientCredentialsProvider with a strategy and no secret', () => {
    assert.doesNotThrow(
      () =>
        new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa',
          clientId: 'cid',
          clientAuthentication: recording().strategy,
        }),
    );
  });

  it('AuthorizationCodeProvider without a secret is still refused', () => {
    assert.throws(
      () =>
        new AuthorizationCodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa',
          clientId: 'cid',
          authorization: codeStrategy(),
        } as never),
      thrown(/clientSecret/),
    );
  });

  it('AuthorizationCodeProvider with a strategy and no secret', () => {
    assert.doesNotThrow(
      () =>
        new AuthorizationCodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa',
          clientId: 'cid',
          authorization: codeStrategy(),
          clientAuthentication: recording().strategy,
        }),
    );
  });
});

describe('one certificate, pinned', () => {
  it('a strategy answering A, then B, is asked once; every request presents A', async () => {
    const { strategy, tlsCalls } = recording([A, B]);
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      authorization: codeStrategy(),
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    await provider.refreshTokens();
    assert.equal(sent.length, 3);
    for (const request of sent) assert.deepEqual(request.cert, A.cert);
    assert.equal(tlsCalls(), 1);
  });

  it('concurrent prepare() calls share one load', async () => {
    const { strategy, tlsCalls } = recording([A, B]);
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    await Promise.all([provider.prepare(), provider.prepare()]);
    assert.equal(tlsCalls(), 1);
    for (const request of sent) assert.deepEqual(request.cert, A.cert);
  });

  it('concurrent first needs outside a renewal share one in-flight load', async () => {
    // The renewal is shared already; a logon needs the pin on its
    // own, so two needs at once must still read the strategy once.
    class TwoNeeds extends ClientCredentialsProvider {
      needBoth() {
        return Promise.all([this.pin(), this.pin()]);
      }
    }
    const { strategy, tlsCalls } = recording([A, B]);
    const provider = new TwoNeeds({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    const [first, second] = await provider.needBoth();
    assert.equal(tlsCalls(), 1);
    assert.deepEqual(first?.material.cert, A.cert);
    assert.deepEqual(second?.material.cert, A.cert);
  });

  it('a strategy without tlsMaterial: no agent on the request', async () => {
    const { strategy } = recording();
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    await provider.prepare();
    assert.equal(sent[0]!.cert, undefined);
  });

  it('material that fails to load: refused in fixed words, the stored refresh token kept and not sent; a later moment loads again', async () => {
    const { strategy, tlsCalls } = recording([
      certificateFailure('unusable'),
      A,
    ]);
    const authorization = codeStrategy();
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      refreshToken: 'stored-refresh',
      authorization,
      clientAuthentication: strategy,
    });

    assert.deepEqual(wordsOf(await provider.prepare()), {
      ok: false,
      refusal: {
        reason: CERTIFICATE_UNUSABLE.reason,
        hint: CERTIFICATE_UNUSABLE.hint,
      },
    });
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
    assert.equal(authorization.authorize.mock.callCount(), 0);

    // The next moment tries again; the refresh token it still holds is spent.
    assert.deepEqual(await provider.prepare(), { ok: true });
    assert.equal(tlsCalls(), 2);
    assert.equal(sent.length, 1);
    matchObject(sent[0]!.body, {
      grant_type: 'refresh_token',
      refresh_token: 'stored-refresh',
    });
    assert.deepEqual(sent[0]!.cert, A.cert);
    assert.equal(authorization.authorize.mock.callCount(), 0);
  });

  it('material that is not usable is refused and not pinned; a later moment loads again', async () => {
    const { strategy, tlsCalls } = recording([
      { cert: A.cert!, key: B.key! },
      A,
    ]);
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    assert.deepEqual(wordsOf(await provider.prepare()), {
      ok: false,
      refusal: {
        reason: CERTIFICATE_UNUSABLE.reason,
        hint: CERTIFICATE_UNUSABLE.hint,
      },
    });
    assert.equal(sent.length, 0);

    assert.deepEqual(await provider.prepare(), { ok: true });
    assert.equal(tlsCalls(), 2);
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0]!.cert, A.cert);
    // Pinned now: a further request reads the strategy no more.
    await provider.refreshTokens();
    assert.equal(tlsCalls(), 2);
    assert.deepEqual(sent[1]!.cert, A.cert);
  });

  it("a change to the strategy's Buffer after pinning does not change what is presented", async () => {
    const cert = Buffer.from(A.cert as Buffer);
    const key = Buffer.from(A.key as Buffer);
    const original = Buffer.from(cert);
    const { strategy } = recording([{ cert, key }]);
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    await provider.prepare();
    // The strategy overwrites the bytes it handed over, in place.
    cert.fill(0);
    await provider.refreshTokens();
    assert.equal(sent.length, 2);
    for (const request of sent) {
      assert.equal(Buffer.from(request.cert as Buffer).equals(original), true);
    }
  });

  it('a logon target that changes the material it was given does not change what later requests present', async () => {
    const original = Buffer.from(A.cert as Buffer);
    const { strategy } = recording([A]);
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    const t = recordingTargets();
    const mutating = {
      ...t.logonTarget,
      tlsMaterial(material: ICertificateMaterial) {
        // In place, and by replacing the fields.
        (material.cert as Buffer).fill(0);
        material.cert = B.cert!;
        material.key = B.key!;
        return { ok: true as const };
      },
    };
    assert.deepEqual(await provider.establish(mutating), { ok: true });
    await provider.prepare();
    assert.deepEqual(await provider.establish(mutating), { ok: true });
    await provider.refreshTokens();
    assert.equal(sent.length, 2);
    for (const request of sent) {
      assert.equal(Buffer.from(request.cert as Buffer).equals(original), true);
    }
  });
});

describe('an expired client certificate', () => {
  const EXPIRED = {
    ok: false,
    refusal: {
      reason: 'the client certificate has expired',
      hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    },
  };
  const expired: ICertificateMaterial = {
    cert: read('expired.crt'),
    key: read('client.key'),
  };

  it('is refused at pin time: nothing sent, nothing pinned (fixture: 2020-01-01 to 2021-01-01)', async () => {
    const { strategy } = recording([expired]);
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    assert.deepEqual(wordsOf(await provider.prepare()), EXPIRED);
    const t = recordingTargets();
    assert.deepEqual(wordsOf(await provider.establish(t.logonTarget)), EXPIRED);
    assert.equal(t.logon.tls.length, 0);
    assert.equal(sent.length, 0);
  });

  it('pinned while valid, then expired: refused before the next request presents it, and at the logon', async () => {
    const { strategy } = recording([A]);
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
    });
    assert.deepEqual(await provider.prepare(), { ok: true });
    assert.equal(sent.length, 1);
    // client.crt is valid until 2126: the clock is moved past it, not crypto.
    const now = mock.method(Date, 'now', () => Date.UTC(2127, 0, 1));
    try {
      assert.deepEqual(wordsOf(await provider.prepare()), EXPIRED);
      assert.equal(sent.length, 1);
      const t = recordingTargets();
      assert.deepEqual(
        wordsOf(await provider.establish(t.logonTarget)),
        EXPIRED,
      );
      assert.equal(t.logon.tls.length, 0);
    } finally {
      now.mock.restore();
    }
  });
  it('an expired certificate refuses the renewal whole: the refresh token is neither sent nor dropped', async () => {
    const { strategy } = recording([A]);
    const authorization = codeStrategy();
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      authorization,
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    assert.equal(sent.length, 1);
    const held = sent.length;
    const now = mock.method(Date, 'now', () => Date.UTC(2127, 0, 1));
    try {
      // The expired material is classified —
      // client-certificate, expired — and thrown as an AuthProviderFailure.
      await assert.rejects(provider.refreshTokens(), (error) => {
        matchObject(error, {
          name: 'AuthProviderFailure',
          error: { kind: 'client-certificate', facts: { problem: 'expired' } },
        });
        return true;
      });
    } finally {
      now.mock.restore();
    }
    assert.equal(sent.length, held);
    assert.equal(authorization.authorize.mock.callCount(), 1);
    // The clock back: the refresh token it held is still there to send.
    await provider.refreshTokens();
    matchObject(sent[held]!.body, { grant_type: 'refresh_token' });
  });

  it('expired between two device polls: the next poll is not sent, and the login is refused in fixed words', async () => {
    const { strategy } = recording([A]);
    const provider = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp/token',
      deviceAuthorizationEndpoint: 'https://idp/device',
      presenter: { present: async () => {} },
      clientAuthentication: strategy,
    });
    let polls = 0;
    // client.crt is valid until 2126: the first poll answers pending and the
    // clock then passes notAfter — the clock moves, not crypto.
    const now = mock.method(Date, 'now');
    mockedAxios.mock.mockImplementation(async (config: any) => {
      sent.push({
        url: config.url,
        body: Object.fromEntries(new URLSearchParams(config.data)),
        cert: config.httpsAgent?.options?.cert,
      });
      if (String(config.url).includes('/device')) {
        return {
          data: {
            device_code: 'dc',
            user_code: 'UC',
            verification_uri: 'https://idp/verify',
            // `interval || 5`: 0 would wait 5 s; 1 ms keeps the poll real.
            interval: 0.001,
          },
        };
      }
      polls += 1;
      // A second poll, had it been sent, gets a token: the login would succeed.
      if (polls > 1) {
        return { data: { access_token: jwt('late'), expires_in: 3600 } };
      }
      now.mock.mockImplementation(() => Date.UTC(2127, 0, 1));
      throw {
        isAxiosError: true,
        response: { status: 400, data: { error: 'authorization_pending' } },
      };
    });
    try {
      assert.deepEqual(wordsOf(await provider.prepare()), EXPIRED);
    } finally {
      now.mock.restore();
    }
    assert.equal(polls, 1);
    assert.deepEqual(
      sent.map((s) => s.url),
      ['https://idp/device', 'https://idp/token'],
    );
  });
});

describe('OIDC discovery: mtls_endpoint_aliases', () => {
  it('fills mtlsEndpoint from the token alias', async () => {
    const issuer = issuerWith({
      mtls_endpoint_aliases: { token_endpoint: 'https://mtls.idp/token' },
    });
    const { strategy, drafts } = recording();
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      username: 'u',
      password: 'p',
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    await provider.refreshTokens();
    assert.deepEqual(
      drafts.map((d) => d.mtlsEndpoint),
      ['https://mtls.idp/token', 'https://mtls.idp/token'],
    );
  });

  it('without aliases, leaves it absent', async () => {
    const issuer = issuerWith({});
    const { strategy, drafts } = recording();
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      username: 'u',
      password: 'p',
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    assert.equal(drafts.length, 1);
    assert.equal('mtlsEndpoint' in drafts[0]!, false);
  });

  it('the device initiation gets the device alias, the poll the token alias', async () => {
    const issuer = issuerWith({
      mtls_endpoint_aliases: {
        token_endpoint: 'https://mtls.idp/token',
        device_authorization_endpoint: 'https://mtls.idp/device',
      },
    });
    const { strategy, drafts } = recording();
    const provider = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      presenter: { present: async () => {} },
      clientAuthentication: strategy,
    });
    await provider.getTokens();
    assert.deepEqual(
      drafts.map((d) => [d.grantType, d.endpoint, d.mtlsEndpoint]),
      [
        ['device_authorization', `${issuer}/device`, 'https://mtls.idp/device'],
        [
          'urn:ietf:params:oauth:grant-type:device_code',
          `${issuer}/token`,
          'https://mtls.idp/token',
        ],
      ],
    );
  });

  it('the device initiation names the discovered token endpoint, not its mTLS alias, as tokenEndpoint', async () => {
    const issuer = issuerWith({
      mtls_endpoint_aliases: {
        token_endpoint: 'https://mtls.idp/token',
        device_authorization_endpoint: 'https://mtls.idp/device',
      },
    });
    const { strategy, drafts } = recording();
    await new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      presenter: { present: async () => {} },
      clientAuthentication: strategy,
    }).getTokens();
    assert.deepEqual(
      drafts.map((d) => [d.grantType, d.tokenEndpoint]),
      [
        ['device_authorization', `${issuer}/token`],
        ['urn:ietf:params:oauth:grant-type:device_code', `${issuer}/token`],
      ],
    );
  });

  it('the device initiation names a configured token endpoint as tokenEndpoint', async () => {
    const { strategy, drafts } = recording();
    await new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://own/token',
      deviceAuthorizationEndpoint: 'https://own/device',
      presenter: { present: async () => {} },
      clientAuthentication: strategy,
    }).getTokens();
    matchObject(drafts[0], {
      grantType: 'device_authorization',
      endpoint: 'https://own/device',
      tokenEndpoint: 'https://own/token',
    });
  });

  it('OidcBrowserProvider and OidcTokenExchangeProvider use the token alias', async () => {
    const issuer = issuerWith({
      mtls_endpoint_aliases: { token_endpoint: 'https://mtls.idp/token' },
    });
    const browser = recording();
    await new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      authorization: oidcCodeStrategy(),
      clientAuthentication: browser.strategy,
    }).getTokens();
    const exchange = recording();
    await new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      clientAuthentication: exchange.strategy,
    }).getTokens();
    assert.equal(browser.drafts[0]!.mtlsEndpoint, 'https://mtls.idp/token');
    assert.equal(exchange.drafts[0]!.mtlsEndpoint, 'https://mtls.idp/token');
  });

  it('an endpoint the configuration names takes no discovered alias', async () => {
    const issuer = issuerWith({
      mtls_endpoint_aliases: {
        token_endpoint: 'https://mtls.idp/token',
        device_authorization_endpoint: 'https://mtls.idp/device',
      },
    });
    const { strategy, drafts } = recording();
    await new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer,
      clientId: 'cid',
      deviceAuthorizationEndpoint: 'https://own/device',
      presenter: { present: async () => {} },
      clientAuthentication: strategy,
    }).getTokens();
    assert.deepEqual(
      drafts.map((d) => d.mtlsEndpoint),
      [undefined, 'https://mtls.idp/token'],
    );
  });
});

describe('clientSecretBasic through a provider', () => {
  it("raw with a client id containing ':': prepare() refuses in fixed words, nothing sent", async () => {
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'my:client',
      clientAuthentication: clientSecretBasic('top-secret', {
        encoding: 'raw',
      }),
    });
    assert.deepEqual(wordsOf(await provider.prepare()), {
      ok: false,
      refusal: {
        reason: "the client id contains ':', which raw Basic cannot carry",
        hint: "use encoding: 'form' or clientSecretPost",
      },
    });
    assert.equal(sent.length, 0);
  });

  it('form with the same client id: the request goes out, the id encoded', async () => {
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'my:client',
      clientAuthentication: clientSecretBasic('top-secret', {
        encoding: 'form',
      }),
    });
    assert.deepEqual(await provider.prepare(), { ok: true });
    assert.equal(sent.length, 1);
  });
});
