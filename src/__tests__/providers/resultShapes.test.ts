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
  AuthorizationRequest,
  CallbackServerFactory,
  IAuthorizationStrategy,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import axios from 'axios';
import { FileCertificateMaterialLoader } from '../../credentials/FileCertificateMaterialLoader';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
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

beforeEach(() => {
  jest.resetAllMocks();
});

describe('token result', () => {
  it('carries refreshToken as an own key, undefined, when the grant gives none — login and cache alike', async () => {
    const reply = { data: { access_token: jwt(), expires_in: 3600 } };
    mockedAxios.mockResolvedValue(reply);
    mockedAxios.post.mockResolvedValue(reply);
    const provider = new ClientCredentialsProvider({
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
  });
});

describe('the request a strategy gets', () => {
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
});
