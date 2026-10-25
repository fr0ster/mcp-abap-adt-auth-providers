/**
 * One test per token site: what each token site throws,
 * as kind, facts and verbatim words.
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import axios from 'axios';
import { discoverOidc } from '../../auth/oidcDiscovery';
import { phrase, SITES } from '../helpers/tokenRequestSites';

jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock; get: Mock };

function rejectEvery(value: unknown): void {
  mockedAxios.mockImplementation(async () => {
    throw value;
  });
  mockedAxios.post.mockImplementation(async () => {
    throw value;
  });
}
function answerEvery(data: unknown): void {
  mockedAxios.mockImplementation(async () => ({ status: 200, data }));
  mockedAxios.post.mockImplementation(async () => ({ status: 200, data }));
}

async function thrownBy(run: () => Promise<unknown>): Promise<Error> {
  const outcome = await run().then(
    () => undefined,
    (error: unknown) => error,
  );
  expect(isAuthProviderFailure(outcome)).toBe(true);
  return outcome as Error;
}

beforeEach(() => {
  jest.resetAllMocks();
});

/** The sites that wrapped their failure in a `TokenEndpointError` at 5.4.2. */
const WRAPPED = new Set([
  'passcode-exchange',
  'device-authorization',
  'password-grant',
  'client-credentials',
  'token-refresh',
]);

describe('a wrapping site refused by the token endpoint', () => {
  it.each(SITES.filter((s) => WRAPPED.has(s.operation)))(
    '$name: request-failed refused, status and registered code; `<operation> failed (HTTP <n>, <oauth>)`',
    async (site) => {
      rejectEvery({
        isAxiosError: true,
        response: {
          status: 401,
          data: { error: 'invalid_client', error_description: 'MARKER' },
        },
      });
      const thrown = await thrownBy(() => site.run());
      const failure = readFailure(thrown, 'unfamiliar-error');
      expect(failure.kind).toBe('request-failed');
      expect(failure.facts).toEqual({
        operation: site.operation,
        problem: 'refused',
        status: 401,
        oauthError: 'invalid_client',
      });
      expect(thrown.message).toBe(
        `${phrase(site.operation)} failed (HTTP 401, invalid_client)`,
      );
      expect((thrown as { cause?: unknown }).cause).toBeUndefined();
      expect(JSON.stringify(thrown)).not.toContain('MARKER');
    },
  );
});

describe('no response: request-failed no-response, or tls', () => {
  it.each(SITES)(
    '$name: an allowlisted system code is the `code` fact',
    async (site) => {
      rejectEvery(Object.assign(new Error('MARKER'), { code: 'ETIMEDOUT' }));
      const thrown = await thrownBy(() => site.run());
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation: site.operation,
        problem: 'no-response',
        code: 'ETIMEDOUT',
      });
      expect(thrown.message).toBe(
        `${phrase(site.operation)} failed (ETIMEDOUT)`,
      );
    },
  );

  it.each(SITES)('$name: an allowlisted TLS code is `tls`', async (site) => {
    rejectEvery(
      Object.assign(new Error('MARKER'), { code: 'CERT_HAS_EXPIRED' }),
    );
    const thrown = await thrownBy(() => site.run());
    const failure = readFailure(thrown, 'unfamiliar-error');
    expect(failure.kind).toBe('tls');
    expect(failure.facts).toEqual({
      operation: site.operation,
      code: 'CERT_HAS_EXPIRED',
    });
    expect(thrown.message).toBe(
      `${phrase(site.operation)} failed: the server's certificate has expired (CERT_HAS_EXPIRED) — the server must renew its certificate; check also this machine's clock`,
    );
  });
});

describe('a non-wrapping site refused by the token endpoint', () => {
  it.each(SITES.filter((s) => !WRAPPED.has(s.operation)))(
    '$name: request-failed refused, not the reduced AxiosError',
    async (site) => {
      rejectEvery({
        isAxiosError: true,
        response: {
          status: 400,
          data: { error: 'invalid_grant', error_description: 'MARKER' },
        },
      });
      const thrown = await thrownBy(() => site.run());
      expect(axios.isAxiosError(thrown)).toBeFalsy();
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation: site.operation,
        problem: 'refused',
        status: 400,
        oauthError: 'invalid_grant',
      });
      expect(thrown.message).toBe(
        `${phrase(site.operation)} failed (HTTP 400, invalid_grant)`,
      );
      expect(JSON.stringify(thrown)).not.toContain('MARKER');
    },
  );
});

describe('a 2xx without access_token', () => {
  it.each(SITES.filter((s) => s.missingProblem === 'no-access-token'))(
    '$name: request-failed no-access-token, `<operation> returned no access_token`',
    async (site) => {
      answerEvery({ token_type: 'bearer' });
      const thrown = await thrownBy(() => site.run());
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation: site.operation,
        problem: 'no-access-token',
        status: 200,
      });
      expect(thrown.message).toBe(
        `${phrase(site.operation)} returned no access_token`,
      );
    },
  );
});

describe('a device authorization response without its fields', () => {
  it.each([
    ['no device_code', { user_code: 'u', verification_uri: 'https://v' }],
    ['no user_code', { device_code: 'd', verification_uri: 'https://v' }],
    ['no verification_uri', { device_code: 'd', user_code: 'u' }],
  ])('%s: request-failed incomplete-response', async (_name, data) => {
    answerEvery(data);
    const site = SITES.find((s) => s.operation === 'device-authorization');
    if (site === undefined) throw new Error('no device initiation site');
    const thrown = await thrownBy(() => site.run());
    expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
      operation: 'device-authorization',
      problem: 'incomplete-response',
      status: 200,
    });
    expect(thrown.message).toBe(
      'the OIDC device authorization returned an incomplete response',
    );
  });
});

describe('a discovery document without token_endpoint', () => {
  it('request-failed incomplete-response of oidc-discovery', async () => {
    mockedAxios.get.mockImplementation(async () => ({
      status: 200,
      data: { issuer: 'https://idp-d6.example' },
    }));
    const thrown = await thrownBy(() => discoverOidc('https://idp-d6.example'));
    const failure = readFailure(thrown, 'unfamiliar-error');
    expect(failure.kind).toBe('request-failed');
    expect(failure.facts).toEqual({
      operation: 'oidc-discovery',
      problem: 'incomplete-response',
    });
    expect(thrown.message).toBe(
      'OIDC discovery returned an incomplete response',
    );
  });
});
