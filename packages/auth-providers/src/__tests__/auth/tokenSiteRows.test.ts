/**
 * One test per token site: what each token site throws,
 * as kind, facts and verbatim words.
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import { discoverOidc } from '../../auth/oidcDiscovery';
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import { cases, caseTitle, notContains } from '../helpers/expectations';
import { phrase, SITES } from '../helpers/tokenRequestSites';

function rejectEvery(value: unknown): void {
  mockedAxios.mock.mockImplementation(async () => {
    throw value;
  });
  mockedAxios.post.mock.mockImplementation(async () => {
    throw value;
  });
}
function answerEvery(data: unknown): void {
  mockedAxios.mock.mockImplementation(async () => ({ status: 200, data }));
  mockedAxios.post.mock.mockImplementation(async () => ({ status: 200, data }));
}

async function thrownBy(run: () => Promise<unknown>): Promise<Error> {
  const outcome = await run().then(
    () => undefined,
    (error: unknown) => error,
  );
  assert.equal(isAuthProviderFailure(outcome), true);
  return outcome as Error;
}

beforeEach(() => {
  resetAxiosMock();
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
  for (const [caseIndex, caseRow] of SITES.filter((s) =>
    WRAPPED.has(s.operation),
  ).entries()) {
    const site = caseRow;
    it(
      caseTitle(
        '$name: request-failed refused, status and registered code; `<operation> failed (HTTP <n>, <oauth>)`',
        caseRow,
        caseIndex,
      ),
      async () => {
        rejectEvery({
          isAxiosError: true,
          response: {
            status: 401,
            data: { error: 'invalid_client', error_description: 'MARKER' },
          },
        });
        const thrown = await thrownBy(() => site.run());
        const failure = readFailure(thrown, 'unfamiliar-error');
        assert.equal(failure.kind, 'request-failed');
        assert.deepEqual(failure.facts, {
          operation: site.operation,
          problem: 'refused',
          status: 401,
          oauthError: 'invalid_client',
        });
        assert.equal(
          thrown.message,
          `${phrase(site.operation)} failed (HTTP 401, invalid_client)`,
        );
        assert.equal((thrown as { cause?: unknown }).cause, undefined);
        notContains(JSON.stringify(thrown), 'MARKER');
      },
    );
  }
});

describe('no response: request-failed no-response, or tls', () => {
  for (const [caseIndex, caseRow] of SITES.entries()) {
    const site = caseRow;
    it(
      caseTitle(
        '$name: an allowlisted system code is the `code` fact',
        caseRow,
        caseIndex,
      ),
      async () => {
        rejectEvery(Object.assign(new Error('MARKER'), { code: 'ETIMEDOUT' }));
        const thrown = await thrownBy(() => site.run());
        assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
          operation: site.operation,
          problem: 'no-response',
          code: 'ETIMEDOUT',
        });
        assert.equal(
          thrown.message,
          `${phrase(site.operation)} failed (ETIMEDOUT)`,
        );
      },
    );
  }

  for (const [caseIndex, caseRow] of SITES.entries()) {
    const site = caseRow;
    it(
      caseTitle('$name: an allowlisted TLS code is `tls`', caseRow, caseIndex),
      async () => {
        rejectEvery(
          Object.assign(new Error('MARKER'), { code: 'CERT_HAS_EXPIRED' }),
        );
        const thrown = await thrownBy(() => site.run());
        const failure = readFailure(thrown, 'unfamiliar-error');
        assert.equal(failure.kind, 'tls');
        assert.deepEqual(failure.facts, {
          operation: site.operation,
          code: 'CERT_HAS_EXPIRED',
        });
        assert.equal(
          thrown.message,
          `${phrase(site.operation)} failed: the server's certificate has expired (CERT_HAS_EXPIRED) — the server must renew its certificate; check also this machine's clock`,
        );
      },
    );
  }
});

describe('a non-wrapping site refused by the token endpoint', () => {
  for (const [caseIndex, caseRow] of SITES.filter(
    (s) => !WRAPPED.has(s.operation),
  ).entries()) {
    const site = caseRow;
    it(
      caseTitle(
        '$name: request-failed refused, not the reduced AxiosError',
        caseRow,
        caseIndex,
      ),
      async () => {
        rejectEvery({
          isAxiosError: true,
          response: {
            status: 400,
            data: { error: 'invalid_grant', error_description: 'MARKER' },
          },
        });
        const thrown = await thrownBy(() => site.run());
        assert.ok(!mockedAxios.isAxiosError(thrown));
        assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
          operation: site.operation,
          problem: 'refused',
          status: 400,
          oauthError: 'invalid_grant',
        });
        assert.equal(
          thrown.message,
          `${phrase(site.operation)} failed (HTTP 400, invalid_grant)`,
        );
        notContains(JSON.stringify(thrown), 'MARKER');
      },
    );
  }
});

describe('a 2xx without access_token', () => {
  for (const [caseIndex, caseRow] of SITES.filter(
    (s) => s.missingProblem === 'no-access-token',
  ).entries()) {
    const site = caseRow;
    it(
      caseTitle(
        '$name: request-failed no-access-token, `<operation> returned no access_token`',
        caseRow,
        caseIndex,
      ),
      async () => {
        answerEvery({ token_type: 'bearer' });
        const thrown = await thrownBy(() => site.run());
        assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
          operation: site.operation,
          problem: 'no-access-token',
          status: 200,
        });
        assert.equal(
          thrown.message,
          `${phrase(site.operation)} returned no access_token`,
        );
      },
    );
  }
});

describe('a device authorization response without its fields', () => {
  for (const [caseIndex, caseRow] of cases([
    ['no device_code', { user_code: 'u', verification_uri: 'https://v' }],
    ['no user_code', { device_code: 'd', verification_uri: 'https://v' }],
    ['no verification_uri', { device_code: 'd', user_code: 'u' }],
  ]).entries()) {
    const [_name, data] = caseRow;
    it(
      caseTitle('%s: request-failed incomplete-response', caseRow, caseIndex),
      async () => {
        answerEvery(data);
        const site = SITES.find((s) => s.operation === 'device-authorization');
        if (site === undefined) throw new Error('no device initiation site');
        const thrown = await thrownBy(() => site.run());
        assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
          operation: 'device-authorization',
          problem: 'incomplete-response',
          status: 200,
        });
        assert.equal(
          thrown.message,
          'the OIDC device authorization returned an incomplete response',
        );
      },
    );
  }
});

describe('a discovery document without token_endpoint', () => {
  it('request-failed incomplete-response of oidc-discovery', async () => {
    mockedAxios.get.mock.mockImplementation(async () => ({
      status: 200,
      data: { issuer: 'https://idp-d6.example' },
    }));
    const thrown = await thrownBy(() => discoverOidc('https://idp-d6.example'));
    const failure = readFailure(thrown, 'unfamiliar-error');
    assert.equal(failure.kind, 'request-failed');
    assert.deepEqual(failure.facts, {
      operation: 'oidc-discovery',
      problem: 'incomplete-response',
    });
    assert.equal(
      thrown.message,
      'OIDC discovery returned an incomplete response',
    );
  });
});
