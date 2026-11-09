/**
 * The pin of the axios module mock (helpers/axiosModuleMock.ts): imported
 * first, it replaces what both kinds of site call — `axios.post` (no
 * strategy) and `axios(config)` (a strategy, through tokenRequest) — and it
 * works only because it is in place before the modules under test load.
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';
import { passwordGrant } from '../../auth/oidcToken';
import { clientSecretPost } from '../../clientAuthentication';
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import { thrown } from '../helpers/expectations';
import { once } from '../helpers/mockOnce';

afterEach(resetAxiosMock);

const TOKENS = { status: 200, data: { access_token: 'at', expires_in: 60 } };

it('an axios.post site calls mockedAxios.post', async () => {
  mockedAxios.post.mock.mockImplementation(async () => TOKENS);
  const tokens = await passwordGrant(
    'https://idp.invalid/token',
    'client',
    'secret',
    'user',
    'password',
    undefined,
  );
  assert.equal(tokens.accessToken, 'at');
  assert.equal(mockedAxios.post.mock.callCount(), 1);
  assert.equal(
    mockedAxios.post.mock.calls[0]?.arguments[0],
    'https://idp.invalid/token',
  );
  assert.equal(mockedAxios.mock.callCount(), 0);
});

it('an axios(config) site calls mockedAxios itself', async () => {
  mockedAxios.mock.mockImplementation(async () => TOKENS);
  const tokens = await passwordGrant(
    'https://idp.invalid/token',
    'client',
    undefined,
    'user',
    'password',
    undefined,
    undefined,
    { strategy: clientSecretPost('client-secret-0123456789') },
  );
  assert.equal(tokens.accessToken, 'at');
  assert.equal(mockedAxios.mock.callCount(), 1);
  assert.equal(
    mockedAxios.mock.calls[0]?.arguments[0].url,
    'https://idp.invalid/token',
  );
  assert.equal(mockedAxios.post.mock.callCount(), 0);
});

it('one-time answers are queued call after call, as Jest queued them', async () => {
  once(mockedAxios.post, async () => ({
    ...TOKENS,
    data: { access_token: 'first' },
  }));
  once(mockedAxios.post, async () => ({
    ...TOKENS,
    data: { access_token: 'second' },
  }));
  const grant = () =>
    passwordGrant('https://idp.invalid/token', 'c', 's', 'u', 'p', undefined);
  assert.equal((await grant()).accessToken, 'first');
  assert.equal((await grant()).accessToken, 'second');
});

it('a reset with a one-time answer no call took fails, rather than let it answer later', () => {
  once(mockedAxios.post, async () => TOKENS);
  assert.throws(resetAxiosMock, thrown('one-time answer'));
  // Taken, so the hook's reset passes.
  void mockedAxios.post('https://idp.invalid/token');
});
