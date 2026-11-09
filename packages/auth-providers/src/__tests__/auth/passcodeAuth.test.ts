/**
 * The passcode exchange: UAA routes it to its passcode filter chain only when
 * the request asks for JSON, so that header is part of the contract.
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { beforeEach, describe, it, mock } from 'node:test';
import { exchangePasscode } from '../../auth/passcodeAuth';
import { clearAxiosMockCalls, mockedAxios } from '../helpers/axiosModuleMock';
import { calledWith, thrown } from '../helpers/expectations';

// Automocked, but with axios's own error class: the sites throw it.

const call = () =>
  mockedAxios.post.mock.calls.map((call) => call.arguments)[0] as [
    string,
    string,
    { headers: Record<string, string> },
  ];

describe('exchangePasscode', () => {
  beforeEach(() => {
    clearAxiosMockCalls();
    mockedAxios.post.mock.mockImplementation(async () => ({
      data: { access_token: 'a', refresh_token: 'r', expires_in: 60 },
    }));
  });

  it('sends the password grant with the passcode and asks for JSON', async () => {
    const tokens = await exchangePasscode(
      'https://uaa',
      'client',
      'secret',
      'CODE',
    );

    const [url, body, options] = call();
    assert.equal(url, 'https://uaa/oauth/token');
    const params = new URLSearchParams(body);
    assert.equal(params.get('grant_type'), 'password');
    assert.equal(params.get('passcode'), 'CODE');
    assert.equal(params.has('username'), false);
    assert.equal(options.headers.Accept, 'application/json');
    assert.equal(
      options.headers.Authorization,
      `Basic ${Buffer.from('client:secret').toString('base64')}`,
    );
    assert.deepEqual(tokens, {
      accessToken: 'a',
      refreshToken: 'r',
      expiresIn: 60,
    });
  });

  it('authenticates a public client with an empty secret, as cf does', async () => {
    await exchangePasscode('https://uaa/', 'cf', undefined, 'CODE');

    const [url, , options] = call();
    assert.equal(url, 'https://uaa/oauth/token');
    assert.equal(
      options.headers.Authorization,
      `Basic ${Buffer.from('cf:').toString('base64')}`,
    );
  });

  it('reports the reason UAA gives, such as a spent passcode', async () => {
    const refused = Object.assign(
      new Error('Request failed with status code 401'),
      {
        isAxiosError: true,
        response: {
          status: 401,
          data: {
            error: 'unauthorized',
            error_description: 'Invalid passcode',
          },
        },
      },
    );
    mockedAxios.post.mock.mockImplementation(async () => {
      throw refused;
    });

    // The message names the status and a registered code only:
    // `unauthorized` is UAA's own, and the description is the server's free
    // text — it reaches no message and no log line.
    const debug = mock.fn();
    const logger = {
      debug,
      info: mock.fn(),
      warn: mock.fn(),
      error: mock.fn(),
    };
    const failed = assert.rejects(
      exchangePasscode(
        'https://uaa',
        'c',
        'client-secret-value',
        'SPENT',
        logger,
      ),
      thrown(/^the passcode exchange failed \(HTTP 401\)$/),
    );
    await failed;
    // 5.4.2's keys and values; the message leads with the operation's phrase.
    calledWith(
      debug,
      'the passcode exchange: the token endpoint refused the request',
      { status: 401 },
    );
  });

  it('refuses a response without an access token', async () => {
    mockedAxios.post.mock.mockImplementation(async () => ({ data: {} }));
    await assert.rejects(
      exchangePasscode('https://uaa', 'c', 's', 'CODE'),
      thrown('the passcode exchange returned no access_token'),
    );
  });
});
