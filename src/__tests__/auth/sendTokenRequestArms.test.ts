/**
 * TRANSITION (Decision D6; deleted in Task 21 with the legacy arm): the
 * third parameter of `sendTokenRequest` is 5.4.2's `TokenRequestDiagnostics`
 * or a `TokenRequestSite`, told apart by the explicit discriminant `arm`
 * alone — never by which other properties an argument carries. The legacy
 * arm is 5.4.2 exactly; 5.4.2's own request tests (tokenRequestShapes,
 * tokenRequestRedirect, devicePoll, canceledRequests, …) stay green beside
 * this suite.
 */

import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { AxiosError, type AxiosResponse, CanceledError } from 'axios';
import {
  sendTokenRequest,
  type TokenRequestSite,
} from '../../auth/tokenRequest';

const SERVER_TEXT = 'SERVER-SAID-THIS';

function recordingLogger(): { logger: ILogger; lines: unknown[][] } {
  const lines: unknown[][] = [];
  const at =
    (level: string) =>
    (...args: unknown[]): void => {
      lines.push([level, ...args]);
    };
  return {
    logger: {
      debug: at('debug'),
      info: at('info'),
      warn: at('warn'),
      error: at('error'),
    },
    lines,
  };
}

const refused = (): unknown => ({
  isAxiosError: true,
  message: SERVER_TEXT,
  response: {
    status: 400,
    data: { error: 'invalid_grant', error_description: SERVER_TEXT },
  },
});

const rejecting = (thrown: unknown) => (): Promise<AxiosResponse<unknown>> =>
  Promise.reject(thrown);

async function failureOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected a failure');
}

const SITE: TokenRequestSite = {
  arm: 'site',
  operation: 'passcode-exchange',
  authDebug: false,
  secrets: [],
};

describe('the legacy arm: 5.4.2 exactly', () => {
  it("label and no arm: 5.4.2's replacement error and its one guarded line of safe facts, no AuthProviderFailure", async () => {
    const { logger, lines } = recordingLogger();
    const failure = await failureOf(
      sendTokenRequest(undefined, rejecting(refused()), {
        logger,
        label: 'Passcode exchange failed',
      }),
    );
    expect(failure).toBeInstanceOf(AxiosError);
    expect(axios.isAxiosError(failure)).toBe(true);
    expect(isAuthProviderFailure(failure)).toBe(false);
    expect((failure as AxiosError).message).toBe(
      'Request failed with status code 400',
    );
    expect((failure as AxiosError).response?.data).toEqual({
      error: 'invalid_grant',
    });
    expect(lines).toEqual([
      [
        'debug',
        'Passcode exchange failed: the token endpoint refused the request',
        { status: 400, error: 'invalid_grant' },
      ],
    ]);
  });

  it("undefined: 5.4.2's path, without a line", async () => {
    const failure = await failureOf(
      sendTokenRequest(undefined, rejecting(refused())),
    );
    expect(failure).toBeInstanceOf(AxiosError);
    expect(isAuthProviderFailure(failure)).toBe(false);
  });

  it('a CanceledError comes out as 5.4.2 lets it out: a fixed-words cancellation', async () => {
    const failure = await failureOf(
      sendTokenRequest(
        undefined,
        rejecting(new CanceledError(`canceled: ${SERVER_TEXT}`)),
        { label: 'Passcode exchange failed' },
      ),
    );
    expect(failure).toBeInstanceOf(CanceledError);
    expect(axios.isCancel(failure)).toBe(true);
    expect((failure as Error).message).toBe('the token request was canceled');
  });

  it("an answer: 5.4.2's AxiosResponse-shaped snapshot", async () => {
    const response = await sendTokenRequest(
      undefined,
      () =>
        Promise.resolve({
          status: 200,
          data: { access_token: 'at', error_description: SERVER_TEXT },
        } as AxiosResponse<unknown>),
      { label: 'Passcode exchange failed' },
    );
    expect(response).toEqual({
      status: 200,
      statusText: '',
      headers: {},
      data: { access_token: 'at' },
    });
  });
});

describe('the new arm', () => {
  it("arm: 'site' → an AuthProviderFailure", async () => {
    const failure = await failureOf(
      sendTokenRequest(undefined, rejecting(refused()), SITE),
    );
    expect(isAuthProviderFailure(failure)).toBe(true);
    expect(axios.isAxiosError(failure)).toBe(false);
    expect(readFailure(failure, 'unfamiliar-error').facts).toEqual({
      operation: 'passcode-exchange',
      problem: 'refused',
      status: 400,
      oauthError: 'invalid_grant',
    });
  });

  it("an object carrying both `label` and arm: 'site' takes the new arm: the discriminant decides", async () => {
    const both = { ...SITE, label: 'Passcode exchange failed' };
    const failure = await failureOf(
      sendTokenRequest(undefined, rejecting(refused()), both),
    );
    expect(isAuthProviderFailure(failure)).toBe(true);
  });

  it('an answer: the snapshot, without statusText or headers', async () => {
    const snapshot = await sendTokenRequest(
      undefined,
      () =>
        Promise.resolve({
          status: 200,
          data: { access_token: 'at', error_description: SERVER_TEXT },
        } as AxiosResponse<unknown>),
      SITE,
    );
    expect(snapshot).toEqual({ status: 200, data: { access_token: 'at' } });
  });
});
