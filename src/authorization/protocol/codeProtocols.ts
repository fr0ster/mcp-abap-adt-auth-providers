/**
 * The authorization code protocols (spec §6d.2, §6d.3.2): `oauthCode` (the
 * code) and `oidcCode` (`{ code, state }`). Both bind a redirect by the
 * `state` of the URL they were given — always there (C7: a provider adds
 * its own to a configured URL that has none) — compared in constant time,
 * before anything else of the answer is read: a forged `?error=` stops at
 * the binding too.
 */

import { authError, isOAuthErrorCode } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerVerdict,
  AuthorizationAnswer,
  IAuthorizationProtocol,
} from '@mcp-abap-adt/interfaces-auth';
import { sameSecret } from '../secrets';
import { accept, endWith, refuse, unreadableUrl, words } from './answers';
import { oneValue, readPaste, urlState } from './readPaste';

/** What an OIDC login's strategy returns: the code, and a redirect's `state`. */
export interface OidcCallbackResult {
  code: string;
  state?: string | undefined;
}

const CODE_WORDS = words(
  'Paste the authorization code (or the whole redirected URL): ',
  "After signing in, copy the code from your browser's address bar (or paste the whole redirected URL) and submit it here.",
);

/** A value present exactly once and not empty, else `undefined`. */
function present(
  params: Parameters<typeof oneValue>[0],
  name: string,
): string | undefined {
  const value = oneValue(params, name);
  return value === '' ? undefined : value;
}

/**
 * The judge of one attempt bound to `expected`. `payloadOf` makes the
 * payload of a code — with the redirect's `state` (the expected one), or
 * `undefined` for a text, which carried none to the composer.
 */
function judgeCodes<T>(
  expected: string,
  payloadOf: (code: string, state: string | undefined) => T,
): AnswerJudge<T> {
  return (answer: AuthorizationAnswer): AnswerVerdict<T> => {
    if (answer.via === 'redirect') {
      const { params } = answer;
      // The binding first: missing, repeated or another login's `state`.
      if (!sameSecret(expected, oneValue(params, 'state'))) {
        return refuse('state');
      }
      const error = present(params, 'error');
      if (error !== undefined) {
        const description = present(params, 'error_description');
        return {
          verdict: 'end',
          // The registered code only: the description and `error_uri` are
          // anyone's text (a link to the local callback carries them).
          error: authError['interactive-login']({
            outcome: 'identity-provider-refused',
            ...(isOAuthErrorCode(error) ? { oauthError: error } : {}),
          }),
          // For the escaped error page only.
          shown: description === undefined ? error : `${error}: ${description}`,
        };
      }
      const code = present(params, 'code');
      if (code === undefined) return refuse('no-payload');
      return accept(payloadOf(code, expected));
    }
    if (answer.via === 'consumer') {
      // The consumer's code returned it: the code, verbatim.
      return answer.text === ''
        ? endWith('no-input')
        : accept(payloadOf(answer.text, undefined));
    }
    const reading = readPaste(expected, answer.text);
    if ('code' in reading) return accept(payloadOf(reading.code, undefined));
    if (reading.refused === 'state') return refuse('pasted-state');
    // A form can be filled in again; a terminal read is not asked twice.
    return answer.via === 'form'
      ? refuse('unreadable')
      : endWith('unreadable-input');
  };
}

function codeProtocol<T>(
  payloadOf: (code: string, state: string | undefined) => T,
): IAuthorizationProtocol<T> {
  return {
    redirect: 'required',
    callbackMethods: Object.freeze(['GET'] as const),
    paste: CODE_WORDS,
    begin(authorizationUrl: string): AnswerJudge<T> {
      // C7: the URL always carries one `state`; one that does not parse,
      // carries none, or carries it repeated or empty binds nothing.
      const expected = urlState(authorizationUrl);
      if (typeof expected !== 'string') throw unreadableUrl();
      return judgeCodes(expected, payloadOf);
    },
  };
}

/** An OAuth authorization code (UAA / XSUAA): the payload is the code. */
export function oauthCode(): IAuthorizationProtocol<string> {
  return codeProtocol((code) => code);
}

/** An OIDC authorization code: `{ code, state }`, the state of a redirect. */
export function oidcCode(): IAuthorizationProtocol<OidcCallbackResult> {
  return codeProtocol((code, state) => ({ code, state }));
}
