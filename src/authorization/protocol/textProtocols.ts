/**
 * The protocols whose payload is a text (spec §6d.2, §6d.3.2):
 * `samlResponse` — bound not here but by `InResponseTo` and the assertion
 * validator (§6a1, Appendix B) — and `passcode`, which takes no redirect.
 */

import type {
  AnswerJudge,
  AnswerVerdict,
  AuthorizationAnswer,
  IAuthorizationProtocol,
} from '@mcp-abap-adt/interfaces-auth';
import { accept, endWith, refuse, words } from './answers';
import { oneValue } from './readPaste';

const SAML_WORDS = words(
  'Paste the SAMLResponse (from the POST body — it is not in the address bar): ',
  'After signing in, the identity provider posts the SAMLResponse to the redirect: copy it from that POST body (your browser’s developer tools show it). It is not in the address bar.',
);

const PASSCODE_WORDS = words(
  'Paste the Temporary Authentication Code (passcode): ',
  'Open the passcode page in any browser, sign in, and copy the Temporary Authentication Code it shows.',
);

/**
 * A text, trimmed, when it is not empty; empty: a form asks again, a
 * terminal or a consumer's code ends `no-input`.
 */
function judgeText(
  answer: Exclude<AuthorizationAnswer, { via: 'redirect' }>,
): AnswerVerdict<string> {
  const text = answer.text.trim();
  if (text !== '') return accept(text);
  return answer.via === 'form' ? refuse('no-payload') : endWith('no-input');
}

/** A `SAMLResponse`, by redirect (GET or POST) or as a text. */
export function samlResponse(): IAuthorizationProtocol<string> {
  const judge: AnswerJudge<string> = (answer) => {
    if (answer.via !== 'redirect') return judgeText(answer);
    const response = oneValue(answer.params, 'SAMLResponse');
    return response === undefined || response === ''
      ? refuse('no-payload')
      : accept(response);
  };
  return {
    redirect: 'required',
    callbackMethods: Object.freeze(['GET', 'POST'] as const),
    paste: SAML_WORDS,
    // Reads nothing from the URL: no `state` binds a SAML response.
    begin: () => judge,
  };
}

/** A UAA passcode, typed in: no redirect ever carries one. */
export function passcode(): IAuthorizationProtocol<string> {
  const judge: AnswerJudge<string> = (answer) =>
    answer.via === 'redirect' ? refuse('no-payload') : judgeText(answer);
  return {
    redirect: 'unused',
    callbackMethods: Object.freeze([] as const),
    paste: PASSCODE_WORDS,
    begin: () => judge,
  };
}
