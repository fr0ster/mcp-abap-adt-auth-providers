/**
 * The shipped validators' brand is read guarded: a consumer's validator that
 * is a Proxy throwing on every trap is simply not a shipped one, so a SAML
 * provider handed it is built without asking for `idpEntityId`, and nothing
 * it throws escapes the constructor. (What a constructor does with any other
 * collaborator that breaks its type is not stated; a collaborator that throws
 * once called inside a moment is classified — `contract/rule1.test.ts`,
 * `authorization/throwingAnswers.test.ts`.)
 */

import { describe, expect, it } from '@jest/globals';
import type { IAssertionValidator } from '@mcp-abap-adt/interfaces-auth';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { refreshThenLogin } from '../../renewal';

const SECRET = 'HOSTILE-OPTION-SECRET-41';
const boom = () => {
  throw new Error(SECRET);
};

describe('a hostile validator is not a shipped one', () => {
  it('a validator that is a throwing object Proxy is not a shipped one', () => {
    const validator = new Proxy(
      {},
      { get: boom, getOwnPropertyDescriptor: boom, has: boom },
    ) as IAssertionValidator;
    expect(
      () =>
        new Saml2PureProvider({
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp',
          cookieProvider: async () => '',
          authorization: {
            authorize: async () => ({ payload: '', redirectUri: '' }),
          },
          assertionValidator: validator,
        }),
    ).not.toThrow();
  });
});
