/**
 * The shipped protocols: what an answer is and how it is
 * checked. Each knows no socket and no terminal.
 */

export { type OidcCallbackResult, oauthCode, oidcCode } from './codeProtocols';
export { passcode, samlResponse } from './textProtocols';
