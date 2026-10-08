/**
 * The shipped protocols (spec §6d.2): what an answer is and how it is
 * checked. Each knows no socket and no terminal.
 */

export { oauthCode, oidcCode } from './codeProtocols';
export { passcode, samlResponse } from './textProtocols';
