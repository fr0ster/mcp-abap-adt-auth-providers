/**
 * The shipped transports: how the user's answer reaches the
 * protocol. Each knows no payload.
 */

export {
  type ConsumerAnswerOptions,
  type ConsumerHandoffOptions,
  consumerAnswer,
  consumerHandoff,
  type ProvideAnswer,
  type ReceiveAnswer,
} from './consumerAnswer';
export { checkedEndpoint, usableEndpoint } from './endpoint';
export {
  type LoopbackOptions,
  loopback,
  loopback4,
  loopback6,
} from './loopback';
export {
  readFromTerminal,
  type TerminalPasteOptions,
  type TerminalRead,
  terminalPaste,
} from './terminalPaste';
