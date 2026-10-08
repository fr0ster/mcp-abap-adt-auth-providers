/**
 * The shipped presentations (spec §6d.2): how the authorization URL reaches
 * the user. Each knows no payload and no transport.
 */

export {
  type ConsumerPresentationOptions,
  consumerPresentation,
  type ShowAuthorizationUrl,
  type ShowContext,
} from './consumerPresentation';
export {
  type OpenableBrowser,
  type OpenInBrowserOptions,
  openInBrowser,
} from './openInBrowser';
export { showUrl } from './showUrl';
