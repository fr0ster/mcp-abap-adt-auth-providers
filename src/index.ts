/**
 * @mcp-abap-adt/auth-providers
 * Token providers for MCP ABAP ADT auth-broker
 *
 * Provides token providers
 */

// The base every provider extends: the four moments, each inside guard.
export {
  AuthProviderBase,
  type Moment,
  type MomentOperations,
} from './auth/AuthProviderBase';
// Authorization by composition (spec §6d): the composer and the parts —
// presentations, transports, protocols — or bring your own of each.
export {
  type ComposedAuthorization,
  type ComposedStrategy,
  type ConsumerAnswerOptions,
  type ConsumerHandoffOptions,
  type ConsumerPresentationOptions,
  composeAuthorization,
  consumerAnswer,
  consumerHandoff,
  consumerPresentation,
  type LoopbackOptions,
  loopback,
  loopback4,
  loopback6,
  type OidcCallbackResult,
  type OpenableBrowser,
  type OpenInBrowserOptions,
  oauthCode,
  oidcCode,
  openInBrowser,
  type ProvideAnswer,
  passcode,
  type ReceiveAnswer,
  readFromTerminal,
  type ShowAuthorizationUrl,
  type ShowContext,
  samlResponse,
  showUrl,
  type TerminalPasteOptions,
  type TerminalRead,
  terminalPaste,
} from './authorization';
// How a token provider's client authenticates to the authorization server.
export * from './clientAuthentication';
// Credentials the process delegates to — every one an IAuthProvider.
export { BasicAuthProvider } from './credentials/BasicAuthProvider';
export { CertificateAuthProvider } from './credentials/CertificateAuthProvider';
export { FileCertificateMaterialLoader } from './credentials/FileCertificateMaterialLoader';
export { SamlAuthProvider } from './credentials/SamlAuthProvider';
export { TokenAuthProvider } from './credentials/TokenAuthProvider';
// Device flow: how the user is shown the code — injected like a strategy.
export {
  consoleDeviceCodePresenter,
  type DeviceCodePrompt,
  type IDeviceCodePresenter,
} from './deviceCode/DeviceCodePresenter';
// The persistence strategy — or bring your own ITokenPersistence.
export {
  type PersistedTokens,
  type RefreshStatePersistenceOptions,
  refreshStatePersistence,
} from './persistence';
export type {
  AuthorizationCodeProviderConfig,
  ClientCredentialsProviderConfig,
  LoginFactoryOptions,
  OidcBrowserProviderConfig,
  OidcDeviceFlowProviderConfig,
  OidcPasswordProviderConfig,
  OidcTokenExchangeProviderConfig,
  Saml2BearerProviderConfig,
  Saml2PureProviderConfig,
  TokenProviderDebug,
  TokenProviderHooks,
  UaaPasscodeProviderConfig,
} from './providers';
// Token Providers (stateful providers with automatic token lifecycle)
export {
  AuthorizationCodeProvider,
  BaseTokenProvider,
  ClientCredentialsProvider,
  OidcBrowserProvider,
  OidcDeviceFlowProvider,
  OidcPasswordProvider,
  OidcTokenExchangeProvider,
  Saml2BearerProvider,
  Saml2PureProvider,
  UaaPasscodeProvider,
} from './providers';
export type { SamlTrust } from './providers/saml2Utils';
// Renewal strategies — or bring your own IRenewalStrategy.
export { refreshOnly, refreshThenLogin } from './renewal';
// SNC — passwordless RFC logon.
export {
  DefaultSncLibraryLocator,
  type ISncLibraryLocator,
  type SncLibrary,
} from './snc/DefaultSncLibraryLocator';
export type { SncArch } from './snc/libraryArchitectures';
export {
  type ISncProductProbe,
  SecureLoginClientProbe,
} from './snc/SecureLoginClientProbe';
export {
  SncLogonProvider,
  type SncLogonProviderConfig,
} from './snc/SncLogonProvider';
export { nodeSncSystem, type SncSystem } from './snc/SncSystem';
// SSO factory
export { SsoProviderFactory } from './sso/SsoProviderFactory';
export type { SsoProviderConfig, SsoProviderInstance } from './sso/types';
export type {
  CallbackStrategyOptions,
  ExternalCodeStrategyOptions,
  ManualPasscodeStrategyOptions,
  ManualStrategyOptions,
  StaticCodeStrategyOptions,
} from './strategies';
// The named compositions — today's names and options — and the strategies
// that compose nothing; or bring your own IAuthorizationStrategy.
export {
  asOidcResult,
  browserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  externalCodeStrategy,
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
  staticCodeStrategy,
} from './strategies';
// SAML assertion validation — the two shipped validators and the replay store,
// or bring your own IAssertionValidator / IAssertionReplayStore.
export {
  createSignedAssertionValidator,
  createSignedResponseValidator,
  type ShippedValidatorOptions,
} from './validation/assertionValidator';
export {
  createInMemoryReplayStore,
  defaultReplayStore,
} from './validation/inMemoryReplayStore';
