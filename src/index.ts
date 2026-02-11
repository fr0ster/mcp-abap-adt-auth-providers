/**
 * @mcp-abap-adt/auth-providers
 * Token providers for MCP ABAP ADT auth-broker
 *
 * Provides token providers
 */

// Errors
export {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from './errors/TokenProviderErrors';
export type {
  AuthorizationCodeProviderConfig,
  ClientCredentialsProviderConfig,
  DeviceFlowProviderConfig,
  OidcBrowserProviderConfig,
  OidcDeviceFlowProviderConfig,
  OidcPasswordProviderConfig,
  OidcTokenExchangeProviderConfig,
  Saml2BearerProviderConfig,
  Saml2PureProviderConfig,
} from './providers';
// Token Providers (stateful providers with automatic token lifecycle)
export {
  AuthorizationCodeProvider,
  BaseTokenProvider,
  ClientCredentialsProvider,
  DeviceFlowProvider,
  OidcBrowserProvider,
  OidcDeviceFlowProvider,
  OidcPasswordProvider,
  OidcTokenExchangeProvider,
  Saml2BearerProvider,
  Saml2PureProvider,
} from './providers';

// SSO factory
export { SsoProviderFactory } from './sso/SsoProviderFactory';
export type { SsoProviderConfig, SsoProviderInstance } from './sso/types';
