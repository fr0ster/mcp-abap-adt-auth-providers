/**
 * @mcp-abap-adt/auth-providers
 * Token providers for MCP ABAP ADT auth-broker
 *
 * Provides XSUAA and BTP token providers
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
} from './providers';
// Token Providers (stateful providers with automatic token lifecycle)
export {
  AuthorizationCodeProvider,
  BaseTokenProvider,
  ClientCredentialsProvider,
  DeviceFlowProvider,
} from './providers';
export { BtpTokenProvider } from './providers/BtpTokenProvider';
// Token providers
export { XsuaaTokenProvider } from './providers/XsuaaTokenProvider';
