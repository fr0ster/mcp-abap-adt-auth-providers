# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2025-12-20

### Fixed
- **Process Termination Cleanup**: OAuth callback server now properly cleans up when process is terminated
  - Added `process.on('exit', 'SIGTERM', 'SIGINT', 'SIGHUP')` handlers to ensure server closes on process termination
  - This fixes port leaks when MCP clients (like Cline) kill the stdio server before authentication completes
  - Cleanup handlers are automatically removed after authentication completes to prevent memory leaks
  - Ports are now properly freed even when process is forcefully terminated

## [0.2.1] - 2025-01-XX

### Added
- **Automatic Port Selection**: Browser auth server now automatically finds an available port if the requested port is in use
  - When `startBrowserAuth()` is called with a port, it checks if the port is available
  - If the port is busy, it automatically tries the next ports (up to 10 attempts)
  - This prevents `EADDRINUSE` errors when multiple stdio servers run simultaneously
  - Port selection happens before server startup, ensuring no conflicts

### Fixed
- **Server Port Cleanup**: Improved server shutdown to ensure ports are properly freed after authentication completes
  - Added `keepAliveTimeout = 0` and `headersTimeout = 0` to prevent connections from staying open
  - Added `closeAllConnections()` calls before `server.close()` to ensure all connections are closed
  - Server now waits for HTTP response to finish before closing to prevent connection leaks
  - Added proper error handling for browser open failures to ensure server is closed
  - Server now properly closes in all error scenarios (timeout, browser open failure, callback errors)
  - This prevents ports from remaining occupied after authentication completes or server shutdown

### Changed
- **Port Selection Logic**: `startBrowserAuth()` now uses `findAvailablePort()` to automatically select a free port
  - Default behavior: tries requested port first, then tries next ports if busy
  - Port range: tries up to 10 consecutive ports starting from the requested port
  - Logs when a different port is used (for debugging)

## [0.2.0] - 2025-12-19

### Added
- **Typed Error Classes**: Added specialized error classes for better error handling and debugging
  - `TokenProviderError` - Base class for all token provider errors with error code
  - `ValidationError` - Thrown when authConfig validation fails (includes `missingFields: string[]` array)
  - `RefreshError` - Thrown when token refresh operation fails (includes `cause?: Error` with original error)
  - `SessionDataError` - Thrown when session data is invalid or incomplete (includes `missingFields` array)
  - `ServiceKeyError` - Thrown when service key data is invalid or incomplete (includes `missingFields` array)
  - `BrowserAuthError` - Thrown when browser authentication fails or is cancelled (includes `cause` error)
  - All error codes use constants from `@mcp-abap-adt/interfaces` package (`TOKEN_PROVIDER_ERROR_CODES`)
  - Errors are exported from package root for easy import

### Changed
- **Enhanced Validation Error Messages**: Validation errors now list specific missing field names instead of generic messages
  - Example: `XSUAA refreshTokenFromSession: authConfig missing required fields: uaaUrl, uaaClientId`
  - `ValidationError` includes `missingFields: string[]` property for programmatic access to missing fields
  - Each missing field is checked individually and added to the list
- **Improved Error Handling in Refresh Methods**: All refresh operations now wrap errors with typed error classes
  - `refreshTokenFromSession` throws `RefreshError` when client_credentials or browser auth fails
  - `refreshTokenFromServiceKey` throws `RefreshError` when browser authentication fails
  - Original error is preserved in `RefreshError.cause` property for debugging
  - Error messages include provider type (XSUAA/BTP) and operation name for clarity
- **Dependency Update**: Updated `@mcp-abap-adt/interfaces` to `^0.2.2` for `TOKEN_PROVIDER_ERROR_CODES` constants
- **Test Coverage**: Added tests for error handling edge cases
  - Tests verify `RefreshError` is thrown when authentication fails
  - Tests verify `ValidationError` includes correct missing field names
  - Tests verify error messages contain expected substrings

## [0.1.5] - 2025-12-13

### Changed
- Dependency bump: `@mcp-abap-adt/interfaces` to `^0.1.16` to align with latest interfaces release

## [0.1.4] - 2025-12-08

### Added
- **Integration Tests for browserAuth**: Added real integration test that uses actual service keys and OAuth flow
  - Test verifies token retrieval with real credentials from service keys
  - Shows all authentication stages with logging when `DEBUG_AUTH_PROVIDERS=true` is set
  - Tests both access token and refresh token retrieval
- **Test Logger Helper**: Added `createTestLogger` helper for tests with environment variable control
  - Supports log levels (debug, info, warn, error) via `LOG_LEVEL` environment variable
  - Only outputs logs when `DEBUG_AUTH_PROVIDERS=true` or `DEBUG_BROWSER_AUTH=true` is set
  - Provides clean, controlled logging for test scenarios

### Changed
- **Improved Logging in browserAuth**: Made logging more concise and informative
  - All log messages are now single-line strings without verbose objects
  - Logs show key information: what we send, what we receive, token lengths
  - Example: `Tokens received: accessToken(2263 chars), refreshToken(34 chars)`
  - Logging only works when logger is provided (no default console output)
- **exchangeCodeForToken Function**: Exported for testing purposes
  - Function is marked as `@internal` but exported to enable unit testing
  - Allows testing token exchange logic without full browser auth flow

### Fixed
- **Test Error Logging**: Fixed error test to use mock logger without console output
  - Error test no longer pollutes console with error messages
  - Still verifies that error logging occurs via spy

## [0.1.3] - 2025-12-07

### Added
- **Configurable Browser Auth Port**: Added optional `browserAuthPort` parameter to `BtpTokenProvider` constructor
  - Allows configuring the OAuth callback server port (default: 3001)
  - Prevents port conflicts when proxy server runs on the same port
  - Port is passed through to `startBrowserAuth` and `exchangeCodeForToken` functions
  - Enables proxy to configure browser auth port via CLI parameter or YAML config

### Changed
- **BtpTokenProvider Constructor**: Now accepts optional `browserAuthPort?: number` parameter
  - Defaults to 3001 if not specified (maintains backward compatibility)
- **startBrowserAuth Function**: Added optional `port: number = 3001` parameter
  - Port is used for OAuth callback server and redirect URI
- **exchangeCodeForToken Function**: Added optional `port: number = 3001` parameter
  - Port is used in redirect URI when exchanging authorization code for tokens
- **Implementation Isolation**: Internal authentication functions are no longer exported from package
  - `startBrowserAuth`, `refreshJwtToken`, and `getTokenWithClientCredentials` are now internal functions
  - Providers use private method wrappers to call these functions
  - Constructor parameters (like `browserAuthPort`) are passed through private methods to internal functions
  - This ensures proper encapsulation and prevents direct usage of internal implementation details
- **Test Improvements**: Unit tests now use provider methods instead of direct internal function imports
  - Tests use `jest.spyOn` to mock private provider methods instead of mocking internal functions
  - Tests now properly test the public API of providers, ensuring better isolation
  - This aligns with encapsulation principles and makes tests more maintainable

## [0.1.2] - 2025-12-05

### Changed
- **Dependency Injection**: Moved `@mcp-abap-adt/auth-stores` and `@mcp-abap-adt/logger` from `dependencies` to `devDependencies`
  - These packages are only used in tests, not in production code
  - Logger is injected via `ITokenProviderOptions.logger?: ILogger` interface in production code
  - Auth stores are not used in production code (consumers inject their own store implementations)

### Removed
- **Unused Dependencies**: Removed `@mcp-abap-adt/connection` dependency (not used in production code)

## [0.1.1] - 2025-12-04

### Added
- **Interfaces Package Integration**: Migrated to use `@mcp-abap-adt/interfaces` package for all interface definitions
  - All interfaces now imported from shared package
  - Dependency on `@mcp-abap-adt/interfaces@^0.1.1` added
  - Updated `@mcp-abap-adt/connection` dependency to `^0.1.14`
  - Updated `@mcp-abap-adt/auth-stores` dependency to `^0.1.3`

### Changed
- **Interface Renaming**: Interfaces renamed to follow `I` prefix convention:
  - `TokenProviderResult` → `ITokenProviderResult` (type alias for backward compatibility)
  - `TokenProviderOptions` → `ITokenProviderOptions` (type alias for backward compatibility)
  - Old names still work via type aliases for backward compatibility
- **Logger Interface**: Updated to use `ILogger` from `@mcp-abap-adt/interfaces` instead of `Logger` from `@mcp-abap-adt/logger`
  - `browserAuth.ts` now uses `ILogger` interface with basic methods (info, error, warn, debug)
  - Browser-specific logging methods (browserUrl, browserOpening) now use basic `info` and `debug` methods

### Fixed
- **BtpTokenProvider Integration Tests**: Fixed to use ABAP destination and `AbapServiceKeyStore` instead of XSUAA
  - BTP and ABAP use the same authentication flow and service key format
  - Tests now correctly use `getAbapDestination` and `hasRealConfig(config, 'abap')`
  - Tests now use `AbapServiceKeyStore` instead of `BtpServiceKeyStore` for loading service keys

## [0.1.0] - 2025-12-04

### Added
- Initial release
- **XsuaaTokenProvider** - Uses `client_credentials` grant type (no browser required)
- **BtpTokenProvider** - Uses browser-based OAuth2 or refresh token flow
- Browser authentication flow with OAuth2 callback server
- Client credentials authentication
- Token refresh functionality
- Token validation (`validateToken` method)
- **Integration Tests**:
  - Integration tests for all providers using real files from `test-config.yaml`
  - Test configuration helpers (`configHelpers.ts`) matching auth-broker format
  - YAML-based test configuration (`tests/test-config.yaml.template`)
  - Tests for service key to session conversion
  - Tests for token validation
  - BTP tests use `AbapServiceKeyStore` (same format as ABAP) and `BtpSessionStore` (without `sapUrl`)
  - ABAP tests use `AbapServiceKeyStore` and `AbapSessionStore` (with `sapUrl`)
  - Both BTP and ABAP tests use `abap.destination` from config (same authentication flow)

### Fixed
- **Integration Tests**: Corrected BTP and ABAP test separation
  - BTP tests correctly handle base BTP sessions (no `sapUrl` required)
  - ABAP tests correctly handle ABAP sessions (with `sapUrl` from service key)
- **Token Validation**: BTP tests now handle cases where `serviceUrl` may not be available (base BTP)
- **Session Storage**: BTP tests no longer attempt to save `serviceUrl` to `BtpSessionStore` (which doesn't accept `sapUrl`)

### Changed
- **Documentation**: Updated README to clarify BTP vs ABAP differences and correct store usage
  - Added explicit examples showing BTP and ABAP as separate entities
  - Clarified that BTP uses `BtpServiceKeyStore`/`BtpSessionStore` (without `sapUrl`)
  - Clarified that ABAP uses `AbapServiceKeyStore`/`AbapSessionStore` (with `sapUrl`)
  - Updated integration test configuration examples

### Dependencies
- `@mcp-abap-adt/auth-broker` ^0.1.6 - Interface definitions
- `@mcp-abap-adt/auth-stores` ^0.1.2 - Store implementations
- `@mcp-abap-adt/connection` ^0.1.13 - Connection utilities
- `@mcp-abap-adt/logger` ^0.1.0 - Logging utilities
