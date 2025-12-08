# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

