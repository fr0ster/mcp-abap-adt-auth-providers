# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

