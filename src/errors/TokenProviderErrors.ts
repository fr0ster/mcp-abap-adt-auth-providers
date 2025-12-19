/**
 * Token Provider Error Types
 * 
 * Defines specific error types that token providers can throw
 * to enable better error handling and debugging.
 */

import { TOKEN_PROVIDER_ERROR_CODES } from '@mcp-abap-adt/interfaces';

/**
 * Base class for all token provider errors
 */
export class TokenProviderError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'TokenProviderError';
    Object.setPrototypeOf(this, TokenProviderError.prototype);
  }
}

/**
 * Thrown when authentication configuration is invalid or incomplete
 */
export class ValidationError extends TokenProviderError {
  constructor(message: string, public readonly missingFields?: string[]) {
    super(message, TOKEN_PROVIDER_ERROR_CODES.VALIDATION_ERROR);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/**
 * Thrown when token refresh operation fails
 */
export class RefreshError extends TokenProviderError {
  constructor(message: string, public readonly cause?: Error) {
    super(message, TOKEN_PROVIDER_ERROR_CODES.REFRESH_ERROR);
    this.name = 'RefreshError';
    Object.setPrototypeOf(this, RefreshError.prototype);
  }
}

/**
 * Thrown when session data is invalid or incomplete
 */
export class SessionDataError extends TokenProviderError {
  constructor(message: string, public readonly missingFields?: string[]) {
    super(message, TOKEN_PROVIDER_ERROR_CODES.SESSION_DATA_ERROR);
    this.name = 'SessionDataError';
    Object.setPrototypeOf(this, SessionDataError.prototype);
  }
}

/**
 * Thrown when service key data is invalid or incomplete
 */
export class ServiceKeyError extends TokenProviderError {
  constructor(message: string, public readonly missingFields?: string[]) {
    super(message, TOKEN_PROVIDER_ERROR_CODES.SERVICE_KEY_ERROR);
    this.name = 'ServiceKeyError';
    Object.setPrototypeOf(this, ServiceKeyError.prototype);
  }
}

/**
 * Thrown when browser authentication fails or is cancelled
 */
export class BrowserAuthError extends TokenProviderError {
  constructor(message: string, public readonly cause?: Error) {
    super(message, TOKEN_PROVIDER_ERROR_CODES.BROWSER_AUTH_ERROR);
    this.name = 'BrowserAuthError';
    Object.setPrototypeOf(this, BrowserAuthError.prototype);
  }
}
