import { TOKEN_PROVIDER_ERROR_CODES } from '@mcp-abap-adt/interfaces-auth';
import { TokenProviderError } from './TokenProviderErrors';

/** The fixed words for a client signing key that cannot be used: the one source. */
export const CLIENT_KEY_UNUSABLE = {
  reason: 'the client signing key could not be used',
  hint: 'check the private key and that it matches the algorithm',
} as const;

/**
 * Thrown when the key a client signs its assertion with cannot be used. Its
 * message is fixed and carries nothing of the key.
 */
export class ClientAuthenticationError extends TokenProviderError {
  constructor() {
    super(
      CLIENT_KEY_UNUSABLE.reason,
      TOKEN_PROVIDER_ERROR_CODES.CLIENT_AUTHENTICATION_ERROR,
    );
    this.name = 'ClientAuthenticationError';
    Object.setPrototypeOf(this, ClientAuthenticationError.prototype);
  }
}

/** The fixed words for a client authentication whose result cannot be sent. */
export const CLIENT_AUTHENTICATION_UNUSABLE = {
  reason: 'the client authentication returned a request that cannot be sent',
  hint: 'check the client authentication strategy',
} as const;

/**
 * Thrown, before anything is sent, when what a client authentication strategy
 * returned cannot be sent: a value that is not a string, a header with a line
 * break, a parameter or header that would replace one of the request's own, an
 * endpoint that is not an absolute `https:` URL. Its message is fixed and
 * carries nothing of what the strategy returned.
 */
export class ClientAuthenticationResultError extends TokenProviderError {
  constructor() {
    super(
      CLIENT_AUTHENTICATION_UNUSABLE.reason,
      TOKEN_PROVIDER_ERROR_CODES.CLIENT_AUTHENTICATION_ERROR,
    );
    this.name = 'ClientAuthenticationResultError';
    Object.setPrototypeOf(this, ClientAuthenticationResultError.prototype);
  }
}
