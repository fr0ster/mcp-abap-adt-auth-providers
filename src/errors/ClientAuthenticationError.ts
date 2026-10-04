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
