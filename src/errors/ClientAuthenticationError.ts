import { TOKEN_PROVIDER_ERROR_CODES } from '@mcp-abap-adt/interfaces-auth';
import { TokenProviderError } from './TokenProviderErrors';

/** The fixed words for a client signing key that cannot be used: the one source. */
export const CLIENT_KEY_UNUSABLE = Object.freeze({
  reason: 'the client signing key could not be used',
  hint: 'check the private key and that it matches the algorithm',
} as const);

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
export const CLIENT_AUTHENTICATION_UNUSABLE = Object.freeze({
  reason: 'the client authentication returned a request that cannot be sent',
  hint: 'check the client authentication strategy',
} as const);

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

/** The fixed words for a client id raw Basic cannot carry: the one source. */
export const BASIC_CLIENT_ID_UNUSABLE = Object.freeze({
  reason: "the client id contains ':', which raw Basic cannot carry",
  hint: "use encoding: 'form' or clientSecretPost",
} as const);

/**
 * Thrown by `clientSecretBasic` with `encoding: 'raw'` for a client id that
 * contains `:` — RFC 7617 splits the credential at the first colon, so no
 * server can read that id back. Its message is fixed and carries nothing of
 * the id or the secret.
 */
export class BasicClientIdError extends TokenProviderError {
  constructor() {
    super(
      BASIC_CLIENT_ID_UNUSABLE.reason,
      TOKEN_PROVIDER_ERROR_CODES.CLIENT_AUTHENTICATION_ERROR,
    );
    this.name = 'BasicClientIdError';
    Object.setPrototypeOf(this, BasicClientIdError.prototype);
  }
}
