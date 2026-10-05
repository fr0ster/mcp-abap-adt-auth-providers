import {
  createPrivateKey,
  type KeyObject,
  randomUUID,
  sign,
} from 'node:crypto';
import type { IClientAuthentication } from '@mcp-abap-adt/interfaces-auth';
import { ClientAuthenticationError } from '../errors/ClientAuthenticationError';

export interface PrivateKeyJwtConfig {
  /** A private key: PEM text or bytes, or a KeyObject. */
  key: string | Buffer | KeyObject;
  algorithm: 'RS256' | 'ES256';
  keyId?: string | undefined;
  /**
   * The assertion's audience. Else the draft's `tokenEndpoint` — the
   * authorization server's token endpoint, also for the device initiation —
   * and, for a draft without one, the endpoint the request goes to.
   */
  audience?: string | undefined;
}

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const LIFETIME_SECONDS = 60;

function usableKey(config: PrivateKeyJwtConfig): KeyObject {
  try {
    const key =
      typeof config.key === 'object' && 'type' in config.key
        ? config.key
        : createPrivateKey(config.key);
    const fits =
      key.type === 'private' &&
      (config.algorithm === 'RS256'
        ? key.asymmetricKeyType === 'rsa'
        : key.asymmetricKeyType === 'ec' &&
          key.asymmetricKeyDetails?.namedCurve === 'prime256v1');
    if (fits) return key;
  } catch {
    // fall through: the error's text can name what it read
  }
  throw new ClientAuthenticationError();
}

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString('base64url');

/** `private_key_jwt`: the client signs a short-lived assertion with its key. */
export function privateKeyJwt(
  config: PrivateKeyJwtConfig,
): IClientAuthentication {
  let key: KeyObject | undefined;
  return {
    authenticate: async (draft) => {
      key ??= usableKey(config);
      const iat = Math.floor(Date.now() / 1000);
      const header = {
        alg: config.algorithm,
        typ: 'JWT',
        ...(config.keyId === undefined ? {} : { kid: config.keyId }),
      };
      const claims = {
        iss: draft.clientId,
        sub: draft.clientId,
        aud: config.audience ?? draft.tokenEndpoint ?? draft.endpoint,
        jti: randomUUID(),
        iat,
        exp: iat + LIFETIME_SECONDS,
      };
      const input = `${b64(header)}.${b64(claims)}`;
      let signature: Buffer;
      try {
        signature = sign(
          'sha256',
          Buffer.from(input),
          config.algorithm === 'ES256'
            ? { key, dsaEncoding: 'ieee-p1363' }
            : key,
        );
      } catch {
        throw new ClientAuthenticationError();
      }
      return {
        parameters: {
          client_id: draft.clientId,
          client_assertion_type: ASSERTION_TYPE,
          client_assertion: `${input}.${signature.toString('base64url')}`,
        },
      };
    },
  };
}
