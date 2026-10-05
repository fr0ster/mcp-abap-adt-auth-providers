import type { IRefreshableTokenProvider } from '@mcp-abap-adt/interfaces-auth';
import { OidcBrowserProvider } from '../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../providers/Saml2PureProvider';
import type { SsoProviderConfig } from './types';

/**
 * Builds the provider a protocol and flow name. A class holding only a static
 * member — biome's noStaticOnlyClass is off for this file (biome.json) — kept
 * a class because it is public: a patch does not change a public type.
 */
export class SsoProviderFactory {
  static create(config: SsoProviderConfig): IRefreshableTokenProvider {
    if (config.protocol === 'oidc') {
      if (config.flow === 'browser') {
        return new OidcBrowserProvider(config.config);
      }
      if (config.flow === 'device') {
        return new OidcDeviceFlowProvider(config.config);
      }
      if (config.flow === 'password') {
        return new OidcPasswordProvider(config.config);
      }
      if (config.flow === 'token_exchange') {
        return new OidcTokenExchangeProvider(config.config);
      }
    }

    if (config.protocol === 'saml2') {
      if (config.flow === 'bearer') {
        return new Saml2BearerProvider(config.config);
      }
      if (config.flow === 'pure') {
        return new Saml2PureProvider(config.config);
      }
    }

    // Fixed words: the config holds the client secret, a password, tokens.
    throw new Error(
      'Unsupported SSO provider config: no provider for this protocol and flow',
    );
  }
}
